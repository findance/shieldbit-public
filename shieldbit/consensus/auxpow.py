# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""Bounded Bitcoin-parent proofs with Namecoin-style merged-mining commitments.

Bitcoin transaction parsing is delegated to python-bitcoinlib. ShieldBit's
proof envelope is distinct from Namecoin's; hashes inside Bitcoin Merkle trees
use raw digest bytes, and parent PoW uses Bitcoin's little-endian integer order.
"""
from dataclasses import dataclass

from shieldbit.consensus.params import AUXPOW_CHAIN_ID, MAX_AUXPOW_SIZE
from shieldbit.core.wire import Reader
from shieldbit.crypto.hashing import double_sha256

MERGE_MAGIC = bytes.fromhex('fabe6d6d')
MAX_BRANCH = 30
MAX_COINBASE = 4096


def merkle_branch(leaf: bytes, siblings: tuple[bytes, ...], index: int) -> bytes:
    if len(leaf) != 32 or len(siblings) > MAX_BRANCH or not 0 <= index < 1 << len(siblings):
        raise ValueError('invalid auxiliary Merkle branch or index')
    for sibling in siblings:
        if len(sibling) != 32:
            raise ValueError('auxiliary Merkle sibling must be 32 bytes')
        leaf = double_sha256(sibling + leaf if index & 1 else leaf + sibling)
        index >>= 1
    return leaf


def expected_index(nonce: int, depth: int) -> int:
    if not 0 <= nonce < 2**32 or not 0 <= depth <= MAX_BRANCH:
        raise ValueError('invalid auxiliary tree nonce or depth')
    size = 1 << depth
    value = (nonce * 1103515245 + 12345) % size
    return ((value + AUXPOW_CHAIN_ID) * 1103515245 + 12345) % size


def commitment(child_hash: bytes, siblings: tuple[bytes, ...] = (), nonce: int = 0) -> bytes:
    root = merkle_branch(child_hash, siblings, expected_index(nonce, len(siblings)))
    return MERGE_MAGIC + root[::-1] + (1 << len(siblings)).to_bytes(4, 'little') + nonce.to_bytes(4, 'little')


@dataclass(frozen=True)
class AuxPow:
    coinbase: bytes
    parent_header: bytes
    coinbase_branch: tuple[bytes, ...] = ()
    chain_branch: tuple[bytes, ...] = ()
    chain_index: int = 0

    def __post_init__(self):
        object.__setattr__(self, 'coinbase_branch', tuple(self.coinbase_branch))
        object.__setattr__(self, 'chain_branch', tuple(self.chain_branch))

    def serialize(self) -> bytes:
        if not 1 <= len(self.coinbase) <= MAX_COINBASE or len(self.parent_header) != 80:
            raise ValueError('invalid auxiliary coinbase or parent-header length')
        merkle_branch(b'\0' * 32, self.coinbase_branch, 0)
        merkle_branch(b'\0' * 32, self.chain_branch, self.chain_index)
        payload = (len(self.coinbase).to_bytes(4, 'big') + self.coinbase + self.parent_header
                   + bytes([len(self.coinbase_branch)]) + b''.join(self.coinbase_branch)
                   + bytes([len(self.chain_branch)]) + b''.join(self.chain_branch)
                   + self.chain_index.to_bytes(4, 'little'))
        if len(payload) > MAX_AUXPOW_SIZE:
            raise ValueError('auxiliary proof exceeds size limit')
        return payload

    @classmethod
    def read_from(cls, reader: Reader):
        start = reader.offset
        size = reader.uint(4)
        if not 1 <= size <= MAX_COINBASE:
            raise ValueError('invalid auxiliary coinbase length')
        coinbase, header = reader.take(size), reader.take(80)
        branches = []
        for _ in range(2):
            count = reader.uint(1)
            if count > MAX_BRANCH:
                raise ValueError('auxiliary branch exceeds depth limit')
            branches.append(tuple(reader.take(32) for _ in range(count)))
        proof = cls(coinbase, header, *branches, reader.uint(4, 'little'))
        if reader.offset - start > MAX_AUXPOW_SIZE:
            raise ValueError('auxiliary proof exceeds size limit')
        proof.serialize()
        return proof

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) > MAX_AUXPOW_SIZE:
            raise ValueError('auxiliary proof exceeds size limit')
        reader = Reader(data)
        proof = cls.read_from(reader)
        reader.finish()
        return proof

    def validate(self, child_hash: bytes, target: int) -> None:
        from bitcoin.core import CTransaction, CheckTransaction
        self.serialize()
        # Canonical reserialization rejects permissive CompactSize encodings.
        try:
            tx = CTransaction.deserialize(self.coinbase)
            CheckTransaction(tx)
        except Exception as exc:
            raise ValueError('invalid Bitcoin coinbase transaction') from exc
        if tx.serialize() != self.coinbase or not tx.is_coinbase():
            raise ValueError('auxiliary transaction must be a canonical Bitcoin coinbase')
        script = bytes(tx.vin[0].scriptSig)
        if script.count(MERGE_MAGIC) != 1:
            raise ValueError('exactly one merged-mining marker is required')
        offset = script.index(MERGE_MAGIC) + len(MERGE_MAGIC)
        if len(script) - offset < 40:
            raise ValueError('truncated merged-mining commitment')
        size = int.from_bytes(script[offset + 32:offset + 36], 'little')
        nonce = int.from_bytes(script[offset + 36:offset + 40], 'little')
        if size != 1 << len(self.chain_branch) or self.chain_index != expected_index(nonce, len(self.chain_branch)):
            raise ValueError('merged-mining tree size or chain slot does not match')
        root = merkle_branch(child_hash, self.chain_branch, self.chain_index)
        if script[offset:offset + 32] != root[::-1]:
            raise ValueError('coinbase does not commit to this ShieldBit block')
        if merkle_branch(tx.GetTxid(), self.coinbase_branch, 0) != self.parent_header[36:68]:
            raise ValueError('Bitcoin coinbase Merkle proof does not match parent header')
        if int.from_bytes(self.parent_header[:4], 'little') >> 16 == AUXPOW_CHAIN_ID:
            raise ValueError('auxiliary parent cannot have the ShieldBit chain identifier')
        if int.from_bytes(double_sha256(self.parent_header), 'little') > target:
            raise ValueError('auxiliary parent proof-of-work does not meet ShieldBit target')


def mining_template(block) -> dict:
    """Return a child commitment for an external pool or independent work proxy."""
    from shieldbit.consensus.params import AUXPOW_VERSION
    if block.header.version != AUXPOW_VERSION or block.auxpow is not None:
        raise ValueError('expected an unsolved auxiliary template')
    return {'header': block.header.serialize().hex(),
            'transactions': [tx.serialize().hex() for tx in block.transactions],
            'hash': block.header.hash.hex(), 'target': f'{block.header.target:064x}',
            'chain_id': AUXPOW_CHAIN_ID, 'commitment': commitment(block.header.hash).hex()}


def complete_template(template: dict, proof: bytes | None):
    """Decode bounded, untrusted pool input; consensus validation follows at submission."""
    from shieldbit.consensus.params import AUXPOW_VERSION, MAX_BLOCK_SIZE
    from shieldbit.core.block import Block, BlockHeader, HEADER_SIZE
    from shieldbit.core.transaction import Transaction
    if not isinstance(template, dict):
        raise ValueError('mining template must be an object')
    header, transactions = template.get('header'), template.get('transactions')
    if not isinstance(header, str) or len(header) != HEADER_SIZE * 2:
        raise ValueError('invalid template header')
    if not isinstance(transactions, list) or not 1 <= len(transactions) <= MAX_BLOCK_SIZE // 4:
        raise ValueError('invalid template transactions')
    size = HEADER_SIZE + 4 + (len(proof) if proof is not None else 0)
    for tx in transactions:
        if not isinstance(tx, str) or len(tx) % 2:
            raise ValueError('invalid template transaction encoding')
        size += len(tx) // 2
        if size > MAX_BLOCK_SIZE:
            raise ValueError('completed block exceeds size limit')
    decoded = BlockHeader.from_bytes(bytes.fromhex(header))
    if decoded.version != AUXPOW_VERSION:
        raise ValueError('template must use auxiliary proof mode')
    return Block(decoded, tuple(Transaction.from_bytes(bytes.fromhex(tx)) for tx in transactions),
                 auxpow=AuxPow.from_bytes(proof) if proof is not None else None)


def mine_auxiliary(block, max_nonce: int = 100_000):
    """Reference CPU solver for independent Bitcoin-format work, not a pool server.

    No Bitcoin connection or reward is required. External ASIC/pool controllers
    can replace this nonce search and submit the same commitment/proof format.
    """
    from dataclasses import replace
    from bitcoin.core import CTransaction, CTxIn, CTxOut, COutPoint, CBlockHeader
    from bitcoin.core.script import CScript
    mining_template(block)
    if type(max_nonce) is not int or not 0 <= max_nonce < 2**32:
        raise ValueError('nonce limit must be an unsigned 32-bit integer')
    tx = CTransaction((CTxIn(COutPoint(), CScript(b'\x01\x01' + commitment(block.header.hash))),),
                      (CTxOut(0, CScript()),))
    header = CBlockHeader(nVersion=0x20000000, hashMerkleRoot=tx.GetTxid(),
                          nTime=block.header.timestamp, nBits=block.header.bits).serialize()
    for nonce in range(max_nonce + 1):
        candidate = header[:76] + nonce.to_bytes(4, 'little')
        if int.from_bytes(double_sha256(candidate), 'little') <= block.header.target:
            return replace(block, auxpow=AuxPow(tx.serialize(), candidate))
    return None
