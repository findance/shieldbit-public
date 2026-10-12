# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Compact block relay for ShieldBit.

Reduces 6 MB block propagation to ~12 KB by sending only a block header
and short 6-byte transaction identifiers. Peers reconstruct the full block
from their mempool, requesting only truly missing transactions.

This dramatically reduces bandwidth during normal operation — a well-connected
node with a typical mempool can reconstruct >95% of blocks immediately.

Author: Vipul Tomar
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from shieldbit.core.block import HEADER_SIZE, Block, BlockHeader
from shieldbit.core.transaction import Transaction
from shieldbit.core.wire import Reader

if TYPE_CHECKING:
    from shieldbit.core.block import Block, BlockHeader
    from shieldbit.core.transaction import Transaction


# ---------------------------------------------------------------------------
# SipHash-2-4 (64-bit output, pure Python)
# ---------------------------------------------------------------------------

def _siphash24_64(k0: int, k1: int, data: bytes) -> int:
    """SipHash-2-4 with 64-bit integer keys, returns 64-bit integer."""
    def _u64(x: int) -> int:
        return x & 0xFFFFFFFFFFFFFFFF

    def _rotl(x: int, b: int) -> int:
        return _u64((x << b) | (x >> (64 - b)))

    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573

    def _round() -> None:
        nonlocal v0, v1, v2, v3
        v0 = _u64(v0 + v1); v1 = _u64(_rotl(v1, 13) ^ v0); v0 = _rotl(v0, 32)
        v2 = _u64(v2 + v3); v3 = _u64(_rotl(v3, 16) ^ v2)
        v0 = _u64(v0 + v3); v3 = _u64(_rotl(v3, 21) ^ v0)
        v2 = _u64(v2 + v1); v1 = _u64(_rotl(v1, 17) ^ v2); v2 = _rotl(v2, 32)

    msg = bytearray(data)
    length = len(msg)
    msg += b'\x00' * (-(length + 1) % 8)
    msg.append(length & 0xFF)

    for i in range(0, len(msg), 8):
        m = struct.unpack_from('<Q', msg, i)[0]
        v3 ^= m
        _round()
        _round()
        v0 ^= m

    v2 ^= 0xFF
    _round()
    _round()
    _round()
    _round()
    return _u64(v0 ^ v1 ^ v2 ^ v3)


def short_txid(txid: bytes, k0: int, k1: int) -> int:
    """Compute a 6-byte (48-bit) short transaction ID using SipHash-2-4.

    Args:
        txid: 32-byte full transaction ID.
        k0: First 8-byte SipHash key.
        k1: Second 8-byte SipHash key.

    Returns:
        48-bit integer short txid.
    """
    h = _siphash24_64(k0, k1, txid)
    return h & 0xFFFFFFFFFFFF  # truncate to 48 bits


def _derive_keys(header_hash: bytes, nonce: int) -> tuple[int, int]:
    """Derive SipHash keys from block header hash + nonce."""
    from shieldbit.crypto.hashing import sha3_256
    seed = sha3_256(header_hash + nonce.to_bytes(8, 'little'))
    k0 = struct.unpack_from('<Q', seed, 0)[0]
    k1 = struct.unpack_from('<Q', seed, 8)[0]
    return k0, k1


# ---------------------------------------------------------------------------
# CompactBlock
# ---------------------------------------------------------------------------

@dataclass
class CompactBlock:
    """A compact block for rapid relay.

    Attributes:
        header_bytes: Serialized BlockHeader (152 bytes).
        nonce: 8-byte random nonce used to seed the short txid key.
        short_txids: List of 48-bit short txids for non-prefilled transactions.
        prefilled: List of (index, serialized_tx_bytes) for pre-included transactions.
                   The coinbase (index 0) is always prefilled.
    """
    header_bytes: bytes
    nonce: int
    short_txids: list[int] = field(default_factory=list)
    prefilled: list[tuple[int, bytes]] = field(default_factory=list)
    auxpow_bytes: bytes = b''

    def to_bytes(self) -> bytes:
        """Serialize the compact block."""
        self.validate()
        def _varint(n: int) -> bytes:
            if n < 0xFD:
                return bytes([n])
            elif n <= 0xFFFF:
                return b'\xfd' + struct.pack('<H', n)
            else:
                return b'\xfe' + struct.pack('<I', n)

        buf = bytearray()
        buf += self.header_bytes
        buf += self.auxpow_bytes
        buf += struct.pack('<Q', self.nonce)
        buf += _varint(len(self.short_txids))
        for sid in self.short_txids:
            buf += struct.pack('<Q', sid)[:6]  # 6-byte little-endian

        buf += _varint(len(self.prefilled))
        for idx, tx_bytes in self.prefilled:
            buf += _varint(idx)
            buf += _varint(len(tx_bytes))
            buf += tx_bytes

        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes) -> CompactBlock:
        """Deserialize a compact block from wire bytes."""
        reader = Reader(data)
        header_bytes = reader.take(HEADER_SIZE)
        from shieldbit.consensus.params import AUXPOW_VERSION
        proof = b''
        if BlockHeader.from_bytes(header_bytes).version == AUXPOW_VERSION:
            from shieldbit.consensus.auxpow import AuxPow
            proof = AuxPow.read_from(reader).serialize()
        nonce = reader.uint(8, 'little')
        n_short = reader.compact_size()
        if n_short > reader.remaining // 6:
            raise ValueError('short ID count exceeds payload')
        short_txids = [reader.uint(6, 'little') for _ in range(n_short)]
        n_prefilled = reader.compact_size()
        if n_prefilled > reader.remaining // 34:
            raise ValueError('prefilled count exceeds payload')
        prefilled = []
        for _ in range(n_prefilled):
            idx = reader.compact_size()
            prefilled.append((idx, reader.take(reader.compact_size())))
        reader.finish()
        compact = cls(header_bytes, nonce, short_txids, prefilled, proof)
        compact.validate()
        return compact

    def validate(self) -> None:
        if not 0 <= self.nonce < 2**64:
            raise ValueError('invalid compact nonce')
        if len(self.header_bytes) != HEADER_SIZE:
            raise ValueError('invalid compact header length')
        header = BlockHeader.from_bytes(self.header_bytes)
        from shieldbit.consensus.params import AUXPOW_VERSION
        if (header.version == AUXPOW_VERSION) != bool(self.auxpow_bytes):
            raise ValueError('compact block proof mode disagrees with proof')
        if self.auxpow_bytes:
            from shieldbit.consensus.auxpow import AuxPow
            AuxPow.from_bytes(self.auxpow_bytes)
        total = len(self.prefilled) + len(self.short_txids)
        indices = [index for index, _ in self.prefilled]
        if not indices or indices[0] != 0 or indices != sorted(set(indices)):
            raise ValueError('invalid prefilled indices')
        if indices[-1] >= total or any(not 0 <= sid < 2**48 for sid in self.short_txids):
            raise ValueError('invalid compact transaction index or short ID')
        for _, payload in self.prefilled:
            Transaction.from_bytes(payload)


# ---------------------------------------------------------------------------
# Build and reconstruct
# ---------------------------------------------------------------------------

def build_compact_block(block: Block) -> CompactBlock:
    """Build a compact block from a full block.

    The coinbase transaction is always prefilled (index 0).
    All other transactions are represented by their 6-byte short txids.

    Args:
        block: The full Block to compact.

    Returns:
        CompactBlock ready for relay.
    """
    header_bytes = block.header.serialize()
    nonce = int.from_bytes(os.urandom(8), 'little')
    k0, k1 = _derive_keys(block.header.hash, nonce)

    prefilled: list[tuple[int, bytes]] = []
    short_txids: list[int] = []

    for i, tx in enumerate(block.transactions):
        tx_bytes = tx.serialize()
        if i == 0:  # Always prefill coinbase
            prefilled.append((0, tx_bytes))
        else:
            short_txids.append(short_txid(tx.txid, k0, k1))

    return CompactBlock(
        header_bytes=header_bytes,
        nonce=nonce,
        short_txids=short_txids,
        prefilled=prefilled,
        auxpow_bytes=block.auxpow.serialize() if block.auxpow else b'',
    )


def get_missing_short_txids(
    compact: CompactBlock,
    mempool: dict[int, bytes],
) -> list[int]:
    """Return short txids that are not present in the mempool.

    Args:
        compact: The CompactBlock received from a peer.
        mempool: Mapping of short_txid -> serialized_tx_bytes.

    Returns:
        List of short txids that need to be fetched via GETBLOCKTXN.
    """
    return [sid for sid in compact.short_txids if sid not in mempool]


def reconstruct_block(
    compact: CompactBlock,
    mempool: dict[int, bytes],
) -> bytes | None:
    """Reconstruct the full serialized block from a CompactBlock and mempool.

    Args:
        compact: The CompactBlock received.
        mempool: Mapping of short_txid -> serialized_tx_bytes for locally known txs.

    Returns:
        Serialized block bytes if all transactions found, None if any are missing.
    """
    compact.validate()
    # Build prefilled map (index -> tx_bytes)
    prefilled_map: dict[int, bytes] = {idx: tx for idx, tx in compact.prefilled}

    # Reconstruct ordered transaction list
    from shieldbit.crypto.hashing import double_sha256
    header_hash = double_sha256(compact.header_bytes)
    k0, k1 = _derive_keys(header_hash, compact.nonce)

    txs: list[bytes] = []

    # Total number of transactions = prefilled + short_txids
    total = len(compact.prefilled) + len(compact.short_txids)
    prefilled_indices = set(prefilled_map.keys())

    non_prefilled_pos = 0
    for i in range(total):
        if i in prefilled_indices:
            txs.append(prefilled_map[i])
        else:
            try:
                sid = compact.short_txids[non_prefilled_pos]
                non_prefilled_pos += 1
            except IndexError:
                return None
            tx_bytes = mempool.get(sid)
            if tx_bytes is None:
                return None
            tx = Transaction.from_bytes(tx_bytes)
            if short_txid(tx.txid, k0, k1) != sid:
                return None
            txs.append(tx_bytes)

    # Full blocks use a fixed-width big-endian transaction count.
    payload = compact.header_bytes + compact.auxpow_bytes + len(txs).to_bytes(4, 'big') + b''.join(txs)
    if not Block.from_bytes(payload).validate_merkle():
        return None
    return payload


def mempool_to_short_txid_map(
    mempool_txids: list[bytes],
    header_hash: bytes,
    nonce: int,
) -> dict[int, bytes]:
    """Convert mempool txids to a short_txid lookup map.

    Args:
        mempool_txids: List of full 32-byte txids from mempool.
        header_hash: 32-byte hash of the block header being reconstructed.
        nonce: Nonce from the CompactBlock.

    Returns:
        Dict mapping short_txid (int) -> txid (bytes).
    """
    k0, k1 = _derive_keys(header_hash, nonce)
    result = {}
    collisions = set()
    for txid in mempool_txids:
        sid = short_txid(txid, k0, k1)
        if sid in result and result[sid] != txid:
            collisions.add(sid)
        result[sid] = txid
    return {sid: txid for sid, txid in result.items() if sid not in collisions}
