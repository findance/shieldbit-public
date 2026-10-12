# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""Block structures with fixed-width header serialisation.

Block header hashing uses **double SHA-256** (SHA-256²) for merge-mining
compatibility with Bitcoin.  Transaction IDs and all other hashes continue
to use SHA3-256.

Header wire format (152 bytes):
  version    : 4 bytes  (big-endian uint32)
  prev_hash  : 32 bytes
  merkle_root: 32 bytes
  filter_root: 32 bytes
  timestamp  : 8 bytes  (big-endian uint64)
  bits       : 4 bytes  (compact target, Bitcoin nBits encoding)
  target     : 32 bytes (full 256-bit integer)
  nonce      : 8 bytes  (big-endian uint64)
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from shieldbit.consensus.params import (
    MAX_BLOCK_SIZE,
    GENESIS_BITS,
    GENESIS_TIMESTAMP,
    GENESIS_MESSAGE,
    block_reward,
    compact_to_target,
    AUXPOW_VERSION,
)
from shieldbit.crypto.hashing import double_sha256, double_sha3
from .merkle import merkle_root as compute_merkle_root
from .transaction import Transaction, TxOutput, coinbase as make_coinbase
from shieldbit.network_profile import network_value

if TYPE_CHECKING:
    from shieldbit.consensus.auxpow import AuxPow


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _u(value: int, size: int) -> bytes:
    """Encode *value* as a big-endian integer of *size* bytes."""
    if not 0 <= value < 1 << (8 * size):
        raise ValueError(f"integer {value} out of range for {size} bytes")
    return value.to_bytes(size, "big")


HEADER_SIZE = 4 + 32 + 32 + 32 + 8 + 4 + 32 + 8  # = 152 bytes
_HEADER_SIZE = HEADER_SIZE


# ---------------------------------------------------------------------------
# BlockHeader
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BlockHeader:
    """Immutable block header.

    Attributes:
        version:     Protocol version (currently 1).
        prev_hash:   32-byte hash of the preceding block header.
        merkle_root: 32-byte Merkle root of the block's transaction IDs.
        filter_root: 32-byte root of the GCS compact block filter.
        timestamp:   Unix epoch seconds (uint64).
        bits:        Compact difficulty target (4-byte nBits encoding).
        target:      Full 256-bit difficulty target decoded from *bits*.
        nonce:       64-bit proof-of-work nonce.
    """
    version: int
    prev_hash: bytes       # 32 bytes
    merkle_root: bytes     # 32 bytes
    filter_root: bytes     # 32 bytes
    timestamp: int
    bits: int              # compact nBits — 4 bytes
    target: int            # full 256-bit integer decoded from bits
    nonce: int = 0

    def serialize(self) -> bytes:
        """Return the canonical 152-byte wire encoding of this header."""
        for name, value in (
            ("prev_hash", self.prev_hash),
            ("merkle_root", self.merkle_root),
            ("filter_root", self.filter_root),
        ):
            if len(value) != 32:
                raise ValueError(f"{name} must be 32 bytes")
        return b"".join((
            _u(self.version, 4),
            self.prev_hash,
            self.merkle_root,
            self.filter_root,
            _u(self.timestamp, 8),
            _u(self.bits, 4),
            _u(self.target, 32),
            _u(self.nonce, 8),
        ))

    @property
    def hash(self) -> bytes:
        """32-byte double-SHA256 hash of this header (used for PoW and chaining)."""
        return double_sha256(self.serialize())

    @classmethod
    def from_bytes(cls, data: bytes) -> "BlockHeader":
        """Deserialise a block header from *data*.

        Reads exactly ``_HEADER_SIZE`` bytes from the start of *data*.
        Raises ``ValueError`` if *data* is too short.
        """
        if len(data) < _HEADER_SIZE:
            raise ValueError(
                f"data too short for block header: need {_HEADER_SIZE} bytes, "
                f"got {len(data)}"
            )
        offset = 0
        version    = int.from_bytes(data[offset:offset + 4], "big");  offset += 4
        prev_hash  = data[offset:offset + 32];                         offset += 32
        mroot      = data[offset:offset + 32];                         offset += 32
        froot      = data[offset:offset + 32];                         offset += 32
        timestamp  = int.from_bytes(data[offset:offset + 8], "big");   offset += 8
        bits       = int.from_bytes(data[offset:offset + 4], "big");   offset += 4
        target     = int.from_bytes(data[offset:offset + 32], "big");  offset += 32
        nonce      = int.from_bytes(data[offset:offset + 8], "big");   offset += 8
        return cls(
            version=version,
            prev_hash=prev_hash,
            merkle_root=mroot,
            filter_root=froot,
            timestamp=timestamp,
            bits=bits,
            target=target,
            nonce=nonce,
        )


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Block:
    """A complete, immutable block (header + ordered list of transactions).

    Attributes:
        header:       The :class:`BlockHeader` for this block.
        transactions: Ordered tuple of :class:`~shieldbit.core.transaction.Transaction`.
        height:       Chain height at which this block was accepted (set by
                      the :class:`~shieldbit.core.blockchain.Blockchain` when
                      the block is added; ``None`` if not yet known).
    """
    header: BlockHeader
    transactions: tuple[Transaction, ...] = field(default_factory=tuple)
    height: Optional[int] = None   # set when added to chain; not part of wire format
    auxpow: AuxPow | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "transactions", tuple(self.transactions))

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def serialize(self) -> bytes:
        """Return the wire encoding of this block.

        Format:
          header payload (152 bytes)  +
          tx_count (4 bytes BE)       +
          transaction payloads (variable)

        Raises ``ValueError`` if the result would exceed MAX_BLOCK_SIZE.
        """
        header_bytes = self.header.serialize()
        if (self.header.version == AUXPOW_VERSION) != (self.auxpow is not None):
            raise ValueError('block proof mode and auxiliary proof disagree')
        proof_bytes = self.auxpow.serialize() if self.auxpow is not None else b''
        tx_bytes = b"".join(tx.serialize() for tx in self.transactions)
        payload = (
            header_bytes
            + proof_bytes
            + len(self.transactions).to_bytes(4, "big")
            + tx_bytes
        )
        if len(payload) > MAX_BLOCK_SIZE:
            raise ValueError(
                f"block size {len(payload)} exceeds maximum {MAX_BLOCK_SIZE}"
            )
        return payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "Block":
        """Deserialise a complete block from raw *data* bytes.

        Parses the fixed-width header, then reads transactions sequentially.
        """
        if not _HEADER_SIZE + 4 <= len(data) <= MAX_BLOCK_SIZE:
            raise ValueError("data too short for a valid block")
        header = BlockHeader.from_bytes(data)
        offset = _HEADER_SIZE
        auxpow = None
        if header.version == AUXPOW_VERSION:
            from shieldbit.consensus.auxpow import AuxPow
            from shieldbit.core.wire import Reader
            reader = Reader(data, offset)
            auxpow = AuxPow.read_from(reader)
            offset = reader.offset
        if len(data) - offset < 4:
            raise ValueError('truncated block transaction count')
        tx_count = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        if tx_count > (len(data) - offset) // 32:
            raise ValueError("transaction count exceeds block payload")
        transactions: list[Transaction] = []
        for _ in range(tx_count):
            tx, offset = Transaction.read_from(data, offset)
            transactions.append(tx)
        if offset != len(data):
            raise ValueError("trailing block bytes")
        return cls(header=header, transactions=tuple(transactions), auxpow=auxpow)

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def validate_merkle(self) -> bool:
        """Return True iff the header's merkle_root matches the transactions."""
        computed = compute_merkle_root([tx.txid for tx in self.transactions])
        return self.header.merkle_root == computed

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Serialised byte length of this block (header + all transactions)."""
        return len(self.serialize())

    def fee_total(self, utxo_amounts: dict[tuple[bytes, int], int]) -> int:
        """Return the total fees collected from all non-coinbase transactions.

        Args:
            utxo_amounts: Mapping of (txid, output_index) → amount in quanta.

        Returns:
            Sum of fees across all non-coinbase transactions in quanta.
        """
        total = 0
        for tx in self.transactions:
            if not tx.is_coinbase():
                total += tx.fee(utxo_amounts)
        return total

    # ------------------------------------------------------------------
    # Genesis factory
    # ------------------------------------------------------------------

    @classmethod
    def create_genesis(cls, miner_address_hash: bytes) -> "Block":
        """Create and **mine** the genesis block.

        Uses ``GENESIS_BITS``, ``GENESIS_TIMESTAMP``, and ``GENESIS_MESSAGE``
        from the consensus parameters.  The genesis difficulty (MIN_BITS) is
        set deliberately low so that this completes quickly in Python.

        Args:
            miner_address_hash: 32-byte versioned public-key commitment,
                                used as the coinbase output recipient.

        Returns:
            A fully solved :class:`Block` (valid PoW nonce found).

        Raises:
            RuntimeError: If no nonce in [0, 2^64) produces a valid hash
                          (this should be impossible with MIN_BITS difficulty).
        """
        if len(miner_address_hash) != 32:
            raise ValueError('genesis recipient must be a 32-byte versioned commitment')
        genesis_reward = block_reward(0)
        bits = network_value('GENESIS_BITS', GENESIS_BITS)
        timestamp = network_value('GENESIS_TIMESTAMP', GENESIS_TIMESTAMP)
        cb_tx = make_coinbase(
            height=0,
            amount=genesis_reward,
            recipient=miner_address_hash,
            message=network_value('GENESIS_MESSAGE', GENESIS_MESSAGE),
        )
        txids = [cb_tx.txid]
        mroot = compute_merkle_root(txids)
        from shieldbit.core.filters import build_gcs_filter, filter_hash
        filter_root = filter_hash(build_gcs_filter([miner_address_hash]))

        target = compact_to_target(bits)

        # Build an unsigned header (nonce = 0) then search for the nonce.
        # We serialise without the nonce field and append candidates.
        base_bytes = b"".join((
            (1).to_bytes(4, "big"),     # version
            b"\x00" * 32,               # prev_hash (all-zero for genesis)
            mroot,
            filter_root,
            timestamp.to_bytes(8, "big"),
            bits.to_bytes(4, "big"),
            target.to_bytes(32, "big"),
            # nonce appended in loop below
        ))

        winning_nonce: Optional[int] = None
        for nonce in range(2**64):
            candidate = base_bytes + nonce.to_bytes(8, "big")
            digest = double_sha256(candidate)
            if int.from_bytes(digest, "big") <= target:
                winning_nonce = nonce
                break

        if winning_nonce is None:
            raise RuntimeError("Failed to find genesis nonce — impossible with MIN_BITS")

        genesis_header = BlockHeader(
            version=1,
            prev_hash=b"\x00" * 32,
            merkle_root=mroot,
            filter_root=filter_root,
            timestamp=timestamp,
            bits=bits,
            target=target,
            nonce=winning_nonce,
        )
        block = cls(header=genesis_header, transactions=(cb_tx,), height=0)
        return block
