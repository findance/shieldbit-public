# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""Canonical transaction objects; signatures are validated by a supplied provider.

All transaction hashing uses SHA3-256 (double_sha3) — only block header PoW
uses SHA-256.  The ``signing_hash`` property returns the hash of the
serialised transaction with all signature fields zeroed, which is what
signers commit to when producing an ML-DSA-65 signature.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import NamedTuple

from shieldbit.crypto.hashing import double_sha3, sha3_256, tagged_hash
from shieldbit.consensus.params import MAX_SUPPLY, MIN_FEE


# ---------------------------------------------------------------------------
# Transaction type registry
# ---------------------------------------------------------------------------

class TxType(IntEnum):
    """Wire type identifiers; only TRANSFER and COINBASE are supported."""
    TRANSFER           = 0x01
    COINBASE           = 0x02
    # Reserved legacy encodings, rejected by consensus. Do not reuse these values.
    CHANNEL_OPEN       = 0x10
    CHANNEL_CLOSE      = 0x11
    CHANNEL_FORCE_CLOSE = 0x12
    CHANNEL_PENALTY    = 0x13
    CHANNEL_ANCHOR     = 0x14
    HTLC_LOCK          = 0x20
    HTLC_CLAIM         = 0x21
    HTLC_REFUND        = 0x22


# ---------------------------------------------------------------------------
# UTXO value object
# ---------------------------------------------------------------------------

class UTXO(NamedTuple):
    """Immutable snapshot of an unspent transaction output."""
    txid: bytes            # 32-byte transaction identifier
    output_index: int      # 0-based index within the transaction
    amount: int            # value in quanta
    recipient: bytes       # 32-byte versioned public-key commitment
    height: int            # block height at which this UTXO was created
    coinbase: bool         # True if this output came from a coinbase transaction


# ---------------------------------------------------------------------------
# Serialisation helpers (internal)
# ---------------------------------------------------------------------------

def _u(value: int, width: int) -> bytes:
    """Encode *value* as a big-endian integer of *width* bytes."""
    if not 0 <= value < 1 << (width * 8):
        raise ValueError(f"integer {value} out of range for {width} bytes")
    return value.to_bytes(width, "big")


def _blob(value: bytes) -> bytes:
    """Prefix *value* with its 4-byte big-endian length."""
    return _u(len(value), 4) + value


# ---------------------------------------------------------------------------
# Transaction components
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TxInput:
    """A reference to a previous output being spent.

    Attributes:
        prev_txid:    32-byte txid of the transaction containing the output.
        output_index: Index of the output within that transaction.
        signature:    ML-DSA-65 signature (or empty when computing signing_hash).
        public_key:   Encoded public key that signed (or empty when signing).
        sequence:     Sequence number.  Values < 0xFFFFFFFE signal RBF opt-in.
                      Defaults to 0xFFFFFFFF (final / no RBF).
    """
    prev_txid: bytes
    output_index: int
    signature: bytes = b""
    public_key: bytes = b""
    sequence: int = 0xFFFF_FFFF   # Only values below 0xFFFFFFFE signal RBF.

    def serialize(self) -> bytes:
        """Return the canonical byte encoding of this input."""
        if len(self.prev_txid) != 32:
            raise ValueError("prev_txid must be 32 bytes")
        return (
            self.prev_txid
            + _u(self.output_index, 4)
            + _blob(self.signature)
            + _blob(self.public_key)
            + _u(self.sequence, 4)
        )

    @property
    def signals_rbf(self) -> bool:
        """True if this input opts in to Replace-by-Fee."""
        return self.sequence < 0xFFFF_FFFE


@dataclass(frozen=True)
class TxOutput:
    """A destination amount + recipient in a transaction.

    Attributes:
        amount:          Value in quanta (must be >= 0 and <= MAX_SUPPLY).
        recipient:       Hash of the recipient's public key (or script bytes).
        ephemeral_pubkey: Reserved wire-format extension; must be empty for valid outputs.
    """
    amount: int
    recipient: bytes
    ephemeral_pubkey: bytes = b""

    def serialize(self) -> bytes:
        """Return the canonical byte encoding of this output."""
        if not 0 <= self.amount <= MAX_SUPPLY:
            raise ValueError(f"invalid output amount {self.amount}")
        return _u(self.amount, 8) + _blob(self.recipient) + _blob(self.ephemeral_pubkey)


# ---------------------------------------------------------------------------
# Transaction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Transaction:
    """An immutable, fully self-describing transaction.

    All fields are encoded into ``serialize()`` which is then double-SHA3'd
    to produce the ``txid``.  Signatures cover ``signing_hash`` — the hash of
    the same serialisation but with all ``signature`` fields replaced by empty
    bytes, preventing signature malleability.

    Attributes:
        tx_type:     One of the :class:`TxType` constants.
        inputs:      Ordered tuple of :class:`TxInput` objects.
        outputs:     Ordered tuple of :class:`TxOutput` objects.
        lock_height: Block height before which this tx is invalid (0 = none).
        lock_time:   Unix timestamp before which this tx is invalid (0 = none).
        rbf:         Explicit signed RBF flag; True requires at least one signaling input.
        version:     Transaction/signing format version (currently 2).
        data:        Arbitrary extra data field (type-specific payload).
    """
    tx_type: TxType
    inputs: tuple[TxInput, ...]   = field(default_factory=tuple)
    outputs: tuple[TxOutput, ...] = field(default_factory=tuple)
    lock_height: int = 0
    lock_time: int   = 0
    rbf: bool        = False
    version: int     = 2
    data: bytes      = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs",  tuple(self.inputs))
        object.__setattr__(self, "outputs", tuple(self.outputs))

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def serialize(self) -> bytes:
        """Return the canonical byte serialisation of this transaction."""
        parts: list[bytes] = [
            _u(self.version, 2),
            _u(int(self.tx_type), 1),
            _u(self.lock_height, 8),
            _u(self.lock_time, 8),
            _u(int(self.rbf), 1),
            _u(len(self.inputs), 4),
        ]
        parts.extend(txin.serialize() for txin in self.inputs)
        parts.append(_u(len(self.outputs), 4))
        parts.extend(output.serialize() for output in self.outputs)
        parts.append(_blob(self.data))
        return b"".join(parts)

    def _serialize_for_signing(self) -> bytes:
        """Return the serialisation used when computing signing_hash.

        Identical to ``serialize()`` except all ``signature`` fields are
        replaced with empty bytes, preventing signature-over-signature loops.
        """
        unsigned_inputs = tuple(
            TxInput(
                prev_txid=txin.prev_txid,
                output_index=txin.output_index,
                signature=b"",
                public_key=txin.public_key,
                sequence=txin.sequence,
            )
            for txin in self.inputs
        )
        stripped = Transaction(
            tx_type=self.tx_type,
            inputs=unsigned_inputs,
            outputs=self.outputs,
            lock_height=self.lock_height,
            lock_time=self.lock_time,
            rbf=self.rbf,
            version=self.version,
            data=self.data,
        )
        return stripped.serialize()

    @classmethod
    def read_from(cls, data: bytes, offset: int = 0) -> tuple[Transaction, int]:
        """Read one self-delimiting transaction from a bounded block payload."""
        from shieldbit.core.wire import Reader
        reader = Reader(data, offset)
        version = reader.uint(2)
        tx_type = TxType(reader.uint(1))
        lock_height, lock_time = reader.uint(8), reader.uint(8)
        flag = reader.uint(1)
        if flag not in (0, 1):
            raise ValueError("invalid RBF flag")
        inputs = tuple(
            TxInput(reader.take(32), reader.uint(4), reader.blob(), reader.blob(), reader.uint(4))
            for _ in range(reader.count(48))
        )
        outputs = tuple(
            TxOutput(reader.uint(8), reader.blob(), reader.blob())
            for _ in range(reader.count(16))
        )
        tx = cls(tx_type, inputs, outputs, lock_height, lock_time, bool(flag), version, reader.blob())
        if tx.serialize() != data[offset:reader.offset]:
            raise ValueError("noncanonical transaction")
        return tx, reader.offset

    @classmethod
    def from_bytes(cls, data: bytes) -> Transaction:
        """Decode exactly one transaction; reject trailing or truncated bytes."""
        tx, end = cls.read_from(data)
        if end != len(data):
            raise ValueError("trailing transaction bytes")
        return tx

    # ------------------------------------------------------------------
    # Derived identifiers / properties
    # ------------------------------------------------------------------

    @property
    def txid(self) -> bytes:
        """32-byte double-SHA3-256 hash uniquely identifying this transaction."""
        return double_sha3(self.serialize())

    @property
    def signing_hash(self) -> bytes:
        """32-byte hash that signers commit to (serialisation with empty sigs)."""
        from shieldbit.network_profile import ACTIVE
        return self.signing_hash_for(ACTIVE.get().network_id)

    def signing_hash_for(self, network_id: bytes) -> bytes:
        """Bind the canonical format to a purpose, version and immutable network."""
        if self.version != 2:
            raise ValueError('unsupported transaction signing format')
        if not isinstance(network_id, bytes) or len(network_id) != 32:
            raise ValueError('signing network identifier must be exactly 32 bytes')
        return tagged_hash('ShieldBit/TxSignature/v2',
                           b'\x00\x02' + network_id + self._serialize_for_signing())

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def output_total(self) -> int:
        """Sum of all output amounts in quanta."""
        return sum(output.amount for output in self.outputs)

    def spent_outpoints(self) -> set[tuple[bytes, int]]:
        """Set of (txid, index) pairs spent by this transaction's inputs."""
        return {(inp.prev_txid, inp.output_index) for inp in self.inputs}

    def is_coinbase(self) -> bool:
        """Return True if this is a coinbase (block-reward) transaction."""
        return self.tx_type == TxType.COINBASE

    def fee(self, utxo_amounts: dict[tuple[bytes, int], int]) -> int:
        """Compute the transaction fee given a mapping of UTXO amounts.

        Args:
            utxo_amounts: Mapping of (txid, output_index) → amount in quanta
                          for each input being spent.

        Returns:
            Fee in quanta (input total minus output total).

        Raises:
            KeyError: If a spent outpoint is not present in *utxo_amounts*.
            ValueError: If outputs exceed inputs (invalid transaction).
        """
        if self.is_coinbase():
            return 0
        input_total = sum(utxo_amounts[pt] for pt in self.spent_outpoints())
        output_total = self.output_total()
        if output_total > input_total:
            raise ValueError("outputs exceed inputs")
        return input_total - output_total


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

def coinbase(
    height: int,
    amount: int,
    recipient: bytes,
    message: bytes = b"",
) -> Transaction:
    """Create a well-formed coinbase transaction.

    The ``data`` field contains:
      * Bytes 0-7: block height encoded as 8-byte big-endian (uniquifies the
        coinbase across blocks so the txid is always distinct).
      * Bytes 8+: optional *message* appended verbatim (e.g. miner tag).

    Args:
        height:    Block height at which this coinbase will appear.
        amount:    Reward amount in quanta.
        recipient: Hash of the miner's public key / address.
        message:   Optional arbitrary bytes appended after the height.

    Returns:
        A :class:`Transaction` of type :attr:`TxType.COINBASE`.
    """
    if height < 0:
        raise ValueError("negative block height")
    data = _u(height, 8) + message
    return Transaction(
        tx_type=TxType.COINBASE,
        outputs=(TxOutput(amount, recipient),),
        data=data,
    )
