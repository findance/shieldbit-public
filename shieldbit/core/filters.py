# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Compact block filters (Golomb-Coded Sets) for ShieldBit light clients.

Implements BIP-158-style compact filters using SHA3-256 and SipHash-2-4.
Light clients download only filter headers (~50 MB/year) instead of full blocks
(~315 GB/year), querying full nodes only when a filter matches their addresses.

Author: Vipul Tomar
"""
from __future__ import annotations

import struct
from shieldbit.crypto.hashing import sha3_256

# Golomb parameter: false-positive rate ~ 1/2^P
P: int = 20
# Modulus M for mapping hashes into range [0, N*M)
M: int = 1 << P  # 1,048,576


# ---------------------------------------------------------------------------
# SipHash-2-4 (pure Python, 64-bit output)
# ---------------------------------------------------------------------------

def _siphash24(key: bytes, data: bytes) -> int:
    """SipHash-2-4: fast non-cryptographic hash for GCS element hashing.

    Args:
        key: 16-byte SipHash key.
        data: Input data to hash.

    Returns:
        64-bit integer hash value.
    """
    assert len(key) == 16

    def _u64(x: int) -> int:
        return x & 0xFFFFFFFFFFFFFFFF

    def _rotl(x: int, b: int) -> int:
        return _u64((x << b) | (x >> (64 - b)))

    k0 = struct.unpack_from('<Q', key, 0)[0]
    k1 = struct.unpack_from('<Q', key, 8)[0]

    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573

    def _sip_round() -> None:
        nonlocal v0, v1, v2, v3
        v0 = _u64(v0 + v1); v1 = _u64(_rotl(v1, 13) ^ v0); v0 = _rotl(v0, 32)
        v2 = _u64(v2 + v3); v3 = _u64(_rotl(v3, 16) ^ v2)
        v0 = _u64(v0 + v3); v3 = _u64(_rotl(v3, 21) ^ v0)
        v2 = _u64(v2 + v1); v1 = _u64(_rotl(v1, 17) ^ v2); v2 = _rotl(v2, 32)

    # Pad and process message
    msg = bytearray(data)
    length = len(msg)
    msg += b'\x00' * (-(length + 1) % 8)
    msg.append(length & 0xFF)

    for i in range(0, len(msg), 8):
        m = struct.unpack_from('<Q', msg, i)[0]
        v3 ^= m
        _sip_round()
        _sip_round()
        v0 ^= m

    v2 ^= 0xFF
    _sip_round()
    _sip_round()
    _sip_round()
    _sip_round()
    return _u64(v0 ^ v1 ^ v2 ^ v3)


def _hash_to_range(key: bytes, data: bytes, n: int) -> int:
    """Map data to [0, n * M) using SipHash."""
    h = _siphash24(key, data)
    # Use 128-bit multiplication to avoid modulo bias: (h * (n * M)) >> 64
    return (h * (n * M)) >> 64


# ---------------------------------------------------------------------------
# Golomb-Rice encoding / decoding
# ---------------------------------------------------------------------------

class _BitWriter:
    def __init__(self) -> None:
        self._buf = bytearray()
        self._bits = 0
        self._nbits = 0

    def write_bits(self, value: int, n: int) -> None:
        self._bits = (self._bits << n) | (value & ((1 << n) - 1))
        self._nbits += n
        while self._nbits >= 8:
            self._nbits -= 8
            self._buf.append((self._bits >> self._nbits) & 0xFF)

    def flush(self) -> bytes:
        if self._nbits:
            self._buf.append((self._bits << (8 - self._nbits)) & 0xFF)
            self._nbits = 0
        return bytes(self._buf)


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._byte_pos = 0
        self._bit_pos = 0

    def read_bit(self) -> int:
        if self._byte_pos >= len(self._data):
            raise EOFError("GCS filter exhausted")
        bit = (self._data[self._byte_pos] >> (7 - self._bit_pos)) & 1
        self._bit_pos += 1
        if self._bit_pos == 8:
            self._bit_pos = 0
            self._byte_pos += 1
        return bit

    def read_bits(self, n: int) -> int:
        result = 0
        for _ in range(n):
            result = (result << 1) | self.read_bit()
        return result


def _encode_golomb(writer: _BitWriter, value: int, p: int) -> None:
    """Encode a single value using Golomb-Rice coding."""
    q, r = divmod(value, 1 << p)
    for _ in range(q):
        writer.write_bits(1, 1)
    writer.write_bits(0, 1)
    writer.write_bits(r, p)


def _decode_golomb(reader: _BitReader, p: int) -> int:
    """Decode a single Golomb-Rice coded value."""
    q = 0
    while reader.read_bit():
        q += 1
    r = reader.read_bits(p)
    return (q << p) | r


# ---------------------------------------------------------------------------
# Public GCS filter API
# ---------------------------------------------------------------------------

def build_gcs_filter(items: list[bytes], key: bytes | None = None) -> bytes:
    """Build a Golomb-Coded Set filter from a list of items (e.g. address hashes).

    Args:
        items: List of byte strings to include in the filter (e.g. 20-byte address hashes).
        key: Optional 16-byte SipHash key. If None, uses 16 zero bytes.

    Returns:
        Encoded GCS filter bytes (4-byte count prefix + Golomb-coded deltas).
    """
    if not items:
        return b'\x00\x00\x00\x00'

    if key is None:
        key = b'\x00' * 16

    unique_items = set(items)
    n = len(unique_items)
    hashes = sorted(_hash_to_range(key, item, n) for item in unique_items)
    n_unique = n

    writer = _BitWriter()
    prev = 0
    for h in hashes:
        delta = h - prev
        _encode_golomb(writer, delta, P)
        prev = h

    encoded = writer.flush()
    # Prefix: 4-byte count of unique elements, then encoded key (16 bytes), then GCS data
    return struct.pack('>I', n_unique) + (key or b'\x00' * 16) + encoded


def match_filter(filter_bytes: bytes, query_items: list[bytes]) -> bool:
    """Test whether any of the query items are present in the GCS filter.

    Args:
        filter_bytes: Filter bytes as returned by build_gcs_filter().
        query_items: List of items to query (same type as items passed to build_gcs_filter).

    Returns:
        True if any item is probably in the filter, False if definitely not.
        (False positives possible at rate ~1/2^P; no false negatives.)
    """
    if len(filter_bytes) < 20:
        return False

    n_unique = struct.unpack_from('>I', filter_bytes, 0)[0]
    if n_unique == 0:
        return False

    key = filter_bytes[4:20]
    gcs_data = filter_bytes[20:]

    # Build sorted set of query hashes
    query_hashes = sorted(set(_hash_to_range(key, item, n_unique) for item in query_items))

    # Decode GCS and merge-search
    reader = _BitReader(gcs_data)
    current = 0
    qi = 0

    try:
        for _ in range(n_unique):
            delta = _decode_golomb(reader, P)
            current += delta
            while qi < len(query_hashes) and query_hashes[qi] < current:
                qi += 1
            if qi < len(query_hashes) and query_hashes[qi] == current:
                return True
    except EOFError:
        pass

    return False


def filter_hash(filter_bytes: bytes) -> bytes:
    """Compute SHA3-256 hash of a GCS filter for block header commitment.

    Args:
        filter_bytes: Filter bytes as returned by build_gcs_filter().

    Returns:
        32-byte SHA3-256 hash.
    """
    return sha3_256(filter_bytes)
