# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Hash functions used by the ShieldBit protocol.

Design notes
------------
* SHA3-256 is the **primary** protocol hash, used for all general-purpose
  cryptographic commitments: transaction IDs, block hashes, address derivation,
  Merkle trees, compact-filter mapping, and tagged-hash constructions.
* SHA-256 / double-SHA-256 are provided **exclusively** to support merge-mining
  and auxiliary compatibility with Bitcoin tooling.  They MUST NOT be used in
  any native ShieldBit data structure outside of PoW block-header processing.

Author: Vipul Tomar
"""
from __future__ import annotations

import hashlib
from hashlib import sha3_256 as _sha3_256, sha256 as _sha256


# ---------------------------------------------------------------------------
# SHA3-256 family — primary protocol hash
# ---------------------------------------------------------------------------

def sha3_256(data: bytes) -> bytes:
    """Return the SHA3-256 digest of *data*.

    Primary hash primitive for ShieldBit transaction IDs, block hashes,
    Merkle trees, compact filters, and address derivation.

    Args:
        data: Arbitrary byte string to hash.

    Returns:
        32-byte SHA3-256 digest.
    """
    return _sha3_256(data).digest()


def double_sha3(data: bytes) -> bytes:
    """Return SHA3-256(SHA3-256(*data*)).

    Used in Merkle tree construction to provide second-preimage resistance
    at the commitment layer.

    Args:
        data: Arbitrary byte string to hash.

    Returns:
        32-byte double-SHA3-256 digest.
    """
    return sha3_256(sha3_256(data))


def hash160(data: bytes) -> bytes:
    """Return the legacy-only 20-byte address identifier for *data*.

    Computed as the first 20 bytes of SHA3-256(*data*).  This is the value
    encoded into historical addresses, not new consensus payment outputs.

    Args:
        data: Typically a serialised public key (version byte + raw key bytes).

    Returns:
        20-byte address hash.
    """
    return sha3_256(data)[:20]


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Return a domain-separated SHA3-256 digest.

    Computes SHA3-256(SHA3-256(tag_bytes) || SHA3-256(tag_bytes) || data),
    analogous to BIP-340 tagged hashes but using SHA3-256.  Prevents
    cross-protocol hash collisions by prepending a tag-specific prefix.

    Args:
        tag:  ASCII tag string identifying the hashing domain
              (e.g. ``"ShieldBit/TxSigHash"``).
        data: Payload to hash under the given tag.

    Returns:
        32-byte tagged digest.
    """
    tag_hash = sha3_256(tag.encode("utf-8"))
    return sha3_256(tag_hash + tag_hash + data)


def address_commitment(public_key: bytes) -> bytes:
    """Version-2, 32-byte commitment to the versioned signing public key."""
    return tagged_hash('ShieldBit/AddressCommitment/v2', public_key)


# ---------------------------------------------------------------------------
# SHA-256 family — merge-mining / PoW compatibility layer ONLY
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of *data*.

    Provided **only** for merge-mining compatibility with Bitcoin's PoW chain.
    Do **not** use this function in native ShieldBit data structures.

    Args:
        data: Arbitrary byte string to hash.

    Returns:
        32-byte SHA-256 digest.
    """
    return _sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    """Return SHA-256(SHA-256(*data*)).

    Standard Bitcoin double-SHA-256.  Used when constructing or verifying
    merge-mined block headers so that ShieldBit auxiliary PoW is
    byte-for-byte compatible with Bitcoin miners.

    Args:
        data: Arbitrary byte string to hash.

    Returns:
        32-byte double-SHA-256 digest.
    """
    return sha256(sha256(data))


def hash256(data: bytes) -> bytes:
    """Alias for :func:`double_sha256`.

    Matches the ``Hash256`` naming convention used in many Bitcoin
    implementations.

    Args:
        data: Arbitrary byte string to hash.

    Returns:
        32-byte double-SHA-256 digest.
    """
    return double_sha256(data)
