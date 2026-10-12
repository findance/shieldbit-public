# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""Proof-of-Work functions for ShieldBit.

Block headers are hashed with **double SHA-256** (SHA-256²) — the same
algorithm used by Bitcoin. Standalone work hashes the ShieldBit header;
auxiliary work validates a Bitcoin-format parent and its child commitment.
Sharing a hash algorithm alone does not guarantee ASIC compatibility.
"""
from __future__ import annotations

from statistics import median
from typing import TYPE_CHECKING

from shieldbit.crypto.hashing import double_sha256
from .params import (
    MAX_TARGET,
    RETARGET_INTERVAL,
    TARGET_BLOCK_SECONDS,
    compact_to_target,
    check_target,
)

if TYPE_CHECKING:
    from shieldbit.core.block import Block


# ---------------------------------------------------------------------------
# Core PoW validation
# ---------------------------------------------------------------------------

def valid_pow(header_bytes: bytes, target: int) -> bool:
    """Return True iff the double-SHA256 hash of *header_bytes* is <= *target*.

    This checks standalone ShieldBit work, not an auxiliary proof.
    """
    if target <= 0 or target > MAX_TARGET:
        return False
    digest = double_sha256(header_bytes)
    return int.from_bytes(digest, "big") <= target


# ---------------------------------------------------------------------------
# Difficulty adjustment
# ---------------------------------------------------------------------------

def validate_pow(block: "Block") -> None:
    """Verify exactly one proof mode against the same ShieldBit target."""
    from .params import AUXPOW_VERSION, target_to_compact
    header = block.header
    target = compact_to_target(header.bits)
    if not 0 < target <= MAX_TARGET or header.target != target or target_to_compact(target) != header.bits:
        raise ValueError('invalid or noncanonical proof-of-work target')
    if header.version == 1 and block.auxpow is None:
        if not check_target(header.hash, header.bits):
            raise ValueError('standalone proof-of-work does not meet difficulty target')
    elif header.version == AUXPOW_VERSION and block.auxpow is not None:
        if header.prev_hash == b'\0' * 32:
            raise ValueError('genesis must use standalone proof-of-work')
        block.auxpow.validate(header.hash, target)
    else:
        raise ValueError('unsupported block version or inconsistent proof mode')


def adjust_target(previous_target: int, timestamps: list[int]) -> int:
    """Retarget from 2016 headers spanning 2015 inter-block intervals.

    Clamps the adjustment to [¼×, 4×] of the previous target (mirrors Bitcoin).
    """
    if len(timestamps) != RETARGET_INTERVAL:
        raise ValueError("need exactly retarget interval timestamps")
    actual = timestamps[-1] - timestamps[0]
    expected = TARGET_BLOCK_SECONDS * (RETARGET_INTERVAL - 1)
    actual = max(expected // 4, min(actual, expected * 4))
    return min(MAX_TARGET, max(1, previous_target * actual // expected))


def median_time_past(timestamps: list[int]) -> int:
    """Return the median of the last 11 block timestamps (MTP-11).

    Used to enforce the rule that a block's timestamp must exceed MTP.
    """
    if not timestamps:
        raise ValueError("timestamps required")
    return int(median(timestamps[-11:]))


# ---------------------------------------------------------------------------
# Mining (nonce search)
# ---------------------------------------------------------------------------

def mine_block_header(
    header_bytes_without_nonce: bytes,
    bits: int,
    max_nonce: int = 2**64 - 1,
) -> int | None:
    """Search for a valid nonce for the given (partial) block header.

    *header_bytes_without_nonce* is the serialised BlockHeader **without** the
    8-byte nonce field appended.  This function appends each candidate nonce
    as an 8-byte big-endian value and checks whether the resulting
    double-SHA256 hash satisfies *bits*.

    Args:
        header_bytes_without_nonce: All header fields except the nonce.
        bits: Compact difficulty target.
        max_nonce: Upper bound for nonce search (exclusive upper bound).

    Returns:
        The winning nonce (int) on success, or ``None`` if no solution was
        found within the search space.
    """
    target = compact_to_target(bits)
    if target <= 0 or target > MAX_TARGET or not 0 <= max_nonce < 2**64:
        return None

    for nonce in range(max_nonce + 1):
        candidate = header_bytes_without_nonce + nonce.to_bytes(8, "big")
        digest = double_sha256(candidate)
        if int.from_bytes(digest, "big") <= target:
            return nonce
    return None


def mine_block(block: "Block", max_nonce: int = 2**32) -> "Block | None":
    """Convenience wrapper: search for a valid nonce and return a solved Block.

    Serialises the header without the nonce field, runs the nonce search, and
    — if successful — returns a new :class:`~shieldbit.core.block.Block` with
    the solved :class:`~shieldbit.core.block.BlockHeader`.

    Returns ``None`` if the search exhausted *max_nonce* without finding a
    valid solution.
    """
    from shieldbit.core.block import BlockHeader
    if block.header.version != 1 or block.auxpow is not None:
        raise ValueError('standalone mining requires a standalone block template')

    # Serialise without the 8-byte nonce tail.
    header = block.header
    header_no_nonce = header.serialize()[:-8]

    nonce = mine_block_header(header_no_nonce, block.header.bits, max_nonce)
    if nonce is None:
        return None

    solved_header = BlockHeader(
        version=header.version,
        prev_hash=header.prev_hash,
        merkle_root=header.merkle_root,
        filter_root=header.filter_root,
        timestamp=header.timestamp,
        bits=header.bits,
        target=header.target,
        nonce=nonce,
    )
    from shieldbit.core.block import Block as _Block
    return _Block(header=solved_header, transactions=block.transactions)


def estimate_hashrate(solve_time_seconds: float, nonce: int) -> float:
    """Estimate the mining hashrate in hashes per second.

    Given the number of seconds it took to find *nonce*, return an estimate
    of how many SHA-256² evaluations were performed per second.

    Args:
        solve_time_seconds: Wall-clock time elapsed during the search.
        nonce: The winning nonce (proxy for number of hashes tried).

    Returns:
        Estimated hashes per second (float).  Returns 0.0 for non-positive
        solve times.
    """
    if solve_time_seconds <= 0:
        return 0.0
    return (nonce + 1) / solve_time_seconds
