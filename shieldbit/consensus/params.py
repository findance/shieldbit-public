# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""Consensus parameters for the ShieldBit network.

These constants define the fundamental rules of the protocol and MUST NOT be
changed after genesis without a hard fork.  All amounts are in *quanta*
(1 SBT = 100,000,000 quanta).
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Monetary supply
# ---------------------------------------------------------------------------
QUANTA_PER_SBT: int = 100_000_000
MAX_SUPPLY: int = 20_000_000 * QUANTA_PER_SBT
INITIAL_REWARD: int = 40 * QUANTA_PER_SBT
# About 4.753 years at ten-minute blocks; the geometric schedule stays below 20M.
HALVING_INTERVAL: int = 250_000

# ---------------------------------------------------------------------------
# Transaction / mempool rules
# ---------------------------------------------------------------------------
COINBASE_MATURITY: int = 100
MIN_FEE: int = 250           # quanta — flat minimum per non-coinbase transaction
DUST_LIMIT: int = 546        # quanta — outputs below this are rejected

# ---------------------------------------------------------------------------
# Block limits & timing
# ---------------------------------------------------------------------------
MAX_BLOCK_SIZE: int = 6 * 1024 * 1024    # 6 MB
TARGET_BLOCK_SECONDS: int = 600           # 10 minutes
RETARGET_INTERVAL: int = 2_016           # blocks per difficulty epoch
MAX_TARGET: int = (1 << 248) - 1

# Draft pre-mainnet consensus identifier; freeze only with network approval.
AUXPOW_CHAIN_ID: int = 0x5342
AUXPOW_VERSION: int = (AUXPOW_CHAIN_ID << 16) | 0x100 | 1
MAX_AUXPOW_SIZE: int = 16 * 1024
MIN_PRUNE_BLOCKS: int = 288

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
NETWORK_PORT: int = 9333
MAGIC_BYTES: bytes = b'\x53\x48\x42\x54'
USER_AGENT: str = '/ShieldBit:0.1.0/'
VERSION: str = '0.1.0'

# ---------------------------------------------------------------------------
# Genesis block
# ---------------------------------------------------------------------------
GENESIS_MESSAGE: bytes = (
    b'OM | 0001-01-01T01:01:01Z\n'
    b'Always believe future is brighter'
)
GENESIS_TIMESTAMP: int = 1_791_648_833
GENESIS_BITS: int = 0x1e0ffff0    # easy initial difficulty for genesis mining
MIN_BITS: int = 0x1e0ffff0        # difficulty floor


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def block_reward(height: int) -> int:
    """Return the subsidy in quanta for the block at *height*.

    Halves every HALVING_INTERVAL blocks in integer quanta until rounding to zero.
    """
    if height < 0:
        raise ValueError("negative height")
    halvings = height // HALVING_INTERVAL
    if halvings >= 64:
        return 0
    return INITIAL_REWARD >> halvings


def compact_to_target(bits: int) -> int:
    """Convert a compact ``bits`` field (4 bytes, nBits format) to a 256-bit
    integer target.

    The encoding matches Bitcoin's nBits:
      * High byte  = exponent (number of bytes in the target)
      * Low 3 bytes = coefficient (mantissa, most-significant byte may not
        have its high bit set — that would make the value negative)

    Returns 0 for invalid or negative-looking encodings.
    """
    exponent: int = (bits >> 24) & 0xFF
    coefficient: int = bits & 0x007FFFFF
    if bits & 0x00800000:
        return 0
    if exponent <= 3:
        target = coefficient >> (8 * (3 - exponent))
    else:
        target = coefficient << (8 * (exponent - 3))
    return target


def target_to_compact(target: int) -> int:
    """Convert a 256-bit integer *target* to compact ``bits`` encoding.

    The result is the minimal 4-byte representation such that
    ``compact_to_target(result) <= target`` (discarding low-order bytes).
    """
    if target <= 0:
        return 0
    nbytes: int = (target.bit_length() + 7) // 8
    if nbytes <= 3:
        coefficient = target << (8 * (3 - nbytes))
    else:
        coefficient = target >> (8 * (nbytes - 3))
    if coefficient & 0x00800000:
        coefficient >>= 8
        nbytes += 1
    return (nbytes << 24) | (coefficient & 0x007FFFFF)


def check_target(block_hash: bytes, bits: int) -> bool:
    """Return True iff *block_hash* satisfies the compact difficulty *bits*.

    Interprets *block_hash* as a big-endian 256-bit integer and compares it
    against the decoded target.  A zero target always fails.
    """
    target: int = compact_to_target(bits)
    if target <= 0 or target > MAX_TARGET or len(block_hash) != 32:
        return False
    hash_int: int = int.from_bytes(block_hash, "big")
    return hash_int <= target
