# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Merkle tree construction and proof generation using SHA3-256.

Author: Vipul Tomar
"""
from __future__ import annotations

from shieldbit.crypto.hashing import double_sha3

_ZERO_HASH = b'\x00' * 32


def merkle_root(txids: list[bytes]) -> bytes:
    """Compute the Merkle root of a list of transaction hashes.

    Args:
        txids: List of 32-byte transaction IDs.

    Returns:
        32-byte Merkle root, or 32 zero bytes for an empty list.

    Raises:
        ValueError: If any txid is not 32 bytes.
    """
    if not txids:
        return _ZERO_HASH
    if any(len(x) != 32 for x in txids):
        raise ValueError("all txids must be exactly 32 bytes")
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) & 1:
            layer.append(layer[-1])  # duplicate last element for odd-length layers
        layer = [double_sha3(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def build_merkle_tree(txids: list[bytes]) -> list[list[bytes]]:
    """Build the complete Merkle tree as a list of layers.

    Args:
        txids: List of 32-byte transaction IDs (leaf layer).

    Returns:
        List of layers from bottom (leaves) to top (root).
        Each layer is a list of 32-byte hashes.
        Returns [[ZERO_HASH]] for an empty input.
    """
    if not txids:
        return [[_ZERO_HASH]]
    layers: list[list[bytes]] = [list(txids)]
    while len(layers[-1]) > 1:
        prev = layers[-1]
        if len(prev) & 1:
            prev = prev + [prev[-1]]
        layers.append([double_sha3(prev[i] + prev[i + 1]) for i in range(0, len(prev), 2)])
    return layers


def merkle_proof(txids: list[bytes], index: int) -> list[tuple[bool, bytes]]:
    """Generate a Merkle inclusion proof for the transaction at `index`.

    Args:
        txids: Full list of leaf txids.
        index: Index of the transaction to prove.

    Returns:
        List of (is_right_sibling, sibling_hash) pairs from leaf to root.
        is_right_sibling=True means the sibling is to the right of the current node.

    Raises:
        IndexError: If index is out of range.
        ValueError: If txids is empty.
    """
    if not txids:
        raise ValueError("cannot generate proof for empty txid list")
    if not 0 <= index < len(txids):
        raise IndexError(f"index {index} out of range for {len(txids)} txids")

    proof: list[tuple[bool, bytes]] = []
    layer = list(txids)
    pos = index

    while len(layer) > 1:
        if len(layer) & 1:
            layer.append(layer[-1])
        sibling_pos = pos ^ 1  # flip last bit to get sibling
        is_right = (pos & 1) == 0  # sibling is to the right if pos is even
        proof.append((is_right, layer[sibling_pos]))
        layer = [double_sha3(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        pos >>= 1

    return proof


def verify_merkle_proof(leaf: bytes, proof: list[tuple[bool, bytes]], root: bytes) -> bool:
    """Verify a Merkle inclusion proof.

    Args:
        leaf: The 32-byte leaf hash (txid) to verify.
        proof: List of (is_right_sibling, sibling_hash) pairs from merkle_proof().
        root: The expected 32-byte Merkle root.

    Returns:
        True if the proof is valid, False otherwise.
    """
    if len(leaf) != 32 or len(root) != 32:
        return False
    current = leaf
    for is_right_sibling, sibling in proof:
        if len(sibling) != 32:
            return False
        if is_right_sibling:
            current = double_sha3(current + sibling)
        else:
            current = double_sha3(sibling + current)
    return current == root
