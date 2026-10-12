# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Bech32m address codec for ShieldBit (BIP-350).

All ShieldBit addresses use the ``sb1`` human-readable part (HRP) and a
witness version prefix, encoded using the bech32m checksum constant
(0x2BC830A3). New ML-DSA addresses use witness version 3 and a tagged 32-byte
commitment to the versioned public key. Witness versions 0-2 are legacy codecs
only, not valid payment destinations under the new consensus rules.

Wire format
-----------
    sb1 <sep=1> <witness_ver(5-bit)> <hash160_in_5-bit_groups> <6-char_checksum>

All on-wire addresses are lower-case.  Addresses are at most 90 characters.

Author: Vipul Tomar
"""
from __future__ import annotations

from typing import List, Optional

from .hashing import hash160 as _hash160, address_commitment


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

from shieldbit.network_profile import network_value

HRP: str = "sb1"
"""Human-readable part for all ShieldBit addresses."""

BECH32M_CONST: int = 0x2BC830A3
"""Bech32m checksum constant from BIP-350."""

CHARSET: str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
"""Bech32 character set — 32 characters mapped to 5-bit values 0–31."""

CHARSET_REV: dict[str, int] = {char: pos for pos, char in enumerate(CHARSET)}

SUPPORTED_VERSIONS: set[int] = {0, 1, 2, 3, 4}
ADDRESS_LENGTHS = {0: 20, 1: 20, 2: 20, 3: 32, 4: 32}
ADDRESS_KEY_VERSIONS = {0: 0, 1: 1, 2: 2, 3: 1, 4: 2}
"""Allowed witness version values (5-bit, 0–16)."""

MAX_ADDRESS_LENGTH: int = 90


# ---------------------------------------------------------------------------
# Low-level bech32m primitives (BIP-350 reference implementation)
# ---------------------------------------------------------------------------

def _polymod(values: List[int]) -> int:
    """Compute the bech32(m) checksum polynomial over *values*.

    Implements the GF(2^30) polynomial from BIP-173/BIP-350.

    Args:
        values: Sequence of integers, each in [0, 31].

    Returns:
        32-bit integer checksum.
    """
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, gen in enumerate(generators):
            if (top >> i) & 1:
                chk ^= gen
    return chk


def _expand_hrp(hrp: str) -> List[int]:
    """Return the HRP expansion for use in :func:`_polymod`.

    The expansion is: high-bits of each character (bits 7-5), a zero
    separator, then low-bits of each character (bits 4-0).

    Args:
        hrp: Human-readable part string (ASCII).

    Returns:
        List of integers suitable for prepending to the data before
        calling :func:`_polymod`.
    """
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp: str, data: List[int]) -> List[int]:
    """Compute the 6-character bech32m checksum for *hrp* and *data*.

    Args:
        hrp:  Human-readable part.
        data: 5-bit integer sequence (witness version + converted payload).

    Returns:
        List of 6 integers in [0, 31] representing the checksum characters.
    """
    values = _expand_hrp(hrp) + data + [0] * 6
    polymod = _polymod(values) ^ BECH32M_CONST
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]


def _verify_checksum(hrp: str, data: List[int]) -> bool:
    """Return ``True`` if *data* contains a valid bech32m checksum for *hrp*.

    Args:
        hrp:  Human-readable part.
        data: 5-bit integer sequence including checksum characters.

    Returns:
        ``True`` if ``polymod(_expand_hrp(hrp) + data) == BECH32M_CONST``.
    """
    return _polymod(_expand_hrp(hrp) + data) == BECH32M_CONST


def _convertbits(
    data: bytes,
    frombits: int = 8,
    tobits: int = 5,
    pad: bool = True,
) -> List[int]:
    """Convert a byte array between bit-group widths.

    Args:
        data:     Input bytes.
        frombits: Number of bits per input group (typically 8).
        tobits:   Number of bits per output group (typically 5).
        pad:      If ``True``, pad the final group with zero bits so no
                  input bits are lost.

    Returns:
        List of integers in ``[0, 2^tobits - 1]``.

    Raises:
        ValueError: If the padding would produce an incomplete group with
            non-zero bits (only checked when *pad* is ``False``).
    """
    acc = 0
    bits = 0
    result: List[int] = []
    maxv = (1 << tobits) - 1
    for byte in data:
        acc = (acc << frombits) | byte
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits) & maxv)
    if pad:
        if bits:
            result.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding in convertbits")
    return result


def _convertbits_back(data: List[int], frombits: int = 5, tobits: int = 8) -> bytes:
    """Convert a 5-bit integer list back to bytes, stripping padding.

    Args:
        data:     List of integers in ``[0, 2^frombits - 1]``.
        frombits: Bits per input group (typically 5).
        tobits:   Bits per output group (typically 8).

    Returns:
        Reconstructed byte string.

    Raises:
        ValueError: On invalid padding or out-of-range values.
    """
    acc = 0
    bits = 0
    result: List[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError(f"Invalid value in 5-bit data: {value}")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits) & maxv)
    # Trailing bits must all be zero
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding in 5-bit to 8-bit conversion")
    return bytes(result)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def pubkey_to_address(public_key: bytes, version: int = 1, *, commitment_version: int = 2) -> str:
    """Encode a public key as a ShieldBit bech32m address.

    Encodes a version-2 tagged 32-byte commitment by default. ``version`` is
    the signing key scheme (1=ML-DSA); its new address witness version is 3.
    ``commitment_version=1`` explicitly exports a legacy 20-byte address.

    The *public_key* may be either raw bytes (no prefix) or version-prefixed
    bytes (first byte = key-type version); both forms are accepted.

    Args:
        public_key: Public key bytes, with or without a leading version byte.
        version:    Witness version to embed in the address (0, 1, or 2).
                    Defaults to 1.

    Returns:
        Lower-case bech32m address string (e.g. ``"sb1q..."``).

    Raises:
        ValueError: If *version* is not in :data:`SUPPORTED_VERSIONS`.
    """
    if version not in (0, 1, 2):
        raise ValueError(
            f"Unsupported witness version {version}. "
            f"Accepted: {sorted(SUPPORTED_VERSIONS)}"
        )
    if commitment_version == 2 and version in (1, 2):
        witness_version = version + 2
        key_hash = address_commitment(public_key)
    elif commitment_version == 1:
        witness_version = version
        key_hash = _hash160(public_key)
    else:
        raise ValueError('unsupported address commitment version')
    data = [witness_version] + _convertbits(key_hash)
    hrp = network_value('ADDRESS_HRP', HRP)
    checksum = _create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[x] for x in data + checksum)


def address_to_commitment(address: str, expected_version: int | None = None,
                          *, expected_commitment_version: int | None = None) -> bytes:
    """Decode a versioned address without changing or truncating its commitment.

    Args:
        address: A valid lower-case ShieldBit bech32m address.

    Returns:
        20-byte legacy or 32-byte version-2 commitment payload.

    Raises:
        ValueError: If the address is malformed, has an invalid checksum, or
            decodes to a payload of unexpected length.
    """
    if not validate_address(address):
        raise ValueError(f"Invalid ShieldBit address: {address!r}")

    sep_pos = len(network_value('ADDRESS_HRP', HRP)) + 1
    data_chars = address[sep_pos:]
    decoded = [CHARSET_REV[c] for c in data_chars]
    # Strip the 6-character checksum
    payload = decoded[:-6]
    # payload[0] is the witness version; payload[1:] is the hash in 5-bit groups
    witness_ver = payload[0]
    if expected_version is not None and ADDRESS_KEY_VERSIONS.get(witness_ver) != expected_version:
        raise ValueError('recipient address uses an unavailable signing version')
    commitment_version = 2 if witness_ver in (3, 4) else 1
    if expected_commitment_version is not None and commitment_version != expected_commitment_version:
        raise ValueError('legacy address requires explicit migration')
    if witness_ver not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported witness version: {witness_ver}")
    raw = _convertbits_back(payload[1:])
    if len(raw) != ADDRESS_LENGTHS[witness_ver]:
        raise ValueError(
            f"Expected {ADDRESS_LENGTHS[witness_ver]}-byte commitment, decoded {len(raw)} bytes"
        )
    return raw


def address_to_hash160(address: str, expected_version: int | None = None) -> bytes:
    """Legacy-only decoder; never silently truncate a version-2 address."""
    return address_to_commitment(address, expected_version, expected_commitment_version=1)


def validate_address(address: str) -> bool:
    """Return ``True`` if *address* is a well-formed ShieldBit bech32m address.

    Checks:
    * All lower-case.
    * Starts with ``sb1`` + separator ``1`` (i.e. the HRP is ``sb1``).
    * Length at most :data:`MAX_ADDRESS_LENGTH` characters.
    * All data characters are in the bech32 charset.
    * Checksum passes bech32m verification.
    * Witness version is in :data:`SUPPORTED_VERSIONS`.
    * Payload length matches the witness version (legacy 20 or new 32 bytes).

    Args:
        address: Candidate address string.

    Returns:
        ``True`` if the address is valid, ``False`` otherwise.
    """
    if not isinstance(address, str):
        return False
    if address != address.lower():
        return False
    hrp = network_value('ADDRESS_HRP', HRP)
    prefix = hrp + "1"
    if not address.startswith(prefix):
        return False
    if len(address) > MAX_ADDRESS_LENGTH:
        return False

    data_part = address[len(prefix):]
    # Must have at least 7 data chars: 1 version + 4 payload groups + 6 checksum
    if len(data_part) < 7:
        return False

    try:
        decoded = [CHARSET_REV[c] for c in data_part]
    except KeyError:
        return False

    if not _verify_checksum(hrp, decoded):
        return False

    # Strip checksum and check witness version
    payload = decoded[:-6]
    if not payload:
        return False
    witness_ver = payload[0]
    if witness_ver not in SUPPORTED_VERSIONS:
        return False

    # The witness version determines commitment length; no permissive fallback.
    try:
        raw = _convertbits_back(payload[1:])
    except ValueError:
        return False
    return len(raw) == ADDRESS_LENGTHS[witness_ver]
