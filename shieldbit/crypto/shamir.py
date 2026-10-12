# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Shamir's Secret Sharing over GF(2^8).

Splits an arbitrary-length secret into *n* shares such that any *k* of them
can reconstruct the secret, but k-1 or fewer shares reveal zero information
about the secret.

GF(2^8) arithmetic uses the irreducible polynomial
x^8 + x^4 + x^3 + x + 1 (0x11B), the same field used by AES.
Each byte of the secret is treated as an independent element of GF(256);
the resulting shares have the same byte-length as the secret.

Share format
------------
:func:`split_secret` returns a list of ``(share_index, share_value)`` tuples.
The *share_index* is an integer in ``[1, n]`` and *share_value* is a bytes
object of the same length as the secret.  The index acts as the x-coordinate
in the polynomial and is NOT prepended to the share bytes; it is returned
separately so callers can store them however they like.

Author: Vipul Tomar
"""
from __future__ import annotations

import secrets
from typing import List, Tuple


# ---------------------------------------------------------------------------
# GF(256) arithmetic — irreducible polynomial 0x11B (AES field)
# ---------------------------------------------------------------------------

def _gf_mul(a: int, b: int) -> int:
    """Multiply two GF(256) elements using the 0x11B irreducible polynomial.

    Implements carry-less multiplication modulo the field polynomial via the
    Russian-peasant (double-and-add) algorithm.  All intermediate values
    remain in ``[0, 255]``.

    Args:
        a: First field element in ``[0, 255]``.
        b: Second field element in ``[0, 255]``.

    Returns:
        Product ``a * b`` in GF(256) in ``[0, 255]``.
    """
    result = 0
    a = a & 0xFF
    b = b & 0xFF
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return result & 0xFF


def _gf_pow(a: int, n: int) -> int:
    """Raise *a* to the *n*-th power in GF(256).

    Uses fast binary exponentiation.

    Args:
        a: Base element in ``[0, 255]``.
        n: Non-negative integer exponent.

    Returns:
        ``a^n`` in GF(256).
    """
    result = 1
    a = a & 0xFF
    while n:
        if n & 1:
            result = _gf_mul(result, a)
        a = _gf_mul(a, a)
        n >>= 1
    return result


def _gf_inv(a: int) -> int:
    """Return the multiplicative inverse of *a* in GF(256).

    Uses Fermat's little theorem: for all non-zero ``a`` in GF(256),
    ``a^255 == 1``, so ``a^(-1) == a^254``.

    Args:
        a: Non-zero field element in ``[1, 255]``.

    Returns:
        Multiplicative inverse of *a* in GF(256).

    Raises:
        ZeroDivisionError: If *a* is zero (no multiplicative inverse exists).
    """
    if a == 0:
        raise ZeroDivisionError("GF(256): multiplicative inverse of zero is undefined")
    return _gf_pow(a, 254)


def _gf_div(a: int, b: int) -> int:
    """Divide ``a`` by ``b`` in GF(256).

    Equivalent to ``a * b^(-1)`` in the field.

    Args:
        a: Numerator element in ``[0, 255]``.
        b: Denominator element in ``[1, 255]``.

    Returns:
        Quotient ``a / b`` in GF(256).

    Raises:
        ZeroDivisionError: If *b* is zero.
    """
    if b == 0:
        raise ZeroDivisionError("GF(256): division by zero")
    return _gf_mul(a, _gf_inv(b))


def _poly_eval(coefficients: List[int], x: int) -> int:
    """Evaluate a GF(256) polynomial at point *x* using Horner's method.

    The polynomial is specified as a list of coefficients in ascending order
    of degree: ``[c0, c1, c2, ...]`` represents ``c0 + c1*x + c2*x^2 + ...``.

    Args:
        coefficients: GF(256) coefficients, index 0 = constant term.
        x:            Evaluation point in ``[0, 255]``.

    Returns:
        Polynomial value at *x* in GF(256).
    """
    value = 0
    for coeff in reversed(coefficients):
        value = _gf_mul(value, x) ^ coeff
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_params(n: int, k: int) -> None:
    """Validate Shamir split parameters and raise on constraint violation.

    Constraints:
    * *k* ≥ 2  (a threshold of 1 provides no secrecy — any single share
      reveals the secret, since it equals the polynomial at that point).
    * *k* ≤ *n*  (cannot require more shares than exist).
    * *n* ≤ 255  (GF(256) only has 255 non-zero x-coordinates).

    Args:
        n: Total number of shares to produce.
        k: Minimum number of shares required to reconstruct the secret.

    Raises:
        ValueError: If any constraint is violated.
    """
    if k < 2:
        raise ValueError(
            f"Threshold k must be at least 2 (got k={k}). "
            "A threshold of 1 gives no secrecy."
        )
    if k > n:
        raise ValueError(
            f"Threshold k ({k}) must not exceed the share count n ({n})."
        )
    if n > 255:
        raise ValueError(
            f"Share count n must not exceed 255 (got n={n}). "
            "GF(256) only supports 255 distinct non-zero x-coordinates."
        )


def split_secret(
    secret: bytes,
    n: int,
    k: int,
) -> List[Tuple[int, bytes]]:
    """Split *secret* into *n* shares with a *k*-of-*n* threshold.

    Each byte of the secret is encoded independently over GF(256) as the
    constant term of a fresh random polynomial of degree ``k - 1``.  The
    shares are the polynomial values at x = 1, 2, …, n.

    Args:
        secret: Non-empty bytes object to protect.
        n:      Total number of shares to generate.
        k:      Minimum number of shares needed to reconstruct the secret.

    Returns:
        List of *n* ``(share_index, share_value)`` tuples.  Share indices
        run from 1 to *n* inclusive.  Share values have the same length as
        *secret*.

    Raises:
        ValueError: If *secret* is empty or if the parameters violate the
            constraints checked by :func:`validate_params`.

    Example::

        shares = split_secret(b"hunter2", n=5, k=3)
        recovered = recover_secret(shares[:3])
        assert recovered == b"hunter2"
    """
    if not secret:
        raise ValueError("Secret must be a non-empty bytes object")
    validate_params(n, k)

    # Pre-allocate one buffer per share
    share_buffers: List[bytearray] = [bytearray() for _ in range(n)]

    for byte_value in secret:
        # Degree-(k-1) polynomial: constant term = byte_value, rest random
        coefficients: List[int] = [byte_value] + list(secrets.token_bytes(k - 1))
        for share_idx in range(n):
            x = share_idx + 1  # x ∈ {1, …, n}
            share_buffers[share_idx].append(_poly_eval(coefficients, x))

    return [(idx + 1, bytes(buf)) for idx, buf in enumerate(share_buffers)]


def recover_secret(shares: List[Tuple[int, bytes]]) -> bytes:
    """Recover the original secret from a subset of Shamir shares.

    Uses Lagrange interpolation over GF(256) evaluated at x = 0, processing
    each byte position independently.  At least *k* shares are required
    (the threshold that was used during :func:`split_secret`).

    Args:
        shares: List of ``(share_index, share_value)`` tuples as returned by
            :func:`split_secret`.  All share values must have the same length.
            Share indices must be distinct non-zero integers.

    Returns:
        Reconstructed secret as a :class:`bytes` object.

    Raises:
        ValueError: If fewer than 2 shares are provided, share indices are not
            distinct, or share value lengths are inconsistent.

    Example::

        shares = split_secret(b"s3cr3t!", n=5, k=3)
        assert recover_secret(shares[0:3]) == b"s3cr3t!"
        assert recover_secret(shares[2:5]) == b"s3cr3t!"
    """
    if len(shares) < 2:
        raise ValueError(
            f"Need at least 2 shares to reconstruct a secret (got {len(shares)})"
        )

    indices = [idx for idx, _ in shares]
    if len(set(indices)) != len(indices):
        raise ValueError(
            "Share indices must be distinct: found duplicate index in provided shares"
        )
    if any(idx < 1 or idx > 255 for idx in indices):
        raise ValueError(
            "Share indices must be in [1, 255]"
        )

    share_len = len(shares[0][1])
    if share_len == 0:
        raise ValueError("Share values must be non-empty")
    if any(len(val) != share_len for _, val in shares):
        raise ValueError(
            "All share values must have the same byte length"
        )

    result = bytearray()

    for byte_pos in range(share_len):
        # Collect (x, y) pairs at this byte position
        points: List[Tuple[int, int]] = [(idx, val[byte_pos]) for idx, val in shares]

        # Lagrange interpolation at x = 0
        secret_byte = 0
        for i, (xi, yi) in enumerate(points):
            # Compute the Lagrange basis value ℓ_i(0) = ∏_{j≠i} (0 - xj)/(xi - xj)
            # In GF(2): 0 - xj == xj; subtraction is XOR.
            basis = 1
            for j, (xj, _) in enumerate(points):
                if i != j:
                    numerator = xj            # 0 XOR xj = xj
                    denominator = xi ^ xj     # xi - xj = xi XOR xj in GF(2)
                    basis = _gf_mul(basis, _gf_div(numerator, denominator))
            secret_byte ^= _gf_mul(yi, basis)

        result.append(secret_byte)

    return bytes(result)
