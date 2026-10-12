# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Fail-closed signature provider boundary for ShieldBit.

ShieldBit does not roll its own post-quantum signature scheme. Instead, all
signing and verification is delegated through the :class:`SignatureProvider`
Protocol to a reviewed FIPS 204/205 implementation.  The module auto-registers
:class:`MLDSAProvider` (ML-DSA-65, version byte 0x01) at import time using the
``cryptography`` library.  A stub for SLH-DSA (version byte 0x02) is also
present and will be activated once the library ships full support.

Versioning scheme
-----------------
* Private keys are stored as raw bytes from the underlying library.
* Public keys on the wire: ``version_byte(1) || raw_public_key_bytes``.
* Signatures on the wire:  ``version_byte(1) || raw_signature_bytes``.
* :func:`verify` auto-detects the version from the first byte of the
  signature, so callers do not need to track key versions separately.

Author: Vipul Tomar
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

# ---------------------------------------------------------------------------
# Version constants
# ---------------------------------------------------------------------------

ML_DSA_65: int = 0x01
"""Version byte for ML-DSA-65 (FIPS 204) keys and signatures."""

SLH_DSA: int = 0x02
"""Version byte for SLH-DSA (FIPS 205) keys and signatures — reserved."""


# ---------------------------------------------------------------------------
# SignatureProvider Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class SignatureProvider(Protocol):
    """Protocol that every signature backend must satisfy.

    Implementors are responsible for key generation, signing, and
    verification.  They must expose a ``version`` class-level integer
    matching one of the defined version constants.
    """

    version: int

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a fresh key pair.

        Returns:
            ``(private_key_bytes, public_key_bytes)`` where both are raw byte
            strings without any version prefix.  The caller (or registry) is
            responsible for attaching version bytes before serialisation.
        """
        ...

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign *message* with *private_key*.

        Args:
            private_key: Raw private key bytes (no version prefix).
            message:     Arbitrary byte string to sign (the caller should
                         pass a pre-hashed 32-byte digest in practice).

        Returns:
            Raw signature bytes without a version prefix.
        """
        ...

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify *signature* over *message* using *public_key*.

        Args:
            public_key: Raw public key bytes (no version prefix).
            message:    The message that was signed.
            signature:  Raw signature bytes (no version prefix).

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        ...


# ---------------------------------------------------------------------------
# Concrete provider: ML-DSA-65 (FIPS 204)
# ---------------------------------------------------------------------------

class MLDSAProvider:
    """Signature provider backed by ML-DSA-65 (FIPS 204).

    Uses ``cryptography.hazmat.primitives.asymmetric.mldsa`` as shipped in
    pyca/cryptography >= 48.0.  The import is deferred to the first operation
    so that the module can be imported on systems that have an older version
    of the library installed — any attempt to actually use the provider will
    raise a clear :class:`RuntimeError` in that case.

    Key format
    ----------
    * Private key: 32-byte seed from ``MLDSA65PrivateKey.private_bytes_raw()``.
    * Public key (wire): ``b'\\x01' + raw_public_key_bytes``.

    Signature format
    ----------------
    * Wire signature: ``b'\\x01' + raw_ml_dsa_signature_bytes``.
    """

    version: int = ML_DSA_65

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_backend():
        """Import and return the mldsa module, raising a helpful error on failure."""
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa  # type: ignore[attr-defined]
            if not hasattr(mldsa, "MLDSA65PrivateKey"):
                raise ImportError("ML-DSA-65 backend unavailable")
            return mldsa
        except (ImportError, AttributeError) as exc:
            raise RuntimeError(
                "ML-DSA-65 requires a supported cryptography backend. "
                "Upgrade with: pip install 'cryptography>=50.0.2'"
            ) from exc

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a fresh ML-DSA-65 key pair.

        Returns:
            ``(raw_private_key_bytes, raw_public_key_bytes)`` — no version
            prefixes.  Use :func:`serialize_public_key` to add the prefix
            before transmitting on the wire.

        Raises:
            RuntimeError: If the ``cryptography`` library version does not
                support ML-DSA-65.
        """
        mldsa = self._load_backend()
        try:
            priv = mldsa.MLDSA65PrivateKey.generate()
        except UnsupportedAlgorithm as exc:
            raise RuntimeError("The installed backend does not support ML-DSA-65") from exc
        raw_priv = priv.private_bytes_raw()
        raw_pub = priv.public_key().public_bytes_raw()
        return raw_priv, raw_pub

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign *message* using the raw ML-DSA-65 *private_key*.

        Args:
            private_key: Raw private key bytes as returned by
                :meth:`generate_keypair`.
            message:     Arbitrary byte payload to sign.

        Returns:
            Raw ML-DSA-65 signature bytes (no version prefix).

        Raises:
            RuntimeError: If the ``cryptography`` library version does not
                support ML-DSA-65.
            ValueError:   If *private_key* cannot be loaded.
        """
        mldsa = self._load_backend()
        try:
            priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(private_key)
            return priv.sign(message)
        except UnsupportedAlgorithm as exc:
            raise RuntimeError("The installed backend does not support ML-DSA-65") from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a raw ML-DSA-65 *signature* over *message*.

        Args:
            public_key: Raw public key bytes (no version prefix).
            message:    The signed message.
            signature:  Raw ML-DSA-65 signature (no version prefix).

        Returns:
            ``True`` if the signature is valid.

        Raises:
            RuntimeError: If the ``cryptography`` library version does not
                support ML-DSA-65.
        """
        mldsa = self._load_backend()
        try:
            pub = mldsa.MLDSA65PublicKey.from_public_bytes(public_key)
            pub.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
        except UnsupportedAlgorithm as exc:
            raise RuntimeError("The installed backend does not support ML-DSA-65") from exc


# ---------------------------------------------------------------------------
# Stub provider: SLH-DSA (FIPS 205) — reserved for future use
# ---------------------------------------------------------------------------

class SLHDSAProvider:
    """Placeholder for the SLH-DSA (FIPS 205) signature scheme.

    SLH-DSA support will be added once pyca/cryptography ships a stable
    FIPS 205 implementation.  Any call to this provider raises
    :class:`NotImplementedError`.
    """

    version: int = SLH_DSA

    _MSG = "SLH-DSA is reserved and is not enabled in ShieldBit"

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Not implemented — raises :class:`NotImplementedError`."""
        raise NotImplementedError(self._MSG)

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Not implemented — raises :class:`NotImplementedError`."""
        raise NotImplementedError(self._MSG)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Not implemented — raises :class:`NotImplementedError`."""
        raise NotImplementedError(self._MSG)


# ---------------------------------------------------------------------------
# KeyRegistry
# ---------------------------------------------------------------------------

@dataclass
class KeyRegistry:
    """Central registry that maps version bytes to :class:`SignatureProvider` instances.

    Providers are registered once at startup.  All signing and verification
    calls go through the registry so the rest of the codebase remains
    agnostic of the underlying cryptographic library.

    Example::

        priv, pub = registry.generate_keypair(ML_DSA_65)
        sig = registry.sign(priv, b"hello", ML_DSA_65)
        assert registry.verify(serialize_public_key(pub), b"hello", sig)
    """

    _providers: dict[int, SignatureProvider] = field(default_factory=dict)

    def register(self, provider: SignatureProvider) -> None:
        """Register *provider* for its declared version.

        Args:
            provider: A :class:`SignatureProvider`-compatible object.  Its
                ``version`` attribute must be one of the recognised version
                constants (:data:`ML_DSA_65` or :data:`SLH_DSA`).

        Raises:
            ValueError: If the version is not recognised.
        """
        if provider.version not in (ML_DSA_65, SLH_DSA):
            raise ValueError(
                f"Unsupported key version 0x{provider.version:02X}. "
                f"Accepted: 0x{ML_DSA_65:02X} (ML-DSA-65), 0x{SLH_DSA:02X} (SLH-DSA)"
            )
        self._providers[provider.version] = provider

    def provider(self, version: int) -> SignatureProvider:
        """Return the provider for *version*, raising if none is registered.

        Args:
            version: Key version byte.

        Returns:
            The registered :class:`SignatureProvider` for *version*.

        Raises:
            RuntimeError: If no provider is registered for *version*.
        """
        try:
            return self._providers[version]
        except KeyError:
            raise RuntimeError(
                f"No reviewed signature provider registered for version "
                f"0x{version:02X}. Register a FIPS 204/205 provider first."
            ) from None

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    def generate_keypair(self, version: int = ML_DSA_65) -> tuple[bytes, bytes]:
        """Generate a key pair using the provider for *version*.

        Returns:
            ``(raw_private_key_bytes, raw_public_key_bytes)`` — no prefixes.
        """
        return self.provider(version).generate_keypair()

    def sign(self, private_key: bytes, message: bytes, version: int = ML_DSA_65) -> bytes:
        """Sign *message* and return a version-prefixed wire signature.

        Args:
            private_key: Raw private key bytes.
            message:     Payload to sign.
            version:     Version byte identifying which scheme to use.

        Returns:
            ``version_byte || raw_signature_bytes`` as a single byte string.
        """
        raw_sig = self.provider(version).sign(private_key, message)
        return bytes([version]) + raw_sig

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a version-prefixed *signature* over *message*.

        Auto-detects the scheme from the first byte of *signature* and
        strips the version prefix before passing the raw signature to the
        provider.  The *public_key* must also be version-prefixed (first
        byte = version).

        Args:
            public_key: ``version_byte || raw_public_key_bytes``.
            message:    The signed payload.
            signature:  ``version_byte || raw_signature_bytes``.

        Returns:
            ``True`` if the signature is cryptographically valid.
        """
        if not signature or not public_key:
            return False
        sig_version = signature[0]
        if sig_version != ML_DSA_65 or public_key[0] != sig_version:
            return False
        if len(public_key) != 1953 or len(signature) != 3310:
            return False
        raw_pub = public_key[1:]
        raw_sig = signature[1:]
        return self.provider(sig_version).verify(raw_pub, message, raw_sig)


# ---------------------------------------------------------------------------
# Module-level singleton registry — auto-register ML-DSA-65
# ---------------------------------------------------------------------------

registry: KeyRegistry = KeyRegistry()

try:
    registry.register(MLDSAProvider())
except Exception:
    # The library is not installed; the provider will raise RuntimeError on use.
    pass

registry.register(SLHDSAProvider())


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def generate_keypair(version: int = ML_DSA_65) -> tuple[bytes, bytes]:
    """Generate a ShieldBit key pair for the given *version* scheme.

    Args:
        version: Key type version byte.  Defaults to :data:`ML_DSA_65`.

    Returns:
        ``(raw_private_key_bytes, raw_public_key_bytes)`` — no wire prefixes.
        Call :func:`serialize_public_key` to obtain the on-wire public key.
    """
    return registry.generate_keypair(version)


def sign(private_key: bytes, message: bytes, version: int = ML_DSA_65) -> bytes:
    """Sign *message* and return a version-prefixed wire signature.

    Args:
        private_key: Raw private key bytes from :func:`generate_keypair`.
        message:     Byte payload to sign.
        version:     Key scheme version byte.  Defaults to :data:`ML_DSA_65`.

    Returns:
        ``version_byte || raw_signature`` as a single byte string.
    """
    return registry.sign(private_key, message, version)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a wire *signature* over *message* using *public_key*.

    The scheme is auto-detected from the first byte of *signature*.

    Args:
        public_key: On-wire public key (``version_byte || raw_pub``).
        message:    The signed byte payload.
        signature:  Wire signature (``version_byte || raw_sig``).

    Returns:
        ``True`` if the signature is valid.
    """
    return registry.verify(public_key, message, signature)


def serialize_public_key(raw_public_key: bytes, version: int = ML_DSA_65) -> bytes:
    """Prepend the version byte to *raw_public_key* for on-wire serialisation.

    Args:
        raw_public_key: Raw public key bytes from :func:`generate_keypair`.
        version:        Key scheme version byte.  Defaults to :data:`ML_DSA_65`.

    Returns:
        ``version_byte || raw_public_key_bytes``.
    """
    if version != ML_DSA_65:
        raise ValueError("Only ML-DSA-65 public keys are currently enabled")
    if len(raw_public_key) != 1952:
        raise ValueError("ML-DSA-65 raw public key must be 1952 bytes")
    return bytes([version]) + raw_public_key


def public_key_from_seed(seed: bytes, version: int = ML_DSA_65) -> bytes:
    """Restore a versioned ML-DSA-65 public key from its 32-byte private seed."""
    if version != ML_DSA_65:
        raise ValueError("Only ML-DSA-65 seed restoration is currently enabled")
    mldsa = MLDSAProvider._load_backend()
    try:
        private_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
        return serialize_public_key(private_key.public_key().public_bytes_raw(), version)
    except UnsupportedAlgorithm as exc:
        raise RuntimeError("The installed backend does not support ML-DSA-65") from exc
