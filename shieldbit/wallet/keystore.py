# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Encrypted keystore for ShieldBit wallet keys.

Keys are stored in a JSON file, with private keys encrypted using
AES-256-GCM. The encryption key is derived from a password using
PBKDF2-HMAC-SHA256 (600,000 iterations).

Protection depends on password strength. Changing the KDF requires a separately
reviewed wallet-format migration and recovery compatibility design.

Author: Vipul Tomar
"""
from __future__ import annotations

import base64
import json
import os
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shieldbit.crypto.keys import public_key_from_seed
from shieldbit.crypto.address import pubkey_to_address, address_to_commitment


# ---------------------------------------------------------------------------
# Key derivation and encryption
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000
PBKDF2_KEYLEN = 32       # AES-256 needs 32-byte key
SALT_SIZE = 32
NONCE_SIZE = 12


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: User-supplied password string.
        salt: Random 32-byte salt.

    Returns:
        32-byte derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEYLEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt bytes using AES-256-GCM.

    Args:
        plaintext: Data to encrypt.
        key: 32-byte AES key.

    Returns:
        nonce(12) + ciphertext+tag bytes.
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_bytes(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext.

    Args:
        ciphertext: nonce(12) + ciphertext+tag as produced by encrypt_bytes().
        key: 32-byte AES key.

    Returns:
        Decrypted plaintext.

    Raises:
        ValueError: If decryption fails (wrong key or tampered data).
    """
    if len(ciphertext) < NONCE_SIZE:
        raise ValueError('ciphertext too short')
    nonce = ciphertext[:NONCE_SIZE]
    ct = ciphertext[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as exc:
        raise ValueError('decryption failed — wrong password or corrupted key file') from exc


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class KeyEntry:
    """A single encrypted key entry in the keystore.

    Attributes:
        address: Bech32m sb1... address string.
        address_hash_hex: Hex-encoded 32-byte versioned address commitment.
        public_key_hex: Hex-encoded versioned public key bytes.
        encrypted_private_key_b64: Base64-encoded AES-GCM ciphertext of the private key.
        key_version: Key version (1=ML-DSA-65, 2=SLH-DSA).
        created_at: Unix timestamp of key creation.
    """
    address: str
    address_hash_hex: str
    public_key_hex: str
    encrypted_private_key_b64: str
    key_version: int
    created_at: int
    address_commitment_version: int = 2
    network_id_hex: str = ''


# ---------------------------------------------------------------------------
# KeyStore
# ---------------------------------------------------------------------------

class KeyStore:
    """AES-GCM encrypted keystore backed by a JSON file.

    Args:
        path: Path to the JSON keystore file (created if it doesn't exist).
        password: Password used to derive the encryption key.
    """

    SALT_FILE_SUFFIX = '.salt'

    def __init__(self, path: str | Path, password: str) -> None:
        self.path = Path(path)
        from shieldbit.network_profile import ACTIVE
        self.network_id = ACTIVE.get().network_id
        self._salt_path = self.path.with_suffix('.salt')
        self._lock_path = self.path.with_name(self.path.name + '.lock')
        self._entries: dict[str, KeyEntry] = {}
        with self._locked():
            self._salt = self._load_or_create_salt()
            self._key = derive_key(password, self._salt)
            self._load()
        for address in self._entries:
            entry = self._entries[address]
            if (entry.address_commitment_version != 2 or
                    entry.network_id_hex != self.network_id.hex() or
                    len(bytes.fromhex(entry.address_hash_hex)) != 32):
                raise ValueError('legacy or wrong-network wallet metadata; use explicit migration, not overwrite')
            public = public_key_from_seed(self.get_private_key(address), entry.key_version)
            if (public.hex() != entry.public_key_hex or
                    pubkey_to_address(public, entry.key_version) != address or
                    entry.address != address or
                    address_to_commitment(address).hex() != entry.address_hash_hex):
                raise ValueError('wallet key metadata does not match the encrypted seed')

    @contextmanager
    def _locked(self):
        # A stable sidecar inode protects the check-and-replace across processes.
        try:
            import fcntl
        except ImportError as exc:
            raise RuntimeError('Wallet locking currently requires a Unix platform') from exc
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError('wallet is busy; retry after the other writer finishes') from exc
            yield
        finally:
            os.close(fd)

    def _load_or_create_salt(self) -> bytes:
        if self._salt_path.exists():
            salt = self._salt_path.read_bytes()
            if len(salt) != SALT_SIZE:
                raise ValueError('invalid wallet salt')
            return salt
        if self.path.exists():
            raise ValueError('wallet salt is missing; restore the original salt file')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(SALT_SIZE)
        fd = os.open(self._salt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(salt)
            stream.flush()
            os.fsync(stream.fileno())
        self._sync_directory()
        return salt

    def _sync_directory(self) -> None:
        # File fsync alone does not make a new salt or wallet rename durable.
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _load(self) -> None:
        self._loaded_payload = None
        if not self.path.exists():
            return
        try:
            self._loaded_payload = self.path.read_bytes()
            data = json.loads(self._loaded_payload)
            for addr, entry_dict in data.items():
                self._entries[addr] = KeyEntry(**entry_dict)
        except (json.JSONDecodeError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError('corrupted wallet file; refusing to overwrite existing keys') from exc

    def _save(self) -> None:
        with self._locked():
            current = self.path.read_bytes() if self.path.exists() else None
            if current != self._loaded_payload or self._salt_path.read_bytes() != self._salt:
                raise ValueError('wallet changed on disk; reload before adding keys')
            self._save_locked()
            self._loaded_payload = self.path.read_bytes()

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {addr: asdict(entry) for addr, entry in self._entries.items()}
        import tempfile
        fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix='.wallet-')
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(data, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self._sync_directory()
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def add_key(
        self,
        private_key: bytes,
        public_key: bytes,
        version: int,
        address: str,
        address_hash: bytes,
    ) -> None:
        """Store a new key in the keystore.

        Args:
            private_key: Raw private key bytes (will be encrypted).
            public_key: Versioned public key bytes.
            version: Key version.
            address: Bech32m address string.
            address_hash: 32-byte address commitment.
        """
        if (public_key_from_seed(private_key, version) != public_key or
                pubkey_to_address(public_key, version) != address or
                address_to_commitment(address) != address_hash):
            raise ValueError('imported key metadata does not match the private seed')
        encrypted = encrypt_bytes(private_key, self._key)
        entry = KeyEntry(
            address=address,
            address_hash_hex=address_hash.hex(),
            public_key_hex=public_key.hex(),
            encrypted_private_key_b64=base64.b64encode(encrypted).decode(),
            key_version=version,
            created_at=int(time.time()),
            address_commitment_version=2,
            network_id_hex=self.network_id.hex(),
        )
        previous = self._entries.get(address)
        self._entries[address] = entry
        try:
            self._save()
        except BaseException:
            if previous is None:
                self._entries.pop(address, None)
            else:
                self._entries[address] = previous
            raise

    def get_private_key(self, address: str) -> bytes:
        """Retrieve and decrypt a private key by address.

        Args:
            address: The sb1... address.

        Returns:
            Decrypted private key bytes.

        Raises:
            KeyError: If address not found.
            ValueError: If decryption fails.
        """
        entry = self._entries[address]
        try:
            ciphertext = base64.b64decode(entry.encrypted_private_key_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError('corrupted encrypted key encoding') from exc
        return decrypt_bytes(ciphertext, self._key)

    def get_public_key(self, address: str) -> bytes:
        """Return the public key for a given address.

        Args:
            address: The sb1... address.

        Returns:
            Versioned public key bytes.

        Raises:
            KeyError: If address not found.
        """
        return bytes.fromhex(self._entries[address].public_key_hex)

    def get_address_hash(self, address: str) -> bytes:
        """Return the stored 32-byte address commitment."""
        return bytes.fromhex(self._entries[address].address_hash_hex)

    def list_addresses(self) -> list[str]:
        """Return all stored addresses."""
        return list(self._entries.keys())

    def list_keys(self) -> list[KeyEntry]:
        """Return all KeyEntry records (without decrypted private keys)."""
        return list(self._entries.values())

    def has_address(self, address: str) -> bool:
        return address in self._entries

    def __len__(self) -> int:
        return len(self._entries)
