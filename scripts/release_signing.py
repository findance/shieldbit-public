"""ML-DSA review-artifact signing; never authorize genesis or mainnet.

Production key custody must be approved separately. Rehearsal mode keeps its
private seed only in memory and is not an approved production trust anchor.
"""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shieldbit.crypto.hashing import tagged_hash
from shieldbit.crypto.keys import generate_keypair, serialize_public_key, sign, verify, public_key_from_seed
from shieldbit.wallet.keystore import derive_key

MAX_JSON = 1024 * 1024
DOMAIN = 'ShieldBit/ReleaseManifest/v1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def read_json(path):
    with Path(path).open('rb') as source:
        data = source.read(MAX_JSON + 1)
    if len(data) > MAX_JSON:
        raise ValueError('release JSON exceeds size limit')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate release JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(canonical(value) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def hex_bytes(value, length):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{' + str(length * 2) + '}', value):
        raise ValueError('invalid release encoding')
    return bytes.fromhex(value)


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_file(root, name):
    root = Path(root).resolve()
    if not isinstance(name, str) or '\\' in name:
        raise ValueError('invalid artifact path')
    relative = PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts or str(relative) != name or not relative.parts:
        raise ValueError('invalid artifact path')
    path = root.joinpath(*relative.parts)
    if not path.resolve().is_relative_to(root) or not path.is_file():
        raise ValueError('artifact is missing or escapes release root')
    if any(parent.is_symlink() for parent in (path, *path.parents) if parent != root and root in parent.parents):
        raise ValueError('artifact symlinks are not allowed')
    return path


def manifest_network(manifest):
    if not isinstance(manifest, dict) or manifest.get('kind') != 'shieldbit-review-release/v1':
        raise ValueError('unsupported release manifest')
    if (manifest.get('mainnet_launch_authorized') is not False or
            manifest.get('production_spec_approved') is not False):
        raise ValueError('review signing cannot authorize production')
    commit = manifest.get('source_commit')
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('exact source commit is required')
    network = hex_bytes(manifest.get('network_id'), 32)
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= 100:
        raise ValueError('bounded artifact inventory is required')
    for name, expected in artifacts.items():
        if not isinstance(name, str):
            raise ValueError('invalid artifact name')
        hex_bytes(expected, 32)
    return network


def validate_manifest(manifest, root):
    network = manifest_network(manifest)
    for name, expected in manifest['artifacts'].items():
        if digest_file(artifact_file(root, name)) != expected:
            raise ValueError('artifact SHA-256 mismatch')
    return network


def release_message(manifest, key_scope):
    return tagged_hash(DOMAIN, manifest_network(manifest) +
                       canonical({'key_scope': key_scope, 'manifest': manifest}))


def fingerprint(public):
    return hashlib.sha3_256(public).hexdigest()


def make_envelope(manifest, root, seed, key_scope):
    if key_scope not in ('rehearsal', 'custodian-review'):
        raise ValueError('unsupported release key scope')
    validate_manifest(manifest, root)
    message = release_message(manifest, key_scope)
    public = public_key_from_seed(seed)
    return {'kind': 'shieldbit-release-signature/v1', 'algorithm': 'ML-DSA-65',
            'purpose': DOMAIN, 'key_scope': key_scope, 'production_trust_anchor_approved': False,
            'public_key': public.hex(), 'public_key_sha3_256': fingerprint(public),
            'manifest_sha256': hashlib.sha256(canonical(manifest)).hexdigest(),
            'signature': sign(seed, message).hex()}


def verify_release(manifest, envelope, root, trusted_fingerprint, expected_network_id, expected_source_commit):
    # Never accept the bundled key/fingerprint as its own evidence of trust.
    hex_bytes(trusted_fingerprint, 32)
    hex_bytes(expected_network_id, 32)
    manifest_network(manifest)
    if manifest.get('network_id') != expected_network_id:
        raise ValueError('release signing network mismatch')
    if manifest.get('source_commit') != expected_source_commit:
        raise ValueError('release source does not match the independently pinned commit')
    if (not isinstance(envelope, dict) or envelope.get('kind') != 'shieldbit-release-signature/v1' or
            envelope.get('algorithm') != 'ML-DSA-65' or envelope.get('purpose') != DOMAIN or
            envelope.get('key_scope') not in ('rehearsal', 'custodian-review') or
            envelope.get('production_trust_anchor_approved') is not False):
        raise ValueError('unsupported release signature envelope')
    public = hex_bytes(envelope.get('public_key'), 1953)
    signature = hex_bytes(envelope.get('signature'), 3310)
    actual = fingerprint(public)
    if actual != trusted_fingerprint or actual != envelope.get('public_key_sha3_256'):
        raise ValueError('release key does not match the independently pinned trust anchor')
    if hashlib.sha256(canonical(manifest)).hexdigest() != envelope.get('manifest_sha256'):
        raise ValueError('signed manifest digest mismatch')
    # Authenticate before hashing potentially large, attacker-supplied artifacts.
    if not verify(public, release_message(manifest, envelope['key_scope']), signature):
        raise ValueError('invalid ML-DSA release signature')
    validate_manifest(manifest, root)
    return {'signature_valid': True, 'artifact_integrity_valid': True,
            'key_scope': envelope['key_scope'], 'production_trust_anchor_approved': False,
            'mainnet_launch_authorized': False}


def make_key(path, password, network_id):
    path = Path(path).absolute()
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError('release key paths must not be symlinks')
    path = path.resolve()
    repository = Path(__file__).resolve().parents[1]
    if path.is_relative_to(repository) and not path.is_relative_to(repository / '.local-release'):
        raise ValueError('release keys inside the repository must be in ignored .local-release')
    if not isinstance(password, str) or len(password) < 20:
        raise ValueError('use a strong passphrase of at least 20 characters')
    hex_bytes(network_id, 32)
    seed, raw = generate_keypair()
    public = serialize_public_key(raw)
    metadata = {'kind': 'shieldbit-encrypted-release-key/v1', 'algorithm': 'ML-DSA-65',
                'role': 'release-signing-only', 'network_id': network_id, 'public_key': public.hex()}
    salt, nonce = os.urandom(32), os.urandom(12)
    sealed = AESGCM(derive_key(password, salt)).encrypt(nonce, seed, canonical(metadata))
    write_new(path, {**metadata, 'salt': salt.hex(), 'nonce': nonce.hex(), 'ciphertext': sealed.hex()})
    return fingerprint(public)


def load_key(path, password, network_id):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise ValueError('release key must be an owner-only regular file')
    record = read_json(path)
    if not isinstance(record, dict):
        raise ValueError('invalid encrypted release key')
    names = ('kind', 'algorithm', 'role', 'network_id', 'public_key')
    metadata = {name: record.get(name) for name in names}
    if (metadata['kind'] != 'shieldbit-encrypted-release-key/v1' or
            metadata['algorithm'] != 'ML-DSA-65' or metadata['role'] != 'release-signing-only' or
            metadata['network_id'] != network_id):
        raise ValueError('release key role or network mismatch')
    public = hex_bytes(record.get('public_key'), 1953)
    salt, nonce = hex_bytes(record.get('salt'), 32), hex_bytes(record.get('nonce'), 12)
    try:
        seed = AESGCM(derive_key(password, salt)).decrypt(
            nonce, hex_bytes(record.get('ciphertext'), 48), canonical(metadata))
    except Exception as exc:
        raise ValueError('release key authentication failed') from exc
    if len(seed) != 32 or public_key_from_seed(seed) != public:
        raise ValueError('release seed/public-key mismatch')
    return seed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    keygen = commands.add_parser('keygen')
    keygen.add_argument('--key-file', type=Path, required=True)
    keygen.add_argument('--network-id', required=True)
    signing = commands.add_parser('sign')
    signing.add_argument('--key-file', type=Path, required=True)
    signing.add_argument('--manifest', type=Path, required=True)
    signing.add_argument('--root', type=Path, required=True)
    signing.add_argument('--output', type=Path, required=True)
    rehearsal = commands.add_parser('rehearsal-sign')
    rehearsal.add_argument('--manifest', type=Path, required=True)
    rehearsal.add_argument('--root', type=Path, required=True)
    rehearsal.add_argument('--output', type=Path, required=True)
    checking = commands.add_parser('verify')
    checking.add_argument('--manifest', type=Path, required=True)
    checking.add_argument('--signature', type=Path, required=True)
    checking.add_argument('--root', type=Path, required=True)
    checking.add_argument('--trusted-key-sha3-256', required=True)
    checking.add_argument('--network-id', required=True)
    checking.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    if args.command in ('keygen', 'sign') and not sys.stdin.isatty():
        parser.error('enter the passphrase privately in an interactive terminal, not a pipe or argument')
    if args.command == 'keygen':
        password = getpass.getpass('Release-key passphrase (never a wallet password): ')
        if password != getpass.getpass('Confirm release-key passphrase: '):
            parser.error('passphrases differ')
        print(json.dumps({'public_key_sha3_256': make_key(args.key_file, password, args.network_id),
                          'production_trust_anchor_approved': False}))
    elif args.command in ('sign', 'rehearsal-sign'):
        manifest = read_json(args.manifest)
        if args.command == 'sign':
            seed = load_key(args.key_file, getpass.getpass('Release-key passphrase: '), manifest['network_id'])
            scope = 'custodian-review'
        else:
            seed, _ = generate_keypair()
            scope = 'rehearsal'
        envelope = make_envelope(manifest, args.root, seed, scope)
        write_new(args.output, envelope)
        print(json.dumps({'public_key_sha3_256': envelope['public_key_sha3_256'],
                          'key_scope': scope, 'mainnet_launch_authorized': False}))
    else:
        print(json.dumps(verify_release(read_json(args.manifest), read_json(args.signature), args.root,
                                       args.trusted_key_sha3_256, args.network_id, args.source_commit)))
