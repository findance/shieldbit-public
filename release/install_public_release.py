"""Install an official signed public package; never create wallets or start mining."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile

OFFICIAL_ARCHIVE_SHA256 = '1477b0ff77406f023bb40575974f5cd6cf6b059a666510be93c3baa0e4fb2a20'

COMMIT = 'c5cb5568c5499c0e22083f504953b9f7ca7b6134'
NETWORK = '3902ef29e80d97be35bdef5c86e71baeadb5ab9dee926040cd56d9c88d268509'
GENESIS = '0000094862883b548e8e5262f7b7fabd35188d25ddae0c82438cd031e8b3bdbd'
TRUST = '48060e8e6795732b8b6cdb9069c3328ddf9ec61b9dff911b844becca2a70eb45'
PINS = {
 'dist/shieldbit-0.1.0-py3-none-any.whl': '77bc85f1061b743e2e6c68a1af76ac462d30f2bbd6ec61bd3fc72c18a83b3a5a',
 'wheelhouse/cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl': 'c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf',
 'wheelhouse/click-8.5.0-py3-none-any.whl': '255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360',
 'wheelhouse/cryptography-50.0.2-cp311-abi3-manylinux_2_34_x86_64.whl': '9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079',
 'wheelhouse/pycparser-3.0-py3-none-any.whl': 'b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992',
 'wheelhouse/python_bitcoinlib-0.12.2-py3-none-any.whl': '2f29a9f475f21c12169b3a6cc8820f34f11362d7ff1200a5703dce3e4e903a44',
}
INVENTORY = set(PINS) | {'source.tar', 'candidate.json', 'offline-install-lock.txt',
                        'production-manifest.json', 'production-signature.json'}
HELPERS = {
 'release_signing.py': 'b743034e425a5ece2a43d99ed001cddb1004f6ebc751ea630719241e58747a95',
 'production_release_signing.py': '9a46b651ea582ce755c2c3fdfbdf07dfc7eb829885b68e275fe18842596b15d5',
 'artifact_authorization_smoke.py': '13bbfa720e719c73a8bf1d467637b543f76ef098df6ad948a1787d24c9eed391',
}


def unpack(archive, destination, names=None):
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if not members or len(members) > 200 or len({m.name for m in members}) != len(members):
            raise ValueError('Invalid bounded archive inventory')
        if names is not None and {m.name for m in members} != names:
            raise ValueError('Unexpected public release inventory')
        for member in members:
            path = Path(member.name)
            if (not member.isfile() or path.is_absolute() or '..' in path.parts or
                    member.size > 20 * 1024 ** 2 or not member.name.startswith('source/') and names is None):
                raise ValueError('Unsafe archive member')
        if sum(m.size for m in members) > 40 * 1024 ** 2:
            raise ValueError('Archive exceeds expansion limit')
        tar.extractall(destination, filter='data')


def verify_archive(archive, expected):
    # The user-supplied hash must agree with the reviewed installer, not just the archive.
    if expected != OFFICIAL_ARCHIVE_SHA256:
        raise ValueError('Hash is not the pinned official release')
    if archive.stat().st_size > 25 * 1024 ** 2 or hashlib.sha256(archive.read_bytes()).hexdigest() != OFFICIAL_ARCHIVE_SHA256:
        raise ValueError('Official archive checksum mismatch')


def install(archive, expected, directory):
    if os.geteuid() == 0:
        raise ValueError('Run as a regular user, not sudo/root')
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64') or sys.version_info[:2] != (3, 12):
        raise ValueError('Initial package requires Linux x86-64 with Python 3.12 (Ubuntu 24.04 / WSL2)')
    if directory.exists():
        raise ValueError('Use a new release directory; existing state is never overwritten')
    verify_archive(archive, expected)
    directory.mkdir(parents=True, mode=0o700)
    unpack(archive, directory, INVENTORY)
    for name, digest in PINS.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Pinned runtime/wheel mismatch')
    # Install only externally pinned wheels; ignore archive-supplied lock instructions.
    subprocess.run([sys.executable, '-m', 'venv', str(directory / 'venv')], check=True)
    python = str(directory / 'venv/bin/python')
    subprocess.run([python, '-m', 'pip', 'install', '--no-index', '--no-deps',
                    *[str(directory / name) for name in PINS]], check=True)
    subprocess.run([python, '-m', 'pip', 'check'], check=True)
    unpack(directory / 'source.tar', directory)
    for name, digest in HELPERS.items():
        if hashlib.sha256((directory / 'source/scripts' / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Pinned release verifier mismatch')
    subprocess.run([python, '-I', str(directory / 'source/scripts/production_release_signing.py'), 'verify',
       '--manifest', str(directory / 'production-manifest.json'), '--signature', str(directory / 'production-signature.json'),
       '--root', str(directory), '--source-commit', COMMIT, '--network-id', NETWORK,
       '--genesis-hash', GENESIS, '--trusted-key-sha3-256', TRUST], check=True)
    subprocess.run([python, '-I', str(directory / 'source/scripts/artifact_authorization_smoke.py'),
       '--candidate-manifest', str(directory / 'candidate.json'), '--report', str(directory / 'authorization.json')], check=True)
    print(json.dumps({'status': 'verified', 'python': python, 'source_commit': COMMIT,
                      'mainnet_launch_authorized': True,
                      'authorization_scope': 'separate founder approval of this pinned mainnet; software signature alone does not authorize activation',
                      'wallet_created': False, 'mining_started': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sha256', required=True, help='Official archive hash; never an arbitrary supplied hash')
    parser.add_argument('--directory', type=Path, default=Path.home() / '.shieldbit-release/c5cb556')
    args = parser.parse_args()
    try:
        install(args.archive.resolve(), args.sha256, args.directory.expanduser().resolve())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc))
