# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
ShieldBit command-line interface.

Quantum-safe cryptocurrency by Vipul Tomar.
Full node, ordinary payments, wallet recovery, and mining.

Author: Vipul Tomar
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path

import click
from shieldbit.mempool.fees import DEFAULT_RELAY_QUANTA_PER_KB, DEFAULT_INCREMENTAL_QUANTA_PER_KB

# Config directory: ~/.shieldbit/
CONFIG_DIR = Path.home() / '.shieldbit'
WALLET_FILE = CONFIG_DIR / 'wallet.json'
DB_FILE = CONFIG_DIR / 'shieldbit.db'
CONFIG_FILE = CONFIG_DIR / 'config.json'

QUANTA_PER_SBT = 100_000_000


def _quanta_to_sbt(q: int) -> str:
    return f'{q / QUANTA_PER_SBT:.8f} SBT'


def _sbt_to_quanta(amount: float) -> int:
    return int(round(amount * QUANTA_PER_SBT))


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def _get_password(prompt: str = 'Wallet password') -> str:
    return click.prompt(prompt, hide_input=True)


def _load_blockchain():
    from shieldbit.storage.database import ChainDatabase
    from shieldbit.core.blockchain import Blockchain
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    db = ChainDatabase(DB_FILE)
    try:
        return Blockchain(db)
    except ValueError as exc:
        db.connection.close()
        raise click.ClickException(str(exc)) from exc


def _load_wallet(blockchain=None):
    from shieldbit.wallet.keystore import KeyStore
    password = _get_password()
    if blockchain is None:
        blockchain = _load_blockchain()
    return KeyStore(WALLET_FILE, password), blockchain


# ===========================================================================
# CLI group
# ===========================================================================

@click.group()
@click.option('--network', type=click.Choice(['main', 'private-testnet']), default='main')
@click.option('--data-dir', type=click.Path(path_type=Path, file_okay=False), default=None)
@click.pass_context
def cli(ctx, network, data_dir):
    """ShieldBit — quantum-safe cryptocurrency by Vipul Tomar."""
    from shieldbit.network_profile import ACTIVE, PROFILES, bind_data_directory
    global CONFIG_DIR, WALLET_FILE, DB_FILE, CONFIG_FILE
    previous = (CONFIG_DIR, WALLET_FILE, DB_FILE, CONFIG_FILE)
    token = ACTIVE.set(PROFILES[network])

    def restore():
        global CONFIG_DIR, WALLET_FILE, DB_FILE, CONFIG_FILE
        CONFIG_DIR, WALLET_FILE, DB_FILE, CONFIG_FILE = previous
        ACTIVE.reset(token)

    ctx.call_on_close(restore)
    if data_dir is None and network == 'private-testnet':
        data_dir = Path.home() / '.shieldbit-private-testnet'
    if data_dir is not None:
        CONFIG_DIR = data_dir.expanduser().absolute()
        WALLET_FILE = CONFIG_DIR / 'wallet.json'
        DB_FILE = CONFIG_DIR / 'shieldbit.db'
        CONFIG_FILE = CONFIG_DIR / 'config.json'
    if data_dir is not None or (CONFIG_DIR / 'network.json').exists():
        try:
            bind_data_directory(CONFIG_DIR, PROFILES[network])
        except (OSError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc


# ===========================================================================
# Node commands
# ===========================================================================

@contextmanager
def _node_data_lock():
    """Keep node startup and offline chain maintenance mutually exclusive."""
    import fcntl
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(DB_FILE) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise click.ClickException('Stop the node before accessing chain maintenance.') from exc
        yield
    finally:
        os.close(descriptor)

@cli.group()
def node():
    """Node management commands."""
    pass


def _recover_node_socket(path):
    """Called only while holding the exclusive node data-directory lock."""
    import errno
    import socket
    import stat
    path = Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return
    parent = path.parent.stat()
    if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid()
            or parent.st_uid != os.getuid() or parent.st_mode & 0o022):
        raise click.ClickException('Refusing to replace unsafe node socket path.')
    with socket.socket(socket.AF_UNIX) as probe:
        probe.settimeout(1)
        result = probe.connect_ex(str(path))
    if result != errno.ECONNREFUSED:
        raise click.ClickException('Node socket is active or cannot be safely recovered.')
    after = path.lstat()
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
        raise click.ClickException('Node socket changed during recovery.')
    path.unlink()


@node.command('genesis-candidate')
@click.option('--address', required=True, help='Private-testnet payout address')
def genesis_candidate(address):
    """Mine a private-only genesis candidate locally; print it without activating it."""
    from shieldbit.network_profile import ACTIVE, MAIN
    from shieldbit.core.block import Block
    from shieldbit.crypto.address import address_to_commitment
    if ACTIVE.get() == MAIN:
        raise click.ClickException('Genesis candidate generation requires private-testnet.')
    try:
        block = Block.create_genesis(address_to_commitment(
            address, expected_version=1, expected_commitment_version=2))
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps({'network': ACTIVE.get().name,
                          'signing_network_id': ACTIVE.get().network_id.hex(),
                          'signing_format_version': 2, 'address_commitment_version': 2,
                          'genesis_hash': block.header.hash.hex(),
                          'block': block.serialize().hex(),
                          'status': 'candidate; founder approval required'}, indent=2))


@node.command('submit-block')
@click.option('--file', 'block_file', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--node-socket', type=click.Path(), default=None)
def submit_block_file(block_file, node_socket):
    """Submit a bounded serialized block to the owner-only local node socket."""
    from shieldbit.consensus.params import MAX_BLOCK_SIZE
    from shieldbit.core.block import Block
    from shieldbit.network.local_rpc import request
    try:
        with open(block_file, 'rb') as source:
            payload = source.read(MAX_BLOCK_SIZE + 1)
        if len(payload) > MAX_BLOCK_SIZE:
            raise ValueError('block exceeds maximum block size')
        Block.from_bytes(payload)
        result = asyncio.run(request(node_socket or CONFIG_DIR / 'node.sock', 'submit_block',
                                     block=payload.hex()))
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, indent=2))


@node.command('status')
@click.option('--node-socket', type=click.Path(), default=None)
def node_status(node_socket):
    """Read running-node status without opening its database."""
    from shieldbit.network.local_rpc import request
    try:
        result = asyncio.run(request(node_socket or CONFIG_DIR / 'node.sock', 'status'))
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, indent=2))


@node.command('start')
@click.option('--prune', default=None, type=click.IntRange(min=0),
              help='Retain N recent bodies/undo (minimum 288; 0 = archive; omitted = saved setting)')
@click.option('--port', default=None, type=click.IntRange(1, 65535), help='Listen port (network default)')
@click.option('--bind', 'bind_host', default=None, help='Listen IP (private-testnet defaults to loopback)')
@click.option('--peer', multiple=True, help='Connect to peer (host:port)')
@click.option('--node-socket', type=click.Path(), default=None)
@click.option('--genesis-hash', default=None, help='Approved 32-byte genesis commitment in hex')
@click.option('--relay-fee-rate', default=DEFAULT_RELAY_QUANTA_PER_KB, type=click.IntRange(min=1),
              help='Relay quanta per 1,000 signed bytes (local policy only)')
@click.option('--incremental-fee-rate', default=DEFAULT_INCREMENTAL_QUANTA_PER_KB, type=click.IntRange(min=1),
              help='Replacement bandwidth quanta per 1,000 bytes')
def node_start(prune: int, port: int, peer: tuple, node_socket: str | None, genesis_hash: str | None,
               bind_host: str | None = None, relay_fee_rate: int = DEFAULT_RELAY_QUANTA_PER_KB,
               incremental_fee_rate: int = DEFAULT_INCREMENTAL_QUANTA_PER_KB):
    """Start the ShieldBit full node."""
    with _node_data_lock():
        _start_node(prune, port, peer, node_socket, genesis_hash, bind_host,
                    relay_fee_rate, incremental_fee_rate)


def _start_node(prune, port, peer, node_socket, genesis_hash, bind_host=None,
                relay_fee_rate=DEFAULT_RELAY_QUANTA_PER_KB,
                incremental_fee_rate=DEFAULT_INCREMENTAL_QUANTA_PER_KB):
    from shieldbit.core.blockchain import Blockchain
    from shieldbit.mempool.mempool import Mempool
    from shieldbit.network.node import Node
    from shieldbit.network.discovery import PeerDiscovery
    from shieldbit.storage.database import ChainDatabase
    from shieldbit.network_profile import ACTIVE, MAIN
    from ipaddress import ip_address
    from shieldbit.consensus.genesis import startup_commitment, mainnet_genesis

    profile = ACTIVE.get()
    try:
        commitment = startup_commitment(profile, bytes.fromhex(genesis_hash) if genesis_hash is not None else None)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    port = profile.port if port is None else port
    bind_host = bind_host or ('127.0.0.1' if profile != MAIN else '0.0.0.0')
    allowed = None
    if profile != MAIN:
        try:
            ip_address(bind_host)
            addresses = []
            for endpoint in peer:
                host, peer_port = endpoint.rsplit(':', 1)
                host = str(ip_address(host.strip('[]')))
                peer_port = int(peer_port)
                if not 1 <= peer_port <= 65535:
                    raise ValueError('peer port out of range')
                addresses.append((host, peer_port))
            if not addresses:
                raise ValueError('private-testnet requires at least one explicit IP peer')
            allowed = frozenset(addresses)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    click.echo(f'Starting ShieldBit node on port {port}...')
    db = ChainDatabase(DB_FILE)
    try:
        blockchain = Blockchain(db, genesis_hash=commitment, prune_depth=prune)
        if profile == MAIN and blockchain.height < 0:
            blockchain.add_block(mainnet_genesis())
    except ValueError as exc:
        db.connection.close()
        raise click.ClickException(str(exc)) from exc
    mempool = Mempool(relay_rate=relay_fee_rate, incremental_rate=incremental_fee_rate)
    socket_path = node_socket or str(CONFIG_DIR / 'node.sock')
    try:
        _recover_node_socket(socket_path)
    except BaseException:
        db.connection.close()
        raise
    node_instance = Node(blockchain, mempool, port=port,
                         host=bind_host, allowed_peers=allowed,
                         rpc_socket=socket_path)

    async def _run():
        discovery = PeerDiscovery(node_instance)
        # Connect to manually specified peers
        for p in (peer if allowed is None else [f'{h}:{p}' for h, p in sorted(allowed)]):
            try:
                host, pport = p.rsplit(':', 1)
                await node_instance.connect_to_peer(host, int(pport))
            except (ValueError, OSError) as e:
                click.echo(f'Could not connect to {p}: {e}', err=True)
        if not peer and profile == MAIN:
            await discovery.bootstrap()
        click.echo(f'Node running. Height: {blockchain.height}, Peers: {node_instance.peer_count()}')
        if blockchain.prune_depth:
            click.echo(f'Pruning mode: keeping last {blockchain.prune_depth} bodies and undo; all headers retained')
        maintenance = asyncio.create_task(discovery.maintain_connections())
        import signal
        loop = asyncio.get_running_loop()
        runner = asyncio.current_task()
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(signum, runner.cancel)
        try:
            await node_instance.start()
        finally:
            for signum in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(signum)
            maintenance.cancel()
            await asyncio.gather(maintenance, return_exceptions=True)
            db.connection.close()

    try:
        asyncio.run(_run())
    except (KeyboardInterrupt, asyncio.CancelledError):
        click.echo('\nNode stopped.')


@node.command('recover-history')
@click.option('--archive-dir', required=True, type=click.Path(exists=True, file_okay=False))
@click.option('--from-height', default=0, type=click.IntRange(min=0))
def recover_history(archive_dir, from_height):
    """Offline: replay a canonical archive and restore discarded bodies and undo."""
    from shieldbit.storage.database import ChainDatabase
    from shieldbit.core.blockchain import Blockchain
    with _node_data_lock():
        db = ChainDatabase(DB_FILE)
        try:
            restored = Blockchain(db).recover_history(archive_dir, from_height)
            click.echo(f'Restored {restored} validated block bodies and undo records.')
        except (ValueError, OSError) as exc:
            raise click.ClickException(str(exc)) from exc
        finally:
            db.connection.close()


@node.command('export-history')
@click.option('--archive-dir', required=True, type=click.Path(file_okay=False))
def export_history(archive_dir):
    """Offline: export canonical blocks for verified pruning recovery."""
    from shieldbit.storage.database import ChainDatabase
    from shieldbit.core.block import BlockHeader
    with _node_data_lock():
        db = ChainDatabase(DB_FILE)
        try:
            directory = Path(archive_dir)
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            for height in range(db.height() + 1):
                raw = db.get_block_by_height(height)
                if raw is None:
                    raise ValueError(f'body unavailable at height {height}; use an archival node')
                path = directory / (BlockHeader.from_bytes(raw).hash.hex() + '.sbb')
                with path.open('xb') as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
            click.echo(f'Exported {db.height() + 1} canonical blocks.')
        except (ValueError, OSError) as exc:
            raise click.ClickException(str(exc)) from exc
        finally:
            db.connection.close()


@node.command('compact')
def compact_database():
    """Offline: reclaim SQLite file space after pruning (requires temporary disk space)."""
    from shieldbit.storage.database import ChainDatabase
    with _node_data_lock():
        db = ChainDatabase(DB_FILE)
        try:
            db.reclaim_space()
            click.echo('Chain database compacted.')
        except (ValueError, OSError) as exc:
            raise click.ClickException(str(exc)) from exc
        finally:
            db.connection.close()


@cli.command('aux-template')
@click.argument('address')
@click.option('--node-socket', type=click.Path(), default=None)
def aux_template(address, node_socket):
    """Get a Bitcoin-format work commitment for independent or merge mining."""
    from shieldbit.crypto.address import address_to_commitment
    from shieldbit.network.local_rpc import request
    try:
        response = asyncio.run(request(node_socket or CONFIG_DIR / 'node.sock', 'aux_block_template',
                                       recipient=address_to_commitment(
                                           address, expected_version=1, expected_commitment_version=2).hex()))
        click.echo(json.dumps(response['template'], indent=2))
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command('submit-aux')
@click.option('--template-file', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--proof-file', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--node-socket', type=click.Path(), default=None)
def submit_aux(template_file, proof_file, node_socket):
    """Submit an external miner's bounded binary auxiliary proof and child template."""
    from shieldbit.consensus.params import MAX_AUXPOW_SIZE
    from shieldbit.network.local_rpc import request, MAX_REQUEST
    try:
        with open(template_file, 'rb') as handle:
            encoded = handle.read(MAX_REQUEST + 1)
        with open(proof_file, 'rb') as handle:
            proof = handle.read(MAX_AUXPOW_SIZE + 1)
        if len(encoded) > MAX_REQUEST or len(proof) > MAX_AUXPOW_SIZE:
            raise ValueError('mining submission file exceeds size limit')
        response = asyncio.run(request(node_socket or CONFIG_DIR / 'node.sock', 'submit_aux_block',
                                       template=json.loads(encoded), proof=proof.hex()))
        click.echo(f"Accepted block: {response['hash']}; canonical: {response['canonical']}")
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command('mine-aux')
@click.argument('address')
@click.option('--max-nonce', default=100_000, type=click.IntRange(min=0, max=2**32 - 1))
@click.option('--node-socket', type=click.Path(), default=None)
def mine_aux(address, max_nonce, node_socket):
    """Reference independent Bitcoin-format mining (CPU; no Bitcoin node needed)."""
    from shieldbit.consensus.auxpow import complete_template, mine_auxiliary
    from shieldbit.crypto.address import address_to_commitment
    from shieldbit.network.local_rpc import request
    async def run():
        socket_path = node_socket or CONFIG_DIR / 'node.sock'
        response = await request(socket_path, 'aux_block_template', recipient=address_to_commitment(
            address, expected_version=1, expected_commitment_version=2).hex())
        template = response['template']
        child = complete_template(template, None)
        solved = mine_auxiliary(child, max_nonce)
        if solved is None:
            raise ValueError('nonce search exhausted; request a new template')
        return await request(socket_path, 'submit_aux_block', template=template,
                             proof=solved.auxpow.serialize().hex())
    try:
        response = asyncio.run(run())
        click.echo(f"Accepted independently mined block: {response['hash']}")
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


@node.command('info')
def node_info():
    """Show current node status."""
    from shieldbit.consensus.params import MAX_SUPPLY, MIN_FEE, QUANTA_PER_SBT as QPC
    from shieldbit.network_profile import ACTIVE
    blockchain = _load_blockchain()
    info = {
        'height': blockchain.height,
        'tip': blockchain.tip.hex(),
        'max_supply_SBT': MAX_SUPPLY / QPC,
        'min_fee_quanta': MIN_FEE,
        'network_port': ACTIVE.get().port,
    }
    click.echo(json.dumps(info, indent=2))


# ===========================================================================
# Wallet commands
# ===========================================================================

@cli.group()
def wallet():
    """Wallet management commands."""
    pass


@wallet.command('create')
@click.option('--recovery-n', default=0, help='Shamir: total recovery shares (0=skip)')
@click.option('--recovery-k', default=0, help='Shamir: shares required to recover')
def wallet_create(recovery_n: int, recovery_k: int):
    """Generate a new wallet address."""
    from shieldbit.crypto.keys import generate_keypair, serialize_public_key
    from shieldbit.crypto.address import pubkey_to_address, address_to_commitment
    from shieldbit.wallet.keystore import KeyStore

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    password = _get_password('New wallet password')
    confirm = _get_password('Confirm password')
    if password != confirm:
        click.echo('Passwords do not match.', err=True)
        sys.exit(1)

    try:
        privkey, raw_pubkey = generate_keypair(1)
        pubkey = serialize_public_key(raw_pubkey, 1)
    except RuntimeError as e:
        click.echo(f'Key generation failed: {e}', err=True)
        click.echo('Make sure cryptography>=50.0.2 is installed and ML-DSA-65 is available.')
        sys.exit(1)

    address = pubkey_to_address(pubkey, 1)
    addr_hash = address_to_commitment(address)

    ks = KeyStore(WALLET_FILE, password)
    ks.add_key(privkey, pubkey, 1, address, addr_hash)
    click.echo(f'✓ New address: {address}')

    if recovery_n >= 2 and recovery_k >= 2 and recovery_k <= recovery_n:
        from shieldbit.crypto.shamir import split_secret
        shares = split_secret(privkey, recovery_n, recovery_k)
        click.echo(f'\nShamir recovery shares ({recovery_k}-of-{recovery_n}):')
        click.echo('KEEP THESE SAFE — any combination of '
                   f'{recovery_k} shares can reconstruct your private key.\n')
        for idx, share_bytes in shares:
            click.echo(f'  Share {idx}: {share_bytes.hex()}')
    elif recovery_n > 0:
        click.echo('⚠ Invalid recovery parameters (need n>=2, k>=2, k<=n). Skipping.')


@wallet.command('balance')
def wallet_balance():
    """Show wallet balance."""
    ks, blockchain = _load_wallet()
    total = 0
    for addr in ks.list_addresses():
        try:
            addr_hash = ks.get_address_hash(addr)
            bal = blockchain.get_balance(addr_hash)
            total += bal
            click.echo(f'  {addr}: {_quanta_to_sbt(bal)}')
        except Exception:
            pass
    click.echo(f'\nTotal: {_quanta_to_sbt(total)}')


@wallet.command('address')
def wallet_address():
    """List receiving addresses."""
    ks, _ = _load_wallet()
    addrs = ks.list_addresses()
    if not addrs:
        click.echo('No addresses yet. Run: shieldbit wallet create')
    for addr in addrs:
        click.echo(addr)


# ===========================================================================
# Top-level transaction commands
# ===========================================================================

@cli.command('send')
@click.argument('to_address')
@click.argument('amount', type=float)
@click.option('--fee', default=None, type=float, help='Explicit fee in SBT (default: node estimate)')
@click.option('--fee-rate', type=click.IntRange(min=1), default=None, help='Quanta per 1,000 signed bytes')
@click.option('--rbf', is_flag=True, help='Signal Replace-By-Fee (allows bumping later)')
@click.option('--from', 'from_address', default='', help='Specific sending address')
@click.option('--node-socket', type=click.Path(), default=None)
def send(to_address: str, amount: float, fee: float | None, fee_rate: int | None,
         rbf: bool, from_address: str, node_socket: str | None):
    """Send SBT to an address."""
    from shieldbit.crypto.address import validate_address
    from shieldbit.wallet.wallet import Wallet
    from shieldbit.network.local_rpc import request

    if not validate_address(to_address):
        click.echo(f'Invalid address: {to_address}', err=True)
        sys.exit(1)

    amount_quanta = _sbt_to_quanta(amount)
    fee_quanta = None if fee is None else _sbt_to_quanta(fee)

    ks, blockchain = _load_wallet()
    try:
        if fee_rate is None:
            estimate = asyncio.run(request(node_socket or CONFIG_DIR / 'node.sock', 'estimate_fee'))
            fee_rate = estimate['quanta_per_kb']
        signed_tx = Wallet.from_keystore(ks, blockchain).build_transaction(
            to_address, amount_quanta, fee=fee_quanta, rbf=rbf,
            from_address=from_address or None, fee_rate_per_kb=fee_rate)
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        raise click.ClickException(str(exc)) from exc

    from shieldbit.consensus.validation import validate_transaction
    rows = blockchain.db.utxos()
    try:
        validate_transaction(
            signed_tx, {(r[0], r[1]): r[2] for r in rows}, 250, blockchain.height,
            {(r[0], r[1]): r[4] for r in rows if r[5]},
            {(r[0], r[1]): r[3] for r in rows}, blockchain.get_median_time_past(),
            blockchain.network_id,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    from shieldbit.network.local_rpc import submit_transaction
    try:
        asyncio.run(submit_transaction(node_socket or CONFIG_DIR / 'node.sock', signed_tx))
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        raise click.ClickException(f'Node submission failed: {exc}') from exc
    click.echo(f'Transaction ID: {signed_tx.txid.hex()}')
    click.echo(f'Amount: {_quanta_to_sbt(amount_quanta)}')
    click.echo(f'Fee: {signed_tx.fee({(r[0], r[1]): r[2] for r in rows})} quanta')
    click.echo('Accepted by the node mempool; confirmation is still pending.')


@cli.command('bump')
@click.argument('txid')
@click.argument('new_fee', type=float)
def bump(txid: str, new_fee: float):
    """Bump the fee on an RBF-flagged transaction."""
    click.echo(f'Bumping fee for txid {txid[:16]}... to {new_fee} SBT')
    click.echo('(Fee bumping requires active mempool access via a running node)')


@cli.command('mine')
@click.option('--threads', default=1, help='Number of mining threads')
@click.option('--address', 'miner_address', default='', help='Payout address (uses first wallet address if not set)')
@click.option('--node-socket', type=click.Path(), default=None)
def mine(threads: int, miner_address: str, node_socket: str | None):
    """CPU-mine templates from the running local node and submit solved blocks."""
    from shieldbit.consensus.pow import mine_block
    from shieldbit.core.block import Block
    from shieldbit.crypto.address import address_to_commitment
    from shieldbit.network.local_rpc import request

    if threads != 1:
        raise click.ClickException('Only single-thread CPU mining is currently supported.')

    # Resolve miner address
    if not miner_address:
        ks, _ = _load_wallet()
        addrs = ks.list_addresses()
        if not addrs:
            click.echo('No wallet address. Run: shieldbit wallet create', err=True)
            sys.exit(1)
        miner_address = addrs[0]

    from shieldbit.crypto.address import validate_address
    if not validate_address(miner_address):
        click.echo(f'Invalid address: {miner_address}', err=True)
        sys.exit(1)

    miner_hash = address_to_commitment(miner_address, expected_version=1, expected_commitment_version=2)
    click.echo(f'Mining to: {miner_address}')
    click.echo('Press Ctrl+C to stop.\n')

    path = node_socket or CONFIG_DIR / 'node.sock'
    found = 0

    try:
        while True:
            response = asyncio.run(request(path, 'block_template', recipient=miner_hash.hex()))
            template = Block.from_bytes(bytes.fromhex(response['block']))
            # Refresh the template periodically instead of mining a stale tip indefinitely.
            solved = mine_block(template, max_nonce=100_000)
            if solved is not None:
                try:
                    receipt = asyncio.run(request(path, 'submit_block', block=solved.serialize().hex()))
                    if receipt.get('hash') != solved.header.hash.hex():
                        raise ValueError('node acknowledged a different block')
                    found += 1
                    status = 'canonical' if receipt.get('canonical') else 'side branch'
                    click.echo(f'Block accepted ({status}): {solved.header.hash.hex()}')
                except ValueError as e:
                    click.echo(f'Block rejected: {e}', err=True)
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        raise click.ClickException(f'Node mining request failed: {exc}') from exc
    except KeyboardInterrupt:
        click.echo(f'\nMining stopped. Blocks found this session: {found}')


# ===========================================================================
# Utility commands
# ===========================================================================

@cli.command('info')
def info():
    """Show network parameters."""
    from shieldbit.consensus.params import MAX_SUPPLY, MIN_FEE, QUANTA_PER_SBT as QPC
    from shieldbit.network_profile import ACTIVE
    profile = ACTIVE.get()
    params = {
        'name': 'ShieldBit',
        'ticker': 'SBT',
        'author': 'Vipul Tomar',
        'max_supply_SBT': MAX_SUPPLY / QPC,
        'initial_block_reward_SBT': 50,
        'halving_interval_blocks': 210000,
        'block_time_seconds': 600,
        'block_size_mb': 6,
        'min_fee_quanta': MIN_FEE,
        'quanta_per_SBT': QPC,
        'network': profile.name,
        'network_magic': profile.magic.hex(),
        'genesis_bits': hex(profile.genesis_bits),
        'network_port': profile.port,
        'address_prefix': profile.hrp,
        'signature_scheme': 'ML-DSA-65 (FIPS 204)',
        'pow_algorithm': 'double-SHA256 proof-of-work',
        'hash_algorithm': 'SHA3-256',
    }
    click.echo(json.dumps(params, indent=2))


def main():
    cli()


if __name__ == '__main__':
    main()
