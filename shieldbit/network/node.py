# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Asyncio P2P node for ShieldBit.

Handles: inbound/outbound connections, message dispatch, block/tx relay,
and compact block propagation.

Author: Vipul Tomar
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from shieldbit.consensus.params import NETWORK_PORT
from shieldbit.core.blockchain import PrunedHistoryRequired
from shieldbit.network.protocol import (
    Message, HEADER_SIZE,
    CMD_VERSION, CMD_VERACK, CMD_INV, CMD_GETDATA, CMD_BLOCK, CMD_TX,
    CMD_GETBLOCKS, CMD_PING, CMD_PONG, CMD_ADDR, CMD_CHANNEL_ALERT,
    CMD_CMPCTBLOCK, CMD_REJECT, CMD_NOTFOUND,
    INV_TX, INV_BLOCK, INV_CMPCT_BLOCK,
    version_msg, verack_msg, ping_msg, pong_msg, inv_msg,
    getdata_msg, getblocks_msg, tx_msg, block_msg, addr_msg, parse_inv, parse_version,
)
from shieldbit.network.peer import PeerManager, PeerInfo
from shieldbit.network.limits import TokenBucket, network_group

if TYPE_CHECKING:
    from shieldbit.core.blockchain import Blockchain
    from shieldbit.mempool.mempool import Mempool

logger = logging.getLogger(__name__)

USER_AGENT = '/ShieldBit:0.1.0/'
HANDSHAKE_TIMEOUT = 10
READ_TIMEOUT = 60
WRITE_TIMEOUT = 5
MAX_CONNECTIONS = 64
OUTBOUND_RESERVE = 8
MAX_OUTBOUND_PER_GROUP = 2
MAX_INBOUND_PER_HOST = 4
MIB = 1024 * 1024


class PeerConnection:
    """Wraps a single peer connection."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        node: 'Node',
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.node = node
        self.host, self.port = writer.get_extra_info('peername', ('?', 0))[:2]
        self.handshake_done = False
        self.version_received = False
        self.verack_received = False
        self.handshake_deadline = time.monotonic() + HANDSHAKE_TIMEOUT
        self._buf = b''
        self.closed = False
        self.outbound = False
        self.dial_address = (self.host, self.port)
        self.receive_budget = TokenBucket(6 * MIB, 24 * MIB)
        self.send_budget = TokenBucket(6 * MIB, 24 * MIB)
        self.work_budget = TokenBucket(256, 2048)
        self.requested: set[tuple[int, bytes]] = set()
        self.sync_end: bytes | None = None
        self.sync_more = False
        self.request_deadline = 0.0
        self.sent_messages = 0
        self.received_messages = 0
        self.disconnect_reason = 'peer_closed'
        self._send_lock = asyncio.Lock()

    async def send(self, msg: Message) -> None:
        """Send a message to this peer."""
        if self.closed:
            return
        try:
            size = HEADER_SIZE + len(msg.payload)
            if not self.send_budget.consume(size) or not self.node.send_budget.consume(size):
                self.close('send_budget_exceeded')
                return
            raw = msg.to_bytes()
            async with self._send_lock:
                self.writer.write(raw)
                await asyncio.wait_for(self.writer.drain(), WRITE_TIMEOUT)
                self.sent_messages += 1
        except (ConnectionError, asyncio.TimeoutError) as exc:
            self.close('write_timeout' if isinstance(exc, asyncio.TimeoutError) else 'write_error')

    async def recv_message(self) -> Message | None:
        """Read one message from the peer."""
        try:
            while True:
                if self.closed:
                    return None
                msg, self._buf = Message.read_from_buffer(self._buf)
                if msg is not None:
                    self.received_messages += 1
                    cost = max(1, len(msg.payload) / 65536)
                    if not self.work_budget.consume(cost) or (self.node and not self.node.work_budget.consume(cost)):
                        raise ValueError('peer work budget exceeded')
                    return msg
                chunk = await self.reader.read(4096)
                if not chunk:
                    return None
                if not self.receive_budget.consume(len(chunk)) or (self.node and not self.node.receive_budget.consume(len(chunk))):
                    raise ValueError('peer bandwidth budget exceeded')
                self._buf += chunk
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return None

    def close(self, reason: str | None = None) -> None:
        if reason is not None:
            self.disconnect_reason = reason
        self.closed = True
        try:
            self.writer.close()
        except OSError as exc:
            logger.debug('Peer close failed: %s', exc)


class Node:
    """ShieldBit P2P node.

    Manages peer connections and relays ordinary transactions and blocks.

    Args:
        blockchain: The local blockchain instance.
        mempool: The local transaction mempool.
        host: Listening address (default 0.0.0.0).
        port: Listening port (default 9333).
    """

    def __init__(
        self,
        blockchain: Blockchain,
        mempool: Mempool,
        host: str = '0.0.0.0',
        port: int = NETWORK_PORT,
        *,
        rpc_socket: str | None = None,
        allowed_peers: frozenset[tuple[str, int]] | None = None,
    ) -> None:
        self.blockchain = blockchain
        self.mempool = mempool
        self.host = host
        self.port = port
        self.allowed_peers = allowed_peers
        self.peer_manager = PeerManager()
        self._connections: list[PeerConnection] = []
        self._server: asyncio.AbstractServer | None = None
        self._running = False
        self._pending_connections = 0
        self._pending_addresses: set[tuple[str, int]] = set()
        self._peer_tasks: set[asyncio.Task] = set()
        self._recent_disconnects: list[dict] = []
        self.receive_budget = TokenBucket(24 * MIB, 128 * MIB)
        self.send_budget = TokenBucket(24 * MIB, 128 * MIB)
        self.work_budget = TokenBucket(1024, 8192)
        from shieldbit.network.local_rpc import LocalRPC
        self._rpc = LocalRPC(self, rpc_socket) if rpc_socket else None

    async def start(self) -> None:
        """Start listening for inbound connections."""
        self._running = True
        serving = None
        try:
            if self._rpc:
                await self._rpc.start()
            self._server = await asyncio.start_server(self._handle_inbound, self.host, self.port)
            logger.info('ShieldBit node listening on %s:%d', self.host, self.port)
            serving = asyncio.create_task(self._server.serve_forever())
            # serve_forever itself waits for clients when cancelled on newer Python.
            # Keep it alive until our finally closes peers, then finish its cleanup.
            await asyncio.shield(serving)
        finally:
            try:
                await self.stop()
            finally:
                if serving is not None:
                    serving.cancel()
                    await asyncio.gather(serving, return_exceptions=True)

    async def stop(self) -> None:
        """Gracefully shut down the node."""
        self._running = False
        if self._rpc:
            await self._rpc.stop()
        if self._server:
            self._server.close()
        # Python 3.12+ waits for clients too; close them before awaiting the server.
        for conn in list(self._connections):
            conn.close()
        tasks = [task for task in self._peer_tasks if task is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._server:
            await self._server.wait_closed()
        self._connections.clear()

    async def connect_to_peer(self, host: str, port: int) -> None:
        """Open an outbound connection to a peer.

        Args:
            host: Peer IP address.
            port: Peer port.
        """
        if self.allowed_peers is not None and (host, port) not in self.allowed_peers:
            return
        if len(self._connections) + self._pending_connections >= MAX_CONNECTIONS:
            return
        address = (host, port)
        if address in self._pending_addresses or any(c.dial_address == address for c in self._connections):
            return
        peer = self.peer_manager.add_peer(host, port)
        if peer.is_banned or peer.retry_after > time.monotonic():
            return
        self._pending_connections += 1
        self._pending_addresses.add(address)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            conn = PeerConnection(reader, writer, self)
            conn.outbound = True
            conn.dial_address = address
            group = network_group(conn.host)
            if group != 'loopback' and sum(
                c.outbound and network_group(c.host) == group for c in self._connections
            ) >= MAX_OUTBOUND_PER_GROUP:
                conn.close()
                await writer.wait_closed()
                self.peer_manager.mark_failed(host, port)
                return
            self._connections.append(conn)
            self.peer_manager.mark_connected(host, port)
            logger.info('Connected to peer %s:%d', host, port)
            task = asyncio.create_task(self._run_peer(conn))
            self._peer_tasks.add(task)
            task.add_done_callback(self._peer_tasks.discard)
            # Send our version message
            await conn.send(version_msg(height=self.blockchain.height, services=self.services,
                                        genesis_hash=self.blockchain.genesis_hash))
        except (OSError, asyncio.TimeoutError) as exc:
            self.peer_manager.mark_failed(host, port)
            logger.debug('Failed to connect to %s:%d: %s', host, port, exc)
        finally:
            self._pending_connections -= 1
            self._pending_addresses.discard(address)

    async def broadcast(self, msg: Message) -> None:
        """Send a message to all connected peers."""
        await asyncio.gather(*(conn.send(msg) for conn in list(self._connections) if conn.handshake_done))

    async def broadcast_tx(self, tx_bytes: bytes) -> None:
        """Relay a transaction to all peers."""
        from shieldbit.crypto.hashing import double_sha3
        txid = double_sha3(tx_bytes)
        await self.broadcast(inv_msg([(INV_TX, txid)]))

    async def broadcast_block(self, block_bytes: bytes) -> None:
        """Relay a new block to all peers using compact relay."""
        from shieldbit.core.block import BlockHeader
        block_hash = BlockHeader.from_bytes(block_bytes).hash
        await self.broadcast(inv_msg([(INV_BLOCK, block_hash)]))

    # ------------------------------------------------------------------
    # Internal connection handlers
    # ------------------------------------------------------------------

    async def _handle_inbound(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        inbound = sum(not getattr(c, 'outbound', False) for c in self._connections)
        inbound_limit = max(0, MAX_CONNECTIONS - min(OUTBOUND_RESERVE, MAX_CONNECTIONS))
        if (len(self._connections) + self._pending_connections >= MAX_CONNECTIONS
                or inbound >= inbound_limit):
            writer.close()
            await writer.wait_closed()
            return
        host, port = writer.get_extra_info('peername', ('?', 0))[:2]
        if self.allowed_peers is not None and host not in {h for h, _ in self.allowed_peers}:
            writer.close()
            await writer.wait_closed()
            return
        if network_group(host) != 'loopback' and sum(c.host == host for c in self._connections) >= MAX_INBOUND_PER_HOST:
            writer.close()
            await writer.wait_closed()
            return
        logger.info('Inbound connection from %s:%d', host, port)
        conn = PeerConnection(reader, writer, self)
        self._connections.append(conn)
        self.peer_manager.add_peer(host, port)
        self.peer_manager.mark_connected(host, port)
        # Send version on inbound too
        await conn.send(version_msg(height=self.blockchain.height, services=self.services,
                                    genesis_hash=self.blockchain.genesis_hash))
        await self._run_peer(conn)

    async def _run_peer(self, conn: PeerConnection) -> None:
        """Main receive loop for a peer connection."""
        task = asyncio.current_task()
        self._peer_tasks.add(task)
        async def keepalive():
            while True:
                await asyncio.sleep(READ_TIMEOUT / 3)
                if conn.requested and time.monotonic() >= conn.request_deadline:
                    conn.close('request_timeout')
                    return
                if conn.handshake_done:
                    await conn.send(ping_msg())
                    if (conn.sync_end is not None
                            and not any(t == INV_BLOCK for t, _ in conn.requested)
                            and not self.blockchain.db.has_block(conn.sync_end)):
                        await self._request_missing_history(conn)
        heartbeat = asyncio.create_task(keepalive())
        try:
            while not conn.reader.at_eof():
                timeout = READ_TIMEOUT if conn.handshake_done else max(0, conn.handshake_deadline - time.monotonic())
                msg = await asyncio.wait_for(conn.recv_message(), timeout)
                if msg is None:
                    break
                await self._handle_message(msg, conn)
        except Exception as exc:
            logger.debug('Peer %s:%d error: %s', conn.host, conn.port, exc)
            conn.disconnect_reason = {'peer work budget exceeded': 'work_budget_exceeded',
                                      'peer bandwidth budget exceeded': 'bandwidth_budget_exceeded'}.get(
                                          str(exc), 'protocol_or_io_error')
        finally:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
            if conn in self._connections:
                self._connections.remove(conn)
            self.peer_manager.mark_disconnected(conn.host, conn.port)
            if conn.dial_address != (conn.host, conn.port):
                self.peer_manager.mark_disconnected(*conn.dial_address)
            conn.close()
            self._recent_disconnects.append({'reason': conn.disconnect_reason,
                'height': self.blockchain.height, 'received_messages': conn.received_messages,
                'sent_messages': conn.sent_messages})
            del self._recent_disconnects[:-16]
            self._peer_tasks.discard(task)
            logger.info('Peer %s:%d disconnected', conn.host, conn.port)

    async def _handle_message(self, msg: Message, conn: PeerConnection) -> None:
        """Dispatch an incoming message by command."""
        cmd = msg.command.rstrip(b'\x00')
        if not conn.handshake_done and cmd not in (b'version', b'verack'):
            raise ValueError('peer handshake is not complete')

        if cmd == CMD_VERSION.rstrip(b'\x00'):
            if conn.version_received:
                raise ValueError('duplicate peer version')
            metadata = parse_version(msg.payload)
            if metadata.pop('genesis_hash') != self.blockchain.genesis_hash:
                raise ValueError('peer genesis commitment does not match configured network')
            self.peer_manager.update_peer(conn.host, conn.port, **metadata)
            conn.version_received = True
            await conn.send(verack_msg())

        elif cmd == CMD_VERACK.rstrip(b'\x00'):
            if not conn.version_received or conn.verack_received or msg.payload:
                raise ValueError('invalid peer handshake acknowledgement')
            conn.verack_received = True
            conn.handshake_done = True
            self.peer_manager.mark_healthy(*getattr(conn, 'dial_address', (conn.host, conn.port)))
            await conn.send(getblocks_msg(self.blockchain.tip))

        elif cmd == CMD_PING.rstrip(b'\x00'):
            if len(msg.payload) != 8:
                raise ValueError('invalid peer ping length')
            await conn.send(pong_msg(msg.payload))

        elif cmd == CMD_PONG.rstrip(b'\x00'):
            if len(msg.payload) != 8:
                raise ValueError('invalid peer pong length')
            pass  # Update latency tracking if desired

        elif cmd == CMD_INV.rstrip(b'\x00'):
            await self._on_inv(msg.payload, conn)

        elif cmd == CMD_GETDATA.rstrip(b'\x00'):
            await self._on_getdata(msg.payload, conn)

        elif cmd == CMD_NOTFOUND.rstrip(b'\x00'):
            items = parse_inv(msg.payload)
            if len(items) > 1000:
                raise ValueError('peer missing-data response exceeds item limit')
            for item in items:
                getattr(conn, 'requested', set()).discard(item)

        elif cmd == CMD_GETBLOCKS.rstrip(b'\x00'):
            await self._on_getblocks(msg.payload, conn)

        elif cmd == CMD_TX.rstrip(b'\x00'):
            await self._on_tx(msg.payload, conn)

        elif cmd == CMD_BLOCK.rstrip(b'\x00'):
            await self._on_block(msg.payload, conn)

        elif cmd == CMD_ADDR.rstrip(b'\x00'):
            pass  # Parse and add to peer_manager

        elif cmd == CMD_CHANNEL_ALERT.rstrip(b'\x00'):
            return  # Reserved legacy command; never interpret or relay it.

        else:
            logger.debug('Unknown command from %s: %s', conn.host, cmd)

    async def _on_inv(self, payload: bytes, conn: PeerConnection) -> None:
        items = parse_inv(payload)
        if len(items) > 1000:
            raise ValueError('peer inventory exceeds request window')
        block_hashes = list(dict.fromkeys(h for t, h in items if t == INV_BLOCK))
        requested = getattr(conn, 'requested', set())
        want = [(t, h) for t, h in items if
                (t, h) not in requested and (
                (t == INV_TX and h not in self.mempool.transactions) or
                (t == INV_BLOCK and not self.blockchain.db.has_block(h)))]
        want = list(dict.fromkeys(want))
        if block_hashes and any(t == INV_BLOCK for t, _ in want):
            conn.sync_end = block_hashes[-1]
            # Only a full getblocks page implies another page. A live block
            # announcement is not a reason to poll history after every block.
            conn.sync_more = getattr(conn, 'sync_more', False) or len(block_hashes) == 500
        if len(requested) + len(want) > 1000:
            raise ValueError('peer inventory exceeds request window')
        if want:
            if not requested:
                conn.request_deadline = time.monotonic() + READ_TIMEOUT
            conn.requested = requested | set(want)
            await conn.send(getdata_msg(want))
        elif block_hashes and not any(t == INV_BLOCK for t, _ in requested):
            last = block_hashes[-1]
            if len(block_hashes) == 500 or self.blockchain.db.get_height_by_hash(last) is None:
                await self._request_missing_history(conn, last)

    async def _on_getdata(self, payload: bytes, conn: PeerConnection) -> None:
        items = parse_inv(payload)
        if len(items) > 1000:
            raise ValueError('peer data request exceeds item limit')
        missing = []
        for item_type, item_hash in items:
            if getattr(conn, 'closed', False):
                break
            if item_type == INV_BLOCK:
                # Try to find block by hash
                raw = self.blockchain.db.get_block_by_hash(item_hash)
                if raw:
                    await conn.send(block_msg(raw))
                else:
                    missing.append((item_type, item_hash))
            elif item_type == INV_TX:
                tx = self.mempool.get(item_hash)
                if tx:
                    await conn.send(tx_msg(tx.serialize()))
                else:
                    missing.append((item_type, item_hash))
        if missing:
            await conn.send(Message(CMD_NOTFOUND, inv_msg(missing).payload))

    async def _on_getblocks(self, payload: bytes, conn: PeerConnection) -> None:
        from shieldbit.core.wire import Reader
        reader = Reader(payload)
        reader.uint(4, 'little')
        count = reader.compact_size()
        if not 1 <= count <= 32:
            raise ValueError('invalid block locator count')
        locators = [reader.take(32) for _ in range(count)]
        stop = reader.take(32)
        reader.finish()
        start = -1
        for locator in locators:
            height = self.blockchain.db.get_height_by_hash(locator)
            if height is not None:
                start = height
                break
        hashes = self.blockchain.db.get_block_hashes(start + 1, start + 500)
        if stop in hashes:
            hashes = hashes[:hashes.index(stop) + 1]
        await conn.send(inv_msg([(INV_BLOCK, h) for h in hashes]))

    async def _on_block(self, block_bytes: bytes, conn: PeerConnection | None = None) -> None:
        """Process a received block."""
        try:
            await self.submit_block(block_bytes, conn)
        except PrunedHistoryRequired as exc:
            logger.warning('Archive recovery needed: %s', exc)
        except ValueError as exc:
            logger.warning('Rejected block: %s', exc)
            if conn is not None and str(exc) == 'unknown parent or competing genesis':
                from shieldbit.core.block import BlockHeader, HEADER_SIZE as BLOCK_HEADER_SIZE
                header = BlockHeader.from_bytes(block_bytes[:BLOCK_HEADER_SIZE])
                if header.prev_hash != b'\0' * 32:
                    await self._request_missing_history(conn)

    async def _request_missing_history(self, conn: PeerConnection, locator: bytes | None = None) -> None:
        tip = self.blockchain.tip if locator is None else locator
        now = time.monotonic()
        previous_tip, previous_time = getattr(conn, 'last_history_request', (None, 0))
        if previous_tip == tip and now - previous_time < 1:
            return
        conn.last_history_request = (tip, now)
        await conn.send(getblocks_msg(tip))

    async def _complete_sync_endpoint(self, conn: PeerConnection, block_hash: bytes) -> None:
        if getattr(conn, 'sync_end', None) != block_hash:
            return
        more = getattr(conn, 'sync_more', False)
        conn.sync_end = None
        conn.sync_more = False
        if more:
            await self._request_missing_history(conn, block_hash)

    async def submit_block(self, block_bytes: bytes, conn: PeerConnection | None = None) -> bytes:
        """Validate a local or peer block and update the shared mempool."""
        from shieldbit.core.block import Block
        block = Block.from_bytes(block_bytes)
        if conn is not None:
            getattr(conn, 'requested', set()).discard((INV_BLOCK, block.header.hash))
        if self.blockchain.db.has_block(block.header.hash):
            if conn is not None:
                await self._complete_sync_endpoint(conn, block.header.hash)
            return block.header.hash
        try:
            self.blockchain.add_block(block)
        except PrunedHistoryRequired as exc:
            with self.blockchain.db.transaction():
                previous = self.blockchain.db.get_setting_int('recovery_height', -1)
                self.blockchain.db.set_setting_int('recovery_height',
                                                   min(previous, exc.height) if previous >= 0 else exc.height)
            raise
        confirmed = {tx.txid for b in self.blockchain.last_connected for tx in b.transactions}
        disconnected = self.blockchain.last_disconnected
        self.mempool.remove_confirmed(confirmed)
        rows = self.blockchain.db.utxos_for_outpoints(
            p for tx in self.mempool.transactions.values() for p in tx.spent_outpoints()
        )
        self.mempool.revalidate(
            {(r[0], r[1]): r[2] for r in rows}, self.blockchain.height,
            {(r[0], r[1]): r[3] for r in rows},
            {(r[0], r[1]): r[4] for r in rows if r[5]},
            self.blockchain.get_median_time_past(),
            self.blockchain.network_id,
        )
        for old_block in reversed(disconnected):
            for tx in old_block.transactions[1:]:
                if tx.txid not in confirmed:
                    try:
                        await self.submit_transaction(tx.serialize())
                    except ValueError:
                        pass  # New-branch conflicts must not be resurrected.
        logger.info('Block accepted; canonical height %d', self.blockchain.height)
        await self.broadcast_block(block_bytes)
        if conn is not None and getattr(conn, 'sync_end', None) == block.header.hash:
            await self._complete_sync_endpoint(conn, block.header.hash)
        elif (conn is not None and getattr(conn, 'sync_end', None) is not None
              and not any(t == INV_BLOCK for t, _ in getattr(conn, 'requested', set()))
              and not self.blockchain.db.has_block(conn.sync_end)):
            await self._request_missing_history(conn)
        return block.header.hash

    def block_template(self, recipient: bytes, *, auxiliary: bool = False):
        """Build a next-tip template from the live node's validated mempool."""
        import time
        import secrets
        from shieldbit.core.block import Block, BlockHeader, HEADER_SIZE
        from shieldbit.core.transaction import coinbase
        from shieldbit.core.merkle import merkle_root
        from shieldbit.core.filters import build_gcs_filter, filter_hash
        from shieldbit.consensus.params import MAX_BLOCK_SIZE, MAX_AUXPOW_SIZE, AUXPOW_VERSION, block_reward, compact_to_target

        if len(recipient) != 32:
            raise ValueError('mining recipient must be 32 bytes')
        chain = self.blockchain
        if auxiliary and chain.height < 0:
            raise ValueError('genesis must be mined independently')
        rows = chain.db.utxos_for_outpoints(
            p for tx in self.mempool.transactions.values() for p in tx.spent_outpoints()
        )
        amounts = {(r[0], r[1]): r[2] for r in rows}
        self.mempool.revalidate(amounts, chain.height, {(r[0], r[1]): r[3] for r in rows},
                                {(r[0], r[1]): r[4] for r in rows if r[5]},
                                chain.get_median_time_past(), chain.network_id)
        height = chain.height + 1
        extra_nonce = secrets.token_bytes(16)
        cb = coinbase(height, block_reward(height), recipient, extra_nonce)
        reserve = MAX_AUXPOW_SIZE if auxiliary else 0
        pending = self.mempool.get_for_block(MAX_BLOCK_SIZE - HEADER_SIZE - 4 - len(cb.serialize()) - reserve)
        fees = sum(sum(amounts[p] for p in tx.spent_outpoints()) - tx.output_total() for tx in pending)
        txs = (coinbase(height, block_reward(height) + fees, recipient, extra_nonce), *pending)
        bits = chain.get_current_bits()
        header = BlockHeader(AUXPOW_VERSION if auxiliary else 1, chain.tip, merkle_root([tx.txid for tx in txs]),
                             filter_hash(build_gcs_filter([o.recipient for tx in txs for o in tx.outputs])),
                             max(int(time.time()), chain.get_median_time_past() + 1),
                             bits, compact_to_target(bits))
        return Block(header, txs)

    async def _on_tx(self, tx_bytes: bytes, conn: PeerConnection) -> None:
        """Process a received transaction."""
        try:
            from shieldbit.crypto.hashing import double_sha3
            getattr(conn, 'requested', set()).discard((INV_TX, double_sha3(tx_bytes)))
            await self.submit_transaction(tx_bytes)
        except ValueError as exc:
            logger.debug('Rejected tx: %s', exc)
            if conn:
                self.peer_manager.add_ban_score(conn.host, conn.port, 1)

    async def submit_transaction(self, tx_bytes: bytes) -> bytes:
        """Apply the same validation to peer and local-wallet submissions."""
        from shieldbit.core.transaction import Transaction
        tx = Transaction.from_bytes(tx_bytes)
        if tx.txid in self.mempool.transactions:
            return tx.txid
        rows = self.blockchain.db.utxos_for_outpoints(tx.spent_outpoints())
        self.mempool.add(
            tx, {(r[0], r[1]): r[2] for r in rows}, self.blockchain.height,
            utxo_recipients={(r[0], r[1]): r[3] for r in rows},
            coinbase_maturities={(r[0], r[1]): r[4] for r in rows if r[5]},
            current_time=self.blockchain.get_median_time_past(),
            network_id=self.blockchain.network_id,
        )
        if tx.txid not in self.mempool.transactions:
            raise ValueError('transaction was evicted by mempool capacity policy')
        await self.broadcast_tx(tx_bytes)
        return tx.txid

    def peer_count(self) -> int:
        """Return the number of currently connected peers."""
        return len(self._connections)

    @property
    def services(self) -> int:
        return 1024 if self.blockchain.prune_depth else 1

    def info(self) -> dict:
        """Return a summary of node state."""
        tip = self.blockchain.db.get_indexed_block(self.blockchain.tip)
        return {
            'network': self.blockchain.network_profile.name,
            'signing_network_id': self.blockchain.network_id.hex(),
            'signing_format_version': 2,
            'address_commitment_version': 2,
            'chainwork': tip[3] if tip else '0',
            'height': self.blockchain.height,
            'tip': self.blockchain.tip.hex(),
            'genesis_commitment': self.blockchain.genesis_hash.hex() if self.blockchain.genesis_hash else None,
            'peers': self.peer_count(),
            'mempool_size': len(self.mempool),
            'listening': f'{self.host}:{self.port}',
            'prune_depth': self.blockchain.prune_depth,
            'prune_height': self.blockchain.db.get_setting_int('prune_height'),
            'recovery_height': self.blockchain.db.get_setting_int('recovery_height', -1),
        }
