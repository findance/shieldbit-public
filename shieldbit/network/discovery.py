# Copyright 2026 Vipul Tomar (findance) — Apache-2.0
"""
Peer discovery for ShieldBit.

Bootstraps the peer set from hardcoded seed nodes (empty at mainnet launch —
to be populated), then learns additional peers from ADDR messages.

Author: Vipul Tomar
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from shieldbit.network.peer import PeerManager

if TYPE_CHECKING:
    from shieldbit.network.node import Node

logger = logging.getLogger(__name__)

# Seed nodes — to be populated at mainnet launch.
# Format: (hostname_or_ip, port)
SEED_NODES: list[tuple[str, int]] = [
    # ('seed1.shieldbit.org', 9333),
    # ('seed2.shieldbit.org', 9333),
]


class PeerDiscovery:
    """Manages peer discovery and bootstrapping.

    Connects to seed nodes on first run and learns peers from ADDR messages.

    Args:
        node: The local Node instance.
    """

    def __init__(self, node: Node) -> None:
        self.node = node
        self.peer_manager: PeerManager = node.peer_manager

    async def bootstrap(
        self,
        seed_nodes: list[tuple[str, int]] | None = None,
        target_peers: int = 8,
    ) -> None:
        """Connect to seed nodes and then to any known peers.

        Args:
            seed_nodes: Override list of seed nodes.
            target_peers: Desired number of connected peers.
        """
        seeds = SEED_NODES if seed_nodes is None else seed_nodes
        for host, port in seeds:
            self.peer_manager.add_peer(host, port)

        # Try to connect to connectable peers
        candidates = self.peer_manager.get_connectable(limit=target_peers)
        tasks = [self.node.connect_to_peer(h, p) for h, p in [c.address for c in candidates]]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        if self.node.peer_count() == 0 and seeds:
            logger.warning('No peers connected after bootstrap. Will retry on next cycle.')
        else:
            logger.info('Bootstrap complete. Connected peers: %d', self.node.peer_count())

    def handle_addr_message(self, peers: list[tuple[str, int]]) -> None:
        """Process an ADDR message from a peer and add discovered peers.

        Args:
            peers: List of (host, port) tuples from the ADDR message.
        """
        for host, port in peers:
            self.peer_manager.add_peer(host, port)
        logger.debug('Learned %d new peer addresses', len(peers))

    async def maintain_connections(
        self, target: int = 8, interval: float = 60.0
    ) -> None:
        """Periodically ensure we have enough connected peers.

        Args:
            target: Target number of connected peers.
            interval: Seconds between maintenance cycles.
        """
        while True:
            await asyncio.sleep(interval)
            current = sum(c.outbound for c in self.node._connections)
            if current < target:
                needed = target - current
                candidates = self.peer_manager.get_connectable(limit=needed)
                for candidate in candidates:
                    await self.node.connect_to_peer(candidate.host, candidate.port)
