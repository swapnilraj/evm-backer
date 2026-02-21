# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.crawler module

Confirmation monitoring for anchored KERI events on Ethereum.

Tracks submitted transactions, waits for sufficient block confirmations,
detects reorgs via block hash comparison, detects reverted transactions,
and requeues events on timeout or failure.

Reference:
  - evm-backer-spec.md section 5.7 (Confirmation)
"""

import logging

logger = logging.getLogger(__name__)

CONFIRMATION_DEPTH = 12  # blocks required to consider an anchor confirmed
TIMEOUT_DEPTH = 32       # blocks after which unconfirmed tx is requeued


class PendingAnchor:
    """Tracks a submitted transaction awaiting confirmation."""

    __slots__ = ("tx_hash", "block_number", "block_hash", "events")

    def __init__(self, tx_hash, block_number, block_hash, events):
        self.tx_hash = tx_hash
        self.block_number = block_number
        self.block_hash = block_hash
        self.events = events  # list of (prefix_qb64, sn, said_qb64)


class Crawler:
    """Monitors anchoring transactions for confirmation and reorgs.

    The Crawler checks pending transactions against the chain:
    1. If current_block - anchor_block >= CONFIRMATION_DEPTH and block hash
       matches, the events are confirmed.
    2. If the block hash at anchor_block has changed, a reorg occurred —
       events are requeued.
    3. If current_block - anchor_block >= TIMEOUT_DEPTH and the tx was
       never mined, events are requeued.
    4. If the transaction receipt shows status == 0 (reverted), events
       are requeued immediately.
    5. If the RPC is unreachable, the check cycle is skipped without
       advancing timeout counters.
    """

    def __init__(self, w3, queuer):
        self.w3 = w3
        self.queuer = queuer
        self._pending = []  # list of PendingAnchor
        self._confirmed_count = 0

    def track(self, tx_hash, events):
        """Start tracking a submitted transaction.

        Fetches the transaction receipt to get the block number and hash.
        If the receipt shows the tx reverted (status == 0), requeues
        the events immediately.

        Args:
            tx_hash: Transaction hash (hex string).
            events: list of (prefix_qb64, sn, said_qb64) tuples.
        """
        try:
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        except Exception:
            logger.warning(
                "Failed to fetch receipt for %s, requeuing events", tx_hash
            )
            self.queuer.requeue(events)
            return

        if receipt is None:
            logger.warning("Receipt is None for %s, requeuing events", tx_hash)
            self.queuer.requeue(events)
            return

        if receipt.status == 0:
            logger.warning(
                "Transaction %s reverted (status=0), requeuing %d events",
                tx_hash,
                len(events),
            )
            self.queuer.requeue(events)
            return

        if receipt.status != 1:
            logger.warning(
                "Transaction %s has unexpected status %d, requeuing events",
                tx_hash,
                receipt.status,
            )
            self.queuer.requeue(events)
            return

        block = self.w3.eth.get_block(receipt.blockNumber)
        pending = PendingAnchor(
            tx_hash=tx_hash,
            block_number=receipt.blockNumber,
            block_hash=block.hash,
            events=events,
        )
        self._pending.append(pending)

    def check(self):
        """Check all pending anchors for confirmation, reorg, or timeout.

        If the RPC is unreachable, the check cycle is skipped entirely —
        pending anchors are not modified and timeout counters do not advance.

        Returns:
            A tuple of (confirmed, reorged) lists.
            Each list contains PendingAnchor instances.
            Returns ([], []) if the RPC is unreachable.
        """
        try:
            current_block = self.w3.eth.block_number
        except Exception:
            logger.warning(
                "RPC unreachable during check(), skipping cycle "
                "(%d pending anchors unchanged)",
                len(self._pending),
            )
            return [], []

        confirmed = []
        reorged = []
        timed_out = []
        still_pending = []

        for anchor in self._pending:
            depth = current_block - anchor.block_number

            # Timeout: tx was mined too long ago without confirmation,
            # or was never included and block height has moved far past
            if depth >= TIMEOUT_DEPTH:
                timed_out.append(anchor)
                self.queuer.requeue(anchor.events)
                logger.warning(
                    "Anchor %s timed out at depth %d, requeuing %d events",
                    anchor.tx_hash,
                    depth,
                    len(anchor.events),
                )
                continue

            if depth < CONFIRMATION_DEPTH:
                still_pending.append(anchor)
                continue

            try:
                current_hash = self.w3.eth.get_block(anchor.block_number).hash
            except Exception:
                logger.warning(
                    "Failed to fetch block %d for anchor %s, keeping pending",
                    anchor.block_number,
                    anchor.tx_hash,
                )
                still_pending.append(anchor)
                continue

            if current_hash == anchor.block_hash:
                confirmed.append(anchor)
                self._confirmed_count += 1
            else:
                reorged.append(anchor)
                self.queuer.requeue(anchor.events)

        self._pending = still_pending
        return confirmed, reorged

    @property
    def pending_count(self):
        """Number of pending (unconfirmed) anchors."""
        return len(self._pending)

    @property
    def confirmed_count(self):
        """Number of confirmed anchors."""
        return self._confirmed_count
