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
TIMEOUT_DEPTH = 32       # blocks after which an unmined tx is abandoned


class PendingAnchor:
    """Tracks a submitted transaction awaiting confirmation."""

    __slots__ = ("tx_hash", "block_number", "block_hash", "events")

    def __init__(self, tx_hash, block_number, block_hash, events):
        self.tx_hash = tx_hash
        self.block_number = block_number
        self.block_hash = block_hash
        self.events = events  # list of (prefix_qb64, sn, said_qb64)


class _UnconfirmedTx:
    """A submitted transaction that has not yet been mined."""

    __slots__ = ("tx_hash", "events", "submitted_block")

    def __init__(self, tx_hash, events, submitted_block):
        self.tx_hash = tx_hash
        self.events = events
        self.submitted_block = submitted_block


class Crawler:
    """Monitors anchoring transactions for confirmation and reorgs.

    The Crawler operates in two phases per check() cycle:

    Phase 1 — Resolve unconfirmed: for each submitted tx whose receipt has
    not yet been fetched, attempt to get the receipt. If mined successfully,
    promote to the pending list. If reverted or timed out (TIMEOUT_DEPTH
    blocks since submission with no receipt), requeue the events.

    Phase 2 — Confirm pending: for each mined tx, check whether its block
    is still canonical at CONFIRMATION_DEPTH. If the block hash at
    anchor.block_number still matches, mark confirmed. If the hash has
    changed (reorg), requeue the events.

    track() is non-blocking — it only records the tx for polling in check().
    All RPC calls are deferred to check(), so a slow node never stalls the
    flush cycle.
    """

    def __init__(self, w3, queuer):
        self.w3 = w3
        self.queuer = queuer
        self._unconfirmed = []  # list of _UnconfirmedTx
        self._pending = []      # list of PendingAnchor (mined, awaiting confirmation)
        self._confirmed_count = 0

    def track(self, tx_hash, events):
        """Start tracking a submitted transaction.

        Non-blocking: records the tx for polling in check(). The receipt is
        fetched lazily so callers do not stall waiting for the tx to be mined.

        Args:
            tx_hash: Transaction hash (hex string).
            events: list of (prefix_qb64, sn, said_qb64) tuples.
        """
        try:
            submitted_block = self.w3.eth.block_number
        except Exception:
            submitted_block = 0
        self._unconfirmed.append(_UnconfirmedTx(tx_hash, events, submitted_block))

    def check(self):
        """Check all tracked transactions for mining, confirmation, and reorgs.

        Phase 1: Resolve unconfirmed transactions (fetch receipts).
        Phase 2: Check pending (mined) transactions for confirmation / reorg.

        If the RPC is unreachable, the check cycle is skipped entirely —
        no state is modified and timeout counters do not advance.

        Returns:
            A tuple of (confirmed, reorged) lists of PendingAnchor instances.
            Timed-out and reverted transactions appear in reorged so that
            callers can call clear_pending_tx on them.
            Returns ([], []) if the RPC is unreachable.
        """
        try:
            current_block = self.w3.eth.block_number
        except Exception:
            logger.warning(
                "RPC unreachable during check(), skipping cycle "
                "(%d unconfirmed, %d pending)",
                len(self._unconfirmed),
                len(self._pending),
            )
            return [], []

        confirmed = []
        reorged = []

        # ------------------------------------------------------------------
        # Phase 1: resolve unconfirmed transactions
        # ------------------------------------------------------------------
        still_unconfirmed = []
        for utx in self._unconfirmed:
            depth = current_block - utx.submitted_block

            if depth >= TIMEOUT_DEPTH:
                logger.warning(
                    "Transaction %s never mined after %d blocks, requeuing %d events",
                    utx.tx_hash, depth, len(utx.events),
                )
                self.queuer.requeue(utx.events)
                # Include in reorged so the caller invokes clear_pending_tx.
                reorged.append(PendingAnchor(
                    tx_hash=utx.tx_hash,
                    block_number=0,
                    block_hash=b"",
                    events=utx.events,
                ))
                continue

            try:
                receipt = self.w3.eth.get_transaction_receipt(utx.tx_hash)
            except Exception:
                still_unconfirmed.append(utx)
                continue

            if receipt is None:
                still_unconfirmed.append(utx)
                continue

            if receipt.status == 0:
                logger.warning(
                    "Transaction %s reverted (status=0), requeuing %d events",
                    utx.tx_hash, len(utx.events),
                )
                self.queuer.requeue(utx.events)
                reorged.append(PendingAnchor(
                    tx_hash=utx.tx_hash,
                    block_number=receipt.blockNumber,
                    block_hash=b"",
                    events=utx.events,
                ))
                continue

            if receipt.status != 1:
                logger.warning(
                    "Transaction %s has unexpected status %d, requeuing events",
                    utx.tx_hash, receipt.status,
                )
                self.queuer.requeue(utx.events)
                reorged.append(PendingAnchor(
                    tx_hash=utx.tx_hash,
                    block_number=receipt.blockNumber,
                    block_hash=b"",
                    events=utx.events,
                ))
                continue

            try:
                block = self.w3.eth.get_block(receipt.blockNumber)
            except Exception:
                still_unconfirmed.append(utx)
                continue

            self._pending.append(PendingAnchor(
                tx_hash=utx.tx_hash,
                block_number=receipt.blockNumber,
                block_hash=block.hash,
                events=utx.events,
            ))

        self._unconfirmed = still_unconfirmed

        # ------------------------------------------------------------------
        # Phase 2: check pending (mined) transactions for confirmation / reorg
        # ------------------------------------------------------------------
        still_pending = []
        for anchor in self._pending:
            depth = current_block - anchor.block_number

            if depth < CONFIRMATION_DEPTH:
                still_pending.append(anchor)
                continue

            try:
                current_hash = self.w3.eth.get_block(anchor.block_number).hash
            except Exception:
                logger.warning(
                    "Failed to fetch block %d for anchor %s, keeping pending",
                    anchor.block_number, anchor.tx_hash,
                )
                still_pending.append(anchor)
                continue

            if current_hash == anchor.block_hash:
                confirmed.append(anchor)
                self._confirmed_count += 1
            else:
                reorged.append(anchor)
                self.queuer.requeue(anchor.events)
                logger.warning(
                    "Anchor %s reorged at depth %d, requeuing %d events",
                    anchor.tx_hash, depth, len(anchor.events),
                )

        self._pending = still_pending
        return confirmed, reorged

    @property
    def pending_count(self):
        """Number of pending (unconfirmed or awaiting confirmation) anchors."""
        return len(self._unconfirmed) + len(self._pending)

    @property
    def confirmed_count(self):
        """Number of confirmed anchors."""
        return self._confirmed_count
