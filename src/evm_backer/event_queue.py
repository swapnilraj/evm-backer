# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.event_queue module

Time-based event batching for Ethereum anchoring.

Collects KERI events and publishes them in batches at regular intervals.

Reference:
  - evm-backer-spec.md section 5.5 (Queueing)
"""

import threading
import time

from web3 import Web3

from evm_backer.transactions import (
    prefix_to_bytes32,
    said_to_bytes32,
    build_anchor_tx_with_sp1_proof,
    submit_anchor_tx,
)

QUEUE_DURATION = 10  # seconds between batch submissions
MAX_BATCH_SIZE = 20  # max events per transaction


class Queuer:
    """Collects KERI events and submits them in batches to the contract.

    Events are queued as (prefix_qb64, sn, said_qb64) tuples. Every
    QUEUE_DURATION seconds (or when MAX_BATCH_SIZE is reached), the
    queued events are encoded and submitted as an anchorBatch transaction
    with an SP1 ZK proof.
    """

    def __init__(
        self, w3, contract, backer_account,
        verifier_address=None, proof_builder=None
    ):
        """Initialize the Queuer.

        Args:
            w3: Web3 instance.
            contract: web3.py Contract instance for KERIBacker.
            backer_account: eth_account.Account for gas payment.
            verifier_address: Address of the approved SP1KERIVerifier contract.
            proof_builder: Callable that takes a list of (prefix_b32, sn, said_b32)
                anchors and returns (public_values, proof_bytes). In production
                this calls generate_sp1_proof; in tests this calls make_mock_sp1_proof.
        """
        self.w3 = w3
        self.contract = contract
        self.backer_account = backer_account
        self.verifier_address = verifier_address
        self.proof_builder = proof_builder
        self._queue = []
        self._lock = threading.Lock()
        self._pending_txs = []  # list of (tx_hash, anchors) for crawler

    def enqueue(self, prefix_qb64, sn, said_qb64):
        """Add a KERI event to the queue for anchoring.

        Args:
            prefix_qb64: Controller AID prefix as qb64 string.
            sn: Event sequence number.
            said_qb64: Event SAID as qb64 string.
        """
        with self._lock:
            self._queue.append((prefix_qb64, sn, said_qb64))

    def flush(self):
        """Submit all queued events as a batch transaction.

        Returns:
            The tx hash if events were submitted, None if queue was empty.
        """
        with self._lock:
            if not self._queue:
                return None
            batch = self._queue[:MAX_BATCH_SIZE]
            self._queue = self._queue[MAX_BATCH_SIZE:]

        anchors = [
            (prefix_to_bytes32(prefix), sn, said_to_bytes32(said))
            for prefix, sn, said in batch
        ]

        # Build the ZK proof for this batch
        public_values, proof_bytes = self.proof_builder(anchors)

        signed_tx = build_anchor_tx_with_sp1_proof(
            self.w3, self.contract, self.backer_account, anchors,
            public_values=public_values,
            proof_bytes=proof_bytes,
            verifier_address=self.verifier_address,
        )
        tx_hash = submit_anchor_tx(self.w3, signed_tx)

        with self._lock:
            self._pending_txs.append((tx_hash, batch))

        return tx_hash

    def get_pending_txs(self):
        """Return a copy of pending transactions for the crawler."""
        with self._lock:
            return list(self._pending_txs)

    def clear_pending_tx(self, tx_hash):
        """Remove a confirmed or timed-out transaction from pending list."""
        with self._lock:
            self._pending_txs = [
                (h, b) for h, b in self._pending_txs if h != tx_hash
            ]

    def requeue(self, events):
        """Re-add events to the queue (e.g. after timeout or reorg).

        Args:
            events: list of (prefix_qb64, sn, said_qb64) tuples.
        """
        with self._lock:
            self._queue.extend(events)
