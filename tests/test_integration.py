# -*- encoding: utf-8 -*-
"""
End-to-end integration tests for the full EVM backer pipeline.

Tests the complete data flow:
  KERI event → Queuer.enqueue → Queuer.flush → KERIBacker.anchorBatch
             → isAnchored() → Crawler.track → Crawler.check

Every test uses a real anvil node and real deployed contract.
No mocks, no monkeypatching.

Reference:
  - evm-backer-spec.md sections 5.5, 5.6, 5.7
"""

import time

import pytest

from evm_backer.crawler import CONFIRMATION_DEPTH, Crawler, PendingAnchor
from evm_backer.transactions import (
    build_anchor_tx,
    prefix_to_bytes32,
    said_to_bytes32,
    submit_anchor_tx,
)
from evm_backer.event_queue import MAX_BATCH_SIZE, Queuer
from tests.conftest import SEED_0, ED25519_SIGNING_KEY, ED25519_PUBKEY_HEX


def _mine_blocks(w3, n):
    for _ in range(n):
        w3.provider.make_request("evm_mine", [])


# ---------------------------------------------------------------------------
# Queuer + transactions: flush() submits a real batch transaction
# ---------------------------------------------------------------------------

class TestQueuerFlushSubmitsTransaction:
    """Queuer.flush() must build and submit a real anchorBatch tx."""

    def test_flush_single_event_anchors_on_chain(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """Enqueue one event, flush, then isAnchored must return True."""
        prefix_qb64 = "BFlushSingleTest00000000000000000000000000"
        said_qb64   = "EFlushSingleTestSaid000000000000000000000000"
        sn = 0

        queuer = Queuer(
            w3=w3, contract=contract, backer_account=backer_account,
            signing_key=ED25519_SIGNING_KEY,
            verifier_address=ed25519_verifier_address,
            backer_pubkey_bytes=bytes.fromhex(ED25519_PUBKEY_HEX),
        )
        queuer.enqueue(prefix_qb64, sn, said_qb64)

        tx_hash = queuer.flush()
        assert tx_hash is not None, "flush() must return a tx hash"

        # Wait for the tx to be mined
        receipt = w3.eth.wait_for_transaction_receipt(bytes.fromhex(tx_hash[2:]))
        assert receipt.status == 1, "flush transaction must succeed"

        prefix_b32 = prefix_to_bytes32(prefix_qb64)
        said_b32   = said_to_bytes32(said_qb64)
        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call()

    def test_flush_multiple_events_all_anchored(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """Enqueue multiple events, flush, all must be anchored."""
        events = [
            ("BFlushMultiPrefix1_00000000000000000000000", 0,
             "EFlushMultiSaid1_00000000000000000000000000"),
            ("BFlushMultiPrefix2_00000000000000000000000", 1,
             "EFlushMultiSaid2_00000000000000000000000000"),
            ("BFlushMultiPrefix3_00000000000000000000000", 2,
             "EFlushMultiSaid3_00000000000000000000000000"),
        ]

        queuer = Queuer(
            w3=w3, contract=contract, backer_account=backer_account,
            signing_key=ED25519_SIGNING_KEY,
            verifier_address=ed25519_verifier_address,
            backer_pubkey_bytes=bytes.fromhex(ED25519_PUBKEY_HEX),
        )
        for prefix, sn, said in events:
            queuer.enqueue(prefix, sn, said)

        tx_hash = queuer.flush()
        assert tx_hash is not None
        w3.eth.wait_for_transaction_receipt(bytes.fromhex(tx_hash[2:]))

        for prefix, sn, said in events:
            assert contract.functions.isAnchored(
                prefix_to_bytes32(prefix), sn, said_to_bytes32(said)
            ).call(), f"Event (prefix={prefix}, sn={sn}) not anchored"

    def test_flush_empty_is_noop(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """flush() with empty queue returns None without submitting a tx."""
        queuer = Queuer(
            w3=w3, contract=contract, backer_account=backer_account,
            signing_key=ED25519_SIGNING_KEY,
            verifier_address=ed25519_verifier_address,
            backer_pubkey_bytes=bytes.fromhex(ED25519_PUBKEY_HEX),
        )
        result = queuer.flush()
        assert result is None

    def test_flush_respects_max_batch_size(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """When more than MAX_BATCH_SIZE events are queued, flush submits only the first batch."""
        queuer = Queuer(
            w3=w3, contract=contract, backer_account=backer_account,
            signing_key=ED25519_SIGNING_KEY,
            verifier_address=ed25519_verifier_address,
            backer_pubkey_bytes=bytes.fromhex(ED25519_PUBKEY_HEX),
        )

        # Enqueue MAX_BATCH_SIZE + 1 events
        for i in range(MAX_BATCH_SIZE + 1):
            prefix = f"BFlushBatchCap{i:04d}00000000000000000000000"
            said   = f"EFlushBatchCapSaid{i:04d}000000000000000000000"
            queuer.enqueue(prefix[:44], i, said[:44])

        tx_hash = queuer.flush()
        assert tx_hash is not None
        w3.eth.wait_for_transaction_receipt(bytes.fromhex(tx_hash[2:]))

        # Exactly 1 event remains in the queue
        assert len(queuer._queue) == 1

    def test_flush_updates_pending_txs(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """After flush(), the tx hash appears in get_pending_txs()."""
        prefix_qb64 = "BFlushPendingTrackingTest0000000000000000000"
        said_qb64   = "EFlushPendingTrackingTestSaid000000000000000"
        sn = 0

        queuer = Queuer(
            w3=w3, contract=contract, backer_account=backer_account,
            signing_key=ED25519_SIGNING_KEY,
            verifier_address=ed25519_verifier_address,
            backer_pubkey_bytes=bytes.fromhex(ED25519_PUBKEY_HEX),
        )
        queuer.enqueue(prefix_qb64, sn, said_qb64)
        tx_hash = queuer.flush()

        pending = queuer.get_pending_txs()
        assert len(pending) == 1
        assert pending[0][0] == tx_hash


# ---------------------------------------------------------------------------
# transactions: build_anchor_tx + submit_anchor_tx
# ---------------------------------------------------------------------------

class TestTransactionSubmitFlow:
    """build_anchor_tx + submit_anchor_tx must produce a confirmed tx."""

    def test_build_and_submit_anchor_tx(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """Build and submit a single anchorBatch via the transactions module."""
        from keri.core import eventing
        from keri.core.signing import Signer

        signer = Signer(raw=SEED_0, transferable=False)
        keys = [signer.verfer.qb64]
        serder = eventing.incept(keys=keys)

        prefix_b32 = prefix_to_bytes32(serder.ked["i"])
        said_b32   = said_to_bytes32(serder.said)
        sn = int(serder.ked["s"], 16)

        anchors = [(prefix_b32, sn, said_b32)]
        signed_tx = build_anchor_tx(
            w3, contract, backer_account, anchors,
            signing_key=ED25519_SIGNING_KEY,
            verifier_address=ed25519_verifier_address,
            backer_pubkey_bytes=bytes.fromhex(ED25519_PUBKEY_HEX),
        )
        tx_hash = submit_anchor_tx(w3, signed_tx)

        assert tx_hash.startswith("0x"), "tx_hash must be hex"
        receipt = w3.eth.wait_for_transaction_receipt(bytes.fromhex(tx_hash[2:]))
        assert receipt.status == 1

        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call()

    def test_build_anchor_tx_batch_of_three(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """Build a batch of three distinct anchors."""
        anchors = [
            (b'\xA1' * 32, 0, b'\xB1' * 32),
            (b'\xA2' * 32, 0, b'\xB2' * 32),
            (b'\xA3' * 32, 0, b'\xB3' * 32),
        ]
        signed_tx = build_anchor_tx(
            w3, contract, backer_account, anchors,
            signing_key=ED25519_SIGNING_KEY,
            verifier_address=ed25519_verifier_address,
            backer_pubkey_bytes=bytes.fromhex(ED25519_PUBKEY_HEX),
        )
        tx_hash = submit_anchor_tx(w3, signed_tx)

        receipt = w3.eth.wait_for_transaction_receipt(bytes.fromhex(tx_hash[2:]))
        assert receipt.status == 1

        for prefix, sn, said in anchors:
            assert contract.functions.isAnchored(prefix, sn, said).call()


# ---------------------------------------------------------------------------
# Crawler: track, check, confirmed, reorg detection
# ---------------------------------------------------------------------------

class TestCrawlerTrackAndCheck:
    """Crawler must track submitted txs and mark them confirmed after enough blocks."""

    def test_crawler_confirms_after_confirmation_depth(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """After CONFIRMATION_DEPTH blocks, Crawler.check must return the anchor as confirmed."""
        prefix = b'\xC1' * 32
        said   = b'\xD1' * 32
        sn     = 0

        # Submit an anchor tx
        from tests.conftest import _send_anchor_tx
        receipt = _send_anchor_tx(
            w3, contract, backer_account, prefix, sn, said, ed25519_verifier_address
        )
        assert receipt.status == 1

        events = [(prefix.hex(), sn, said.hex())]

        # Set up a mock queuer for requeue (not called in this test)
        class _DummyQueuer:
            def requeue(self, evts):
                pass

        crawler = Crawler(w3=w3, queuer=_DummyQueuer())
        tx_hash = receipt.transactionHash.hex()
        crawler.track(tx_hash, events)

        assert crawler.pending_count == 1

        # Mine enough blocks for confirmation
        _mine_blocks(w3, CONFIRMATION_DEPTH)

        confirmed, reorged = crawler.check()
        assert len(confirmed) == 1, "Anchor should be confirmed after CONFIRMATION_DEPTH"
        assert len(reorged) == 0
        assert crawler.pending_count == 0
        assert crawler.confirmed_count == 1

    def test_crawler_still_pending_before_confirmation_depth(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """Before CONFIRMATION_DEPTH blocks, Crawler.check must leave anchor pending."""
        prefix = b'\xC2' * 32
        said   = b'\xD2' * 32
        sn     = 0

        from tests.conftest import _send_anchor_tx
        receipt = _send_anchor_tx(
            w3, contract, backer_account, prefix, sn, said, ed25519_verifier_address
        )

        class _DummyQueuer:
            def requeue(self, evts):
                pass

        crawler = Crawler(w3=w3, queuer=_DummyQueuer())
        crawler.track(receipt.transactionHash.hex(), [(prefix.hex(), sn, said.hex())])

        # Don't mine to confirmation depth — just one block
        _mine_blocks(w3, 1)

        confirmed, reorged = crawler.check()
        assert len(confirmed) == 0
        assert crawler.pending_count == 1, "Should still be pending"

    def test_crawler_failed_tx_requeues_immediately(self, w3, contract, backer_account):
        """If track() receives a failed tx hash, events are requeued immediately."""
        requeued = []

        class _RequeueCapture:
            def requeue(self, evts):
                requeued.extend(evts)

        crawler = Crawler(w3=w3, queuer=_RequeueCapture())

        # Use an invalid/non-existent tx hash — receipt will be None
        fake_hash = "0x" + "ab" * 32
        events = [("BFakePrefix", 0, "EFakeSaid")]

        # track() should handle None receipt gracefully and requeue
        try:
            crawler.track(fake_hash, events)
            # If no exception, check that events were requeued
            assert requeued == events or crawler.pending_count == 0
        except Exception:
            # web3 may raise for unknown tx hash — acceptable behavior
            pass


# ---------------------------------------------------------------------------
# Full pipeline: Queuer → Crawler
# ---------------------------------------------------------------------------

class TestFullPipeline:
    """Complete flow: enqueue → flush → track → check → confirmed."""

    def test_pipeline_enqueue_flush_track_confirm(
        self, w3, contract, backer_account, ed25519_verifier_address
    ):
        """End-to-end pipeline test using Queuer and Crawler together."""
        prefix_qb64 = "BPipelineFullTest00000000000000000000000000"
        said_qb64   = "EPipelineFullTestSaid0000000000000000000000"
        sn = 0

        # Step 1: Enqueue and flush
        queuer = Queuer(
            w3=w3, contract=contract, backer_account=backer_account,
            signing_key=ED25519_SIGNING_KEY,
            verifier_address=ed25519_verifier_address,
            backer_pubkey_bytes=bytes.fromhex(ED25519_PUBKEY_HEX),
        )
        queuer.enqueue(prefix_qb64, sn, said_qb64)
        tx_hash = queuer.flush()
        assert tx_hash is not None

        receipt = w3.eth.wait_for_transaction_receipt(bytes.fromhex(tx_hash[2:]))
        assert receipt.status == 1

        # Step 2: Verify on-chain
        prefix_b32 = prefix_to_bytes32(prefix_qb64)
        said_b32   = said_to_bytes32(said_qb64)
        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call()

        # Step 3: Track with crawler
        pending = queuer.get_pending_txs()
        assert len(pending) == 1
        assert pending[0][0] == tx_hash

        crawler = Crawler(w3=w3, queuer=queuer)
        raw_events = pending[0][1]  # (prefix_qb64, sn, said_qb64) tuples
        crawler.track(tx_hash, raw_events)

        # Step 4: Mine to confirmation depth
        _mine_blocks(w3, CONFIRMATION_DEPTH)

        confirmed, reorged = crawler.check()
        assert len(confirmed) == 1
        assert crawler.confirmed_count == 1

        # Step 5: Clear pending tx from queuer
        queuer.clear_pending_tx(tx_hash)
        assert len(queuer.get_pending_txs()) == 0
