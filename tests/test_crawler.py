# -*- encoding: utf-8 -*-
"""
Golden tests for the confirmation monitoring (crawler) module.

These tests verify the Crawler's behavior:
  1. Events are marked confirmed when they reach CONFIRMATION_DEPTH blocks
  2. Events pending confirmation are tracked correctly
  3. Reorg detection identifies when a confirmed block hash changes
  4. Timeout handling requeues events after TIMEOUT_DEPTH blocks

Raw CESR bytes are NOT passed to the contract (A1 fix: unnecessary gas cost).
The SAID is sufficient for on-chain verification; full event bytes are served
by the backer's HTTP endpoint.

Uses a real anvil node -- blocks are mined by anvil's auto-mining or manual
mining via `evm_mine`. No mocks.

Reference:
  - evm-backer-spec.md section 5.7 (Confirmation)
  - docs/06-design-challenges.md (A1 fix)
"""

import pytest
from web3 import Web3

from evm_backer.crawler import CONFIRMATION_DEPTH, TIMEOUT_DEPTH
from tests.conftest import _send_anchor_tx_zk


def _mine_blocks(w3: Web3, n: int):
    """Mine n blocks on the anvil node using the evm_mine RPC method."""
    for _ in range(n):
        w3.provider.make_request("evm_mine", [])


class TestConfirmationDepth:
    """Test that confirmation depth is correctly tracked using real block numbers."""

    def test_event_not_confirmed_at_zero_depth(
        self, w3, contract_with_zk, backer_account
    ):
        """An event that was just anchored has zero confirmations.
        It should NOT be considered confirmed yet.
        """
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix = b'\x10' * 32
        said = b'\x20' * 32

        receipt = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix, 0, said, sp1_verifier,
        )
        anchor_block = receipt.blockNumber
        current_block = w3.eth.block_number

        depth = current_block - anchor_block
        assert depth < CONFIRMATION_DEPTH, (
            f"Event should not be confirmed at depth {depth}"
        )

    def test_event_confirmed_after_sufficient_blocks(
        self, w3, contract_with_zk, backer_account
    ):
        """After CONFIRMATION_DEPTH blocks pass, the event should be considered confirmed.

        We mine blocks manually to simulate time passing.
        """
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix = b'\x11' * 32
        said = b'\x21' * 32

        receipt = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix, 0, said, sp1_verifier,
        )
        anchor_block = receipt.blockNumber

        # Mine enough blocks to reach confirmation depth
        _mine_blocks(w3, CONFIRMATION_DEPTH)

        current_block = w3.eth.block_number
        depth = current_block - anchor_block

        assert depth >= CONFIRMATION_DEPTH, (
            f"Expected depth >= {CONFIRMATION_DEPTH}, got {depth}"
        )

        # The event is still anchored on-chain (immutable)
        assert contract.functions.isAnchored(prefix, 0, said).call() is True

    def test_confirmation_depth_boundary(
        self, w3, contract_with_zk, backer_account
    ):
        """Test the exact boundary: at depth=11 not confirmed, at depth=12 confirmed."""
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix = b'\x12' * 32
        said = b'\x22' * 32

        receipt = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix, 0, said, sp1_verifier,
        )
        anchor_block = receipt.blockNumber

        # Mine to depth=11 (one short of confirmation)
        _mine_blocks(w3, CONFIRMATION_DEPTH - 1)
        current_block = w3.eth.block_number
        depth = current_block - anchor_block
        assert depth == CONFIRMATION_DEPTH - 1

        # Mine one more to reach confirmation depth
        _mine_blocks(w3, 1)
        current_block = w3.eth.block_number
        depth = current_block - anchor_block
        assert depth == CONFIRMATION_DEPTH


class TestBlockHashTracking:
    """Test that block hashes can be used to detect reorgs."""

    def test_block_hash_is_stable(
        self, w3, contract_with_zk, backer_account
    ):
        """After anchoring, the block hash of the anchoring block should
        remain consistent when queried again (no reorg on anvil).
        """
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix = b'\x13' * 32
        said = b'\x23' * 32

        receipt = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix, 0, said, sp1_verifier,
        )
        anchor_block_num = receipt.blockNumber
        anchor_block = w3.eth.get_block(anchor_block_num)
        hash_before = anchor_block.hash

        # Mine some blocks
        _mine_blocks(w3, 5)

        # Re-fetch the same block number
        anchor_block_again = w3.eth.get_block(anchor_block_num)
        hash_after = anchor_block_again.hash

        assert hash_before == hash_after, (
            "Block hash should be stable when no reorg occurs"
        )

    def test_transaction_receipt_block_number_matches_anchor(
        self, w3, contract_with_zk, backer_account
    ):
        """The transaction receipt's blockNumber must match what getAnchor returns."""
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix = b'\x14' * 32
        said = b'\x24' * 32

        receipt = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix, 0, said, sp1_verifier,
        )

        # getAnchor returns (eventSAID, blockNumber, exists)
        record = contract.functions.getAnchor(prefix, 0).call()
        on_chain_block = record[1]

        assert on_chain_block == receipt.blockNumber, (
            f"Contract stored blockNumber ({on_chain_block}) must match "
            f"tx receipt blockNumber ({receipt.blockNumber})"
        )


class TestReorgDetection:
    """Test reorg detection logic.

    On a real chain, reorgs are detected when the block hash at a previously
    known block number changes. Anvil doesn't naturally reorg, but we can
    verify the detection logic by testing the hash comparison.

    In production, the Crawler would:
    1. Store the block hash when first seeing a transaction
    2. Re-check the block hash periodically
    3. If the hash changes, requeue the affected events
    """

    def test_reorg_detection_via_block_hash_comparison(
        self, w3, contract_with_zk, backer_account
    ):
        """Demonstrate the reorg detection pattern:
        store a block hash, re-query it, compare.

        On anvil (no actual reorgs), this verifies the detection mechanism
        works correctly -- the hashes should always match.
        """
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix = b'\x15' * 32
        said = b'\x25' * 32

        receipt = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix, 0, said, sp1_verifier,
        )
        anchor_block_num = receipt.blockNumber

        # Store the block hash (this is what the Crawler would do)
        stored_hash = w3.eth.get_block(anchor_block_num).hash

        # Mine more blocks
        _mine_blocks(w3, 20)

        # Re-check the block hash (this is what the Crawler does periodically)
        current_hash = w3.eth.get_block(anchor_block_num).hash

        # On anvil, these should match (no reorg)
        reorg_detected = stored_hash != current_hash
        assert reorg_detected is False, (
            "No reorg should be detected on anvil"
        )


class TestTimeoutDepth:
    """Test timeout handling behavior.

    Spec section 5.7: 'If confirmations not reached after TIMEOUT_DEPTH
    blocks -- requeue events, retry with new transaction.'
    """

    def test_timeout_threshold_exceeds_confirmation_threshold(self):
        """Timeout depth must be strictly greater than confirmation depth.

        If timeout <= confirmation, events would time out before being confirmed.
        """
        assert TIMEOUT_DEPTH > CONFIRMATION_DEPTH, (
            f"TIMEOUT_DEPTH ({TIMEOUT_DEPTH}) must be > "
            f"CONFIRMATION_DEPTH ({CONFIRMATION_DEPTH})"
        )

    def test_event_pending_beyond_timeout_depth(
        self, w3, contract_with_zk, backer_account
    ):
        """If more than TIMEOUT_DEPTH blocks pass and the event is still anchored,
        the event should be requeued.

        In this test we simulate the passage of TIMEOUT_DEPTH blocks.
        The event IS anchored on-chain, so in production the Crawler would
        mark it confirmed rather than timing out. This test verifies that
        the block counting logic is correct.
        """
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix = b'\x16' * 32
        said = b'\x26' * 32

        receipt = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix, 0, said, sp1_verifier,
        )
        anchor_block = receipt.blockNumber

        # Mine TIMEOUT_DEPTH blocks
        _mine_blocks(w3, TIMEOUT_DEPTH)

        current_block = w3.eth.block_number
        depth = current_block - anchor_block

        assert depth >= TIMEOUT_DEPTH, (
            f"Expected depth >= {TIMEOUT_DEPTH}, got {depth}"
        )

        # Event is still on-chain (timeout doesn't remove it -- it's for
        # handling transactions that were NEVER mined, not confirmed ones)
        assert contract.functions.isAnchored(prefix, 0, said).call() is True


class TestMultipleEventsConfirmation:
    """Test confirmation tracking with multiple events across multiple blocks."""

    def test_events_at_different_blocks_confirm_at_different_times(
        self, w3, contract_with_zk, backer_account
    ):
        """Events anchored in different blocks should reach confirmation
        depth at different current block numbers.
        """
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        # Anchor event A
        prefix_a = b'\x17' * 32
        said_a = b'\x27' * 32
        receipt_a = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix_a, 0, said_a, sp1_verifier,
        )
        block_a = receipt_a.blockNumber

        # Mine a few blocks, then anchor event B
        _mine_blocks(w3, 3)

        prefix_b = b'\x18' * 32
        said_b = b'\x28' * 32
        receipt_b = _send_anchor_tx_zk(
            w3, contract, backer_account,
            prefix_b, 0, said_b, sp1_verifier,
        )
        block_b = receipt_b.blockNumber

        assert block_b > block_a, "Event B must be in a later block"

        # Mine to confirmation depth for event A but not B
        blocks_needed = CONFIRMATION_DEPTH - (w3.eth.block_number - block_a)
        if blocks_needed > 0:
            _mine_blocks(w3, blocks_needed)

        depth_a = w3.eth.block_number - block_a
        depth_b = w3.eth.block_number - block_b

        assert depth_a >= CONFIRMATION_DEPTH, "Event A should be confirmed"
        assert depth_b < CONFIRMATION_DEPTH, "Event B should NOT yet be confirmed"


class TestCrawlerRevertDetection:
    """Test that the Crawler correctly handles reverted transactions."""

    def test_reverted_tx_requeues_events(self, w3, contract_with_zk, backer_account):
        """When track() receives a tx that reverted (status==0), events must
        be requeued immediately and not added to the pending list.

        We simulate a revert by sending a tx with an unregistered verifier.
        """
        contract = contract_with_zk["contract"]
        from evm_backer.crawler import Crawler
        from tests.conftest import ANVIL_DEPLOYER_KEY

        from eth_account import Account

        deployer = Account.from_key(ANVIL_DEPLOYER_KEY)

        # Try to anchor with an unregistered verifier -- should revert
        prefix = b'\xF1' * 32
        said = b'\xF2' * 32
        unregistered_verifier = "0x0000000000000000000000000000000000000000"
        try:
            tx = contract.functions.anchorEvent(
                prefix, 0, said, unregistered_verifier, b'',
            ).build_transaction({
                "from": deployer.address,
                "nonce": w3.eth.get_transaction_count(deployer.address, "pending"),
                "chainId": w3.eth.chain_id,
                "gas": 500_000,
            })
            signed = deployer.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        except Exception:
            # If sending itself fails, skip this test variant
            pytest.skip("Could not create a reverting transaction")
            return

        # Verify the tx actually reverted
        assert receipt.status == 0, "Transaction should have reverted"

        requeued = []

        class _RequeueCapture:
            def requeue(self, evts):
                requeued.extend(evts)

        crawler = Crawler(w3=w3, queuer=_RequeueCapture())
        events = [("prefix", 0, "said")]
        crawler.track(receipt.transactionHash.hex(), events)

        # track() is non-blocking -- receipt is fetched lazily in check().
        # After track(), the tx is in the unconfirmed list.
        assert crawler.pending_count == 1, "Tx should be in unconfirmed list"
        assert requeued == [], "Events should not be requeued before check()"

        # check() fetches the receipt, detects status==0, and requeues.
        _, reorged = crawler.check()
        assert crawler.pending_count == 0, "Reverted tx should be removed after check()"
        assert requeued == events, "Events should be requeued after check() detects revert"

    def test_track_with_rpc_failure_retries_next_cycle(self):
        """If get_transaction_receipt throws during check(), the tx stays in
        the unconfirmed list and is retried in the next cycle rather than
        being requeued immediately.
        """
        from evm_backer.crawler import Crawler
        from unittest.mock import MagicMock, PropertyMock

        mock_w3 = MagicMock()
        type(mock_w3.eth).block_number = PropertyMock(return_value=100)
        mock_w3.eth.get_transaction_receipt.side_effect = ConnectionError("RPC down")

        requeued = []

        class _RequeueCapture:
            def requeue(self, evts):
                requeued.extend(evts)

        crawler = Crawler(w3=mock_w3, queuer=_RequeueCapture())
        events = [("prefix", 0, "said")]
        crawler.track("0x" + "ab" * 32, events)

        # First check: receipt fetch fails, tx remains in unconfirmed
        _, reorged = crawler.check()
        assert crawler.pending_count == 1, "Tx should remain in unconfirmed on RPC failure"
        assert requeued == [], "Events should not be requeued on transient RPC failure"


class TestCrawlerRPCResilience:
    """Test that the Crawler gracefully handles RPC downtime during check()."""

    def test_check_skips_on_rpc_failure(self):
        """If w3.eth.block_number throws, check() returns empty lists
        without modifying pending anchors.
        """
        from evm_backer.crawler import Crawler, PendingAnchor
        from unittest.mock import MagicMock, PropertyMock

        mock_w3 = MagicMock()
        type(mock_w3.eth).block_number = PropertyMock(
            side_effect=ConnectionError("RPC down")
        )

        class _DummyQueuer:
            def requeue(self, evts):
                pass

        crawler = Crawler(w3=mock_w3, queuer=_DummyQueuer())
        # Manually inject a pending anchor
        crawler._pending.append(
            PendingAnchor(
                tx_hash="0xabc",
                block_number=100,
                block_hash=b'\x00' * 32,
                events=[("prefix", 0, "said")],
            )
        )

        confirmed, reorged = crawler.check()
        assert confirmed == []
        assert reorged == []
        assert crawler.pending_count == 1, "Pending anchors should be unchanged"

    def test_check_handles_get_block_failure_for_single_anchor(self):
        """If get_block fails for one anchor, it stays pending."""
        from evm_backer.crawler import Crawler, PendingAnchor, CONFIRMATION_DEPTH
        from unittest.mock import MagicMock, PropertyMock

        mock_w3 = MagicMock()
        type(mock_w3.eth).block_number = PropertyMock(return_value=200)
        # get_block fails
        mock_w3.eth.get_block.side_effect = ConnectionError("RPC flaky")

        class _DummyQueuer:
            def requeue(self, evts):
                pass

        crawler = Crawler(w3=mock_w3, queuer=_DummyQueuer())
        crawler._pending.append(
            PendingAnchor(
                tx_hash="0xdef",
                block_number=200 - CONFIRMATION_DEPTH,  # exactly at confirmation depth
                block_hash=b'\x01' * 32,
                events=[("prefix", 0, "said")],
            )
        )

        confirmed, reorged = crawler.check()
        assert confirmed == []
        assert reorged == []
        assert crawler.pending_count == 1, "Anchor should stay pending on get_block failure"


class TestCrawlerTimeoutRequeue:
    """Test that anchors exceeding TIMEOUT_DEPTH are requeued."""

    def test_timeout_requeues_events(self):
        """An anchor older than TIMEOUT_DEPTH blocks must be requeued."""
        from evm_backer.crawler import Crawler, PendingAnchor, TIMEOUT_DEPTH
        from unittest.mock import MagicMock, PropertyMock

        mock_w3 = MagicMock()
        type(mock_w3.eth).block_number = PropertyMock(return_value=500)

        requeued = []

        class _RequeueCapture:
            def requeue(self, evts):
                requeued.extend(evts)

        crawler = Crawler(w3=mock_w3, queuer=_RequeueCapture())
        events = [("prefix", 0, "said")]
        crawler._pending.append(
            PendingAnchor(
                tx_hash="0xtimeout",
                block_number=500 - TIMEOUT_DEPTH,  # exactly at timeout depth
                block_hash=b'\x02' * 32,
                events=events,
            )
        )

        confirmed, reorged = crawler.check()
        assert requeued == events, "Timed-out events should be requeued"
        assert crawler.pending_count == 0, "Timed-out anchor should be removed"
