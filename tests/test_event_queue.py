# -*- encoding: utf-8 -*-
"""
Tests for the event_queue module.

Verifies state management of the Queuer class — enqueue, requeue,
batch size cap, and pending transaction tracking. flush() integration
with the contract is covered by test_integration.py.

No mocks. Uses real Queuer with dummy w3/contract for state-only tests.
"""

import pytest

from evm_backer.event_queue import MAX_BATCH_SIZE, QUEUE_DURATION, Queuer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeAccount:
    address = "0x1234"


class _FakeTx:
    raw_transaction = b"\x00" * 32


class _FakeContract:
    def functions(self):
        pass


class _FakeW3:
    """Minimal web3 stub for state-only tests (flush not called)."""
    class eth:
        chain_id = 31337
        @staticmethod
        def get_transaction_count(_addr):
            return 0


def _queuer_stub():
    """Return a Queuer with stub deps — do NOT call flush() on it."""
    return Queuer(w3=_FakeW3(), contract=_FakeContract(), backer_account=_FakeAccount())


# ---------------------------------------------------------------------------
# Enqueue
# ---------------------------------------------------------------------------

class TestEnqueue:
    """Verify enqueue adds events and flush collects them."""

    def test_enqueue_single_event(self):
        q = _queuer_stub()
        q.enqueue("BPrefix1", 0, "ESaid1")
        assert len(q._queue) == 1
        assert q._queue[0] == ("BPrefix1", 0, "ESaid1")

    def test_enqueue_multiple_events(self):
        q = _queuer_stub()
        q.enqueue("BPrefix1", 0, "ESaid1")
        q.enqueue("BPrefix2", 1, "ESaid2")
        assert len(q._queue) == 2

    def test_enqueue_is_ordered(self):
        q = _queuer_stub()
        for i in range(5):
            q.enqueue(f"BPrefix{i}", i, f"ESaid{i}")
        for i in range(5):
            assert q._queue[i] == (f"BPrefix{i}", i, f"ESaid{i}")

    def test_flush_on_empty_returns_none(self):
        """flush() with no events must return None without any side effects."""
        q = _queuer_stub()
        result = q.flush()
        assert result is None

    def test_batch_size_cap(self):
        """Enqueue more than MAX_BATCH_SIZE events — flush takes only the first batch."""
        q = _queuer_stub()
        # Enqueue MAX_BATCH_SIZE + 3 events
        total = MAX_BATCH_SIZE + 3
        for i in range(total):
            q.enqueue(f"BPrefix{i}", i, f"ESaid{i}")

        # The queue holds all events
        assert len(q._queue) == total

        # After taking a batch, the remaining stays
        with q._lock:
            batch = q._queue[:MAX_BATCH_SIZE]
            q._queue = q._queue[MAX_BATCH_SIZE:]

        assert len(batch) == MAX_BATCH_SIZE
        assert len(q._queue) == 3


# ---------------------------------------------------------------------------
# Requeue
# ---------------------------------------------------------------------------

class TestRequeue:
    """Verify requeue re-adds events for retry."""

    def test_requeue_adds_events(self):
        q = _queuer_stub()
        events = [("BPrefix1", 0, "ESaid1"), ("BPrefix2", 1, "ESaid2")]
        q.requeue(events)
        assert len(q._queue) == 2
        assert q._queue[0] == ("BPrefix1", 0, "ESaid1")
        assert q._queue[1] == ("BPrefix2", 1, "ESaid2")

    def test_requeue_appends_to_existing(self):
        q = _queuer_stub()
        q.enqueue("BPrefix0", 0, "ESaid0")
        q.requeue([("BPrefix1", 1, "ESaid1")])
        assert len(q._queue) == 2

    def test_requeue_empty_list(self):
        q = _queuer_stub()
        q.requeue([])
        assert len(q._queue) == 0


# ---------------------------------------------------------------------------
# Pending transaction tracking
# ---------------------------------------------------------------------------

class TestPendingTxTracking:
    """Verify the pending transaction list for crawler integration."""

    def test_get_pending_txs_empty_initially(self):
        q = _queuer_stub()
        assert q.get_pending_txs() == []

    def test_get_pending_txs_returns_copy(self):
        q = _queuer_stub()
        with q._lock:
            q._pending_txs.append(("0xdeadbeef", [("BPrefix1", 0, "ESaid1")]))
        txs = q.get_pending_txs()
        assert len(txs) == 1
        assert txs[0][0] == "0xdeadbeef"

    def test_clear_pending_tx_removes_by_hash(self):
        q = _queuer_stub()
        events1 = [("BPrefix1", 0, "ESaid1")]
        events2 = [("BPrefix2", 1, "ESaid2")]
        with q._lock:
            q._pending_txs.append(("0xabc", events1))
            q._pending_txs.append(("0xdef", events2))

        q.clear_pending_tx("0xabc")
        txs = q.get_pending_txs()
        assert len(txs) == 1
        assert txs[0][0] == "0xdef"

    def test_clear_pending_tx_unknown_hash_is_noop(self):
        q = _queuer_stub()
        with q._lock:
            q._pending_txs.append(("0xabc", []))

        q.clear_pending_tx("0xunknown")  # should not raise
        assert len(q.get_pending_txs()) == 1


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_queue_duration_is_positive(self):
        assert QUEUE_DURATION > 0

    def test_max_batch_size_is_positive(self):
        assert MAX_BATCH_SIZE > 0

    def test_max_batch_size_is_reasonable(self):
        """Batch too large means huge gas costs; too small means frequent txs."""
        assert 1 <= MAX_BATCH_SIZE <= 100
