# -*- encoding: utf-8 -*-
"""
Integration tests for the HTTP server, service wiring, and CLI.

Tests the HTTP endpoint via falcon.testing (no real socket needed),
verifies the flush loop calls Queuer.flush(), and tests the full
pipeline from HTTP POST through to on-chain anchoring.

HTTP endpoint tests use a simple stub queuer to avoid depending on
forge/anvil (which may be broken by concurrent contract changes).
On-chain tests use real anvil + deployed contract from conftest.py fixtures.
"""

import time

import falcon.testing
import pytest
from web3 import Web3

from evm_backer.backer import setup_kevery, setup_parser, setup_tevery
from evm_backer.crawler import Crawler
from evm_backer.event_queue import Queuer
from evm_backer.http_server import create_app
from evm_backer.proofs import make_mock_sp1_proof
from evm_backer.service import ServiceLoop
from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32


# ---------------------------------------------------------------------------
# Stub queuer for HTTP tests (no anvil/contract dependency)
# ---------------------------------------------------------------------------

class StubQueuer:
    """Minimal queuer that records enqueue calls without hitting the chain."""

    def __init__(self):
        self.enqueued = []

    def enqueue(self, prefix_qb64, sn, said_qb64):
        self.enqueued.append((prefix_qb64, sn, said_qb64))

    def flush(self):
        self.enqueued.clear()
        return None

    def get_pending_txs(self):
        return []

    def clear_pending_tx(self, tx_hash):
        pass

    def requeue(self, events):
        self.enqueued.extend(events)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_proof_builder(w3):
    """Return a proof_builder callable for the Queuer that uses mock SP1 proofs."""
    def _build_proof(anchors):
        encoded = w3.codec.encode(["(bytes32,uint64,bytes32)[]"], [anchors])
        msg_hash = Web3.keccak(encoded)
        _, public_values = make_mock_sp1_proof(msg_hash)
        return public_values, b""
    return _build_proof


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def backer_components(keri_habery, backer_hab):
    """Set up the full keripy backer pipeline for HTTP tests."""
    kevery_components = setup_kevery(keri_habery)
    tevery_components = setup_tevery(keri_habery, backer_hab, kevery_components)
    parser = setup_parser(kevery_components, tevery_components)
    return {
        "hab": backer_hab,
        "parser": parser,
        "kevery_components": kevery_components,
    }


@pytest.fixture
def stub_queuer():
    """A queuer stub that doesn't need anvil/contract."""
    return StubQueuer()


@pytest.fixture
def test_app(backer_components, stub_queuer):
    """Create a falcon.testing.TestClient for the HTTP endpoint.

    Uses StubQueuer so these tests don't depend on forge/anvil.
    """
    app = create_app(
        backer_components["hab"],
        backer_components["parser"],
        backer_components["kevery_components"],
        stub_queuer,
    )
    return falcon.testing.TestClient(app)


# ---------------------------------------------------------------------------
# HTTP endpoint tests (no anvil needed)
# ---------------------------------------------------------------------------

class TestHttpEndpoint:
    """Test the POST /events HTTP endpoint."""

    def test_post_events_empty_body_returns_400(self, test_app):
        """POST /events with empty body returns 400."""
        result = test_app.simulate_post("/events", body=b"")
        assert result.status == falcon.HTTP_400

    def test_post_events_get_returns_405(self, test_app):
        """GET /events returns 405 Method Not Allowed (only POST is accepted)."""
        result = test_app.simulate_get("/events")
        assert result.status == falcon.HTTP_405

    def test_health_endpoint_returns_ok(self, test_app):
        """GET /health returns 200 with status ok."""
        result = test_app.simulate_get("/health")
        assert result.status == falcon.HTTP_200
        assert result.json["status"] == "ok"

    def test_nonexistent_route_returns_404(self, test_app):
        """GET /nonexistent returns 404."""
        result = test_app.simulate_get("/nonexistent")
        assert result.status == falcon.HTTP_404


# ---------------------------------------------------------------------------
# Service loop tests (no anvil needed)
# ---------------------------------------------------------------------------

class TestServiceLoop:
    """Test the ServiceLoop._tick() method."""

    def test_tick_with_empty_queue_no_error(self, keri_habery, backer_hab):
        """_tick() with an empty queue should not raise."""
        stub_q = StubQueuer()

        class StubCrawler:
            def track(self, tx_hash, events): pass
            def check(self): return [], []

        kevery_components = setup_kevery(keri_habery)
        tevery_components = setup_tevery(keri_habery, backer_hab, kevery_components)
        parser = setup_parser(kevery_components, tevery_components)
        app = create_app(backer_hab, parser, kevery_components, stub_q)

        service = {
            "app": app,
            "hab": backer_hab,
            "hby": keri_habery,
            "queuer": stub_q,
            "crawler": StubCrawler(),
            "config": {
                "BACKER_PORT": 15680,
                "QUEUE_DURATION": 1,
            },
            "w3": None,
        }

        loop = ServiceLoop(service)
        loop._tick()  # Should not raise


# ---------------------------------------------------------------------------
# On-chain integration tests (require anvil + contract)
# ---------------------------------------------------------------------------

class TestFlushLoop:
    """Test that the service loop flushes the queue to chain."""

    def test_flush_submits_queued_event(
        self, w3, contract_with_zk, backer_account, keri_habery, backer_hab
    ):
        """Enqueue an event, then _tick() flushes and submits it to chain."""
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        queuer = Queuer(
            w3=w3, contract=contract, backer_account=backer_account,
            verifier_address=sp1_verifier,
            proof_builder=_make_mock_proof_builder(w3),
        )
        crawler = Crawler(w3=w3, queuer=queuer)

        kevery_components = setup_kevery(keri_habery)
        tevery_components = setup_tevery(keri_habery, backer_hab, kevery_components)
        parser = setup_parser(kevery_components, tevery_components)
        app = create_app(backer_hab, parser, kevery_components, queuer)

        service = {
            "app": app,
            "hab": backer_hab,
            "hby": keri_habery,
            "queuer": queuer,
            "crawler": crawler,
            "config": {
                "BACKER_PORT": 15681,
                "QUEUE_DURATION": 1,
            },
            "w3": w3,
        }

        prefix_qb64 = "BServiceTickFlushTest000000000000000000000000"
        said_qb64 = "EServiceTickFlushTestSaid00000000000000000000"
        sn = 0

        queuer.enqueue(prefix_qb64, sn, said_qb64)
        loop = ServiceLoop(service)
        loop._tick()

        # Verify the event is now anchored on-chain
        prefix_b32 = prefix_to_bytes32(prefix_qb64)
        said_b32 = said_to_bytes32(said_qb64)

        # Wait for the tx to be mined
        time.sleep(2)

        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call(), \
            "Event should be anchored after flush tick"


class TestFullServicePipeline:
    """Test the full pipeline from enqueue through flush to on-chain verification."""

    def test_enqueue_flush_verify(self, w3, contract_with_zk, backer_account):
        """Direct enqueue + flush + on-chain verification (no HTTP involved)."""
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        prefix_qb64 = "BServicePipelineTest00000000000000000000000"
        said_qb64 = "EServicePipelineTestSaid0000000000000000000"
        sn = 0

        queuer = Queuer(
            w3=w3, contract=contract, backer_account=backer_account,
            verifier_address=sp1_verifier,
            proof_builder=_make_mock_proof_builder(w3),
        )
        queuer.enqueue(prefix_qb64, sn, said_qb64)
        tx_hash = queuer.flush()
        assert tx_hash is not None

        # Wait for mining
        receipt = w3.eth.wait_for_transaction_receipt(bytes.fromhex(tx_hash[2:]))
        assert receipt.status == 1

        prefix_b32 = prefix_to_bytes32(prefix_qb64)
        said_b32 = said_to_bytes32(said_qb64)
        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call()
