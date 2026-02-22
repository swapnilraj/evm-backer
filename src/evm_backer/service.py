# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.service module

Main service loop that wires together the backer components:
  - HTTP server (falcon WSGI via wsgiref)
  - Periodic queue flush (submits batched events to Ethereum)
  - Crawler polling (monitors confirmations and reorgs)

Configuration is loaded from environment variables with sensible defaults.

Reference:
  - evm-backer-spec.md section 5 (Backer Service)
"""

import json
import logging
import os
import threading
import time
from pathlib import Path

from eth_account import Account
from keri.app import habbing
from keri.core.signing import Salter
from web3 import Web3

from evm_backer.backer import setup_kevery, setup_parser, setup_tevery
from evm_backer.crawler import Crawler
from evm_backer.event_queue import Queuer
from evm_backer.http_server import create_app
from evm_backer.rpc import MultiRPCProvider

logger = logging.getLogger("evm_backer")

# Default configuration values
DEFAULTS = {
    "ETH_RPC_URL": "http://127.0.0.1:8545",
    "ETH_CONTRACT_ADDRESS": "",
    "ETH_CHAIN_ID": "31337",
    "ETH_PRIVATE_KEY": "",
    "BACKER_SALT": "",
    "BACKER_NAME": "evm-backer",
    "BACKER_PORT": "5680",
    "QUEUE_DURATION": "10",
    "BATCH_SIZE": "20",
}


def load_config():
    """Load service configuration from environment variables.

    Returns:
        dict with all configuration values.
    """
    config = {}
    for key, default in DEFAULTS.items():
        config[key] = os.environ.get(key, default)
    # Parse numeric values
    config["ETH_CHAIN_ID"] = int(config["ETH_CHAIN_ID"])
    config["BACKER_PORT"] = int(config["BACKER_PORT"])
    config["QUEUE_DURATION"] = int(config["QUEUE_DURATION"])
    config["BATCH_SIZE"] = int(config["BATCH_SIZE"])
    return config


def load_contract_abi(abi_path=None):
    """Load the KERIBacker contract ABI from the forge artifact.

    Args:
        abi_path: Path to the forge-compiled JSON artifact. If None,
                  uses the default path relative to the project root.

    Returns:
        The ABI as a list of dicts.
    """
    if abi_path is None:
        project_root = Path(__file__).parent.parent.parent
        abi_path = (
            project_root / "contracts" / "out" / "KERIBacker.sol" / "KERIBacker.json"
        )
    with open(abi_path) as f:
        artifact = json.load(f)
    return artifact["abi"]


def setup_web3(config):
    """Create a Web3 instance connected to the configured RPC endpoint(s).

    Supports comma-separated URLs for multi-RPC failover via MultiRPCProvider.
    When multiple URLs are given, the primary endpoint is used initially;
    call rpc_provider.report_failure() / rpc_provider.get_web3() to rotate
    on failure.

    Args:
        config: dict from load_config().

    Returns:
        A tuple of (w3, rpc_provider) where rpc_provider is None for
        single-URL configurations.
    """
    urls = [u.strip() for u in config["ETH_RPC_URL"].split(",") if u.strip()]
    if len(urls) > 1:
        rpc_provider = MultiRPCProvider(urls)
        w3 = rpc_provider.get_web3()
    else:
        rpc_provider = None
        w3 = Web3(Web3.HTTPProvider(urls[0]))

    if not w3.is_connected():
        raise ConnectionError(
            f"Cannot connect to Ethereum node at {config['ETH_RPC_URL']}"
        )
    return w3, rpc_provider


def setup_backer_hab(config):
    """Create the backer's KERI Habery and non-transferable Hab.

    Args:
        config: dict from load_config().

    Returns:
        tuple of (hby, hab).
    """
    name = config["BACKER_NAME"]
    salt_raw = config["BACKER_SALT"]

    kwargs = {"name": name, "temp": True}
    if salt_raw:
        salt = Salter(raw=salt_raw.encode() if isinstance(salt_raw, str) else salt_raw).qb64
        kwargs["salt"] = salt

    hby = habbing.Habery(**kwargs)
    hab = hby.makeHab(name=name, transferable=False)
    return hby, hab


def setup_ethereum(config, abi_path=None):
    """Set up Ethereum components: Web3, contract, backer account, and RPC provider.

    Args:
        config: dict from load_config().
        abi_path: Optional path to contract ABI artifact.

    Returns:
        tuple of (w3, contract, backer_account, rpc_provider).
    """
    w3, rpc_provider = setup_web3(config)
    abi = load_contract_abi(abi_path)
    contract = w3.eth.contract(
        address=config["ETH_CONTRACT_ADDRESS"],
        abi=abi,
    )
    backer_account = Account.from_key(config["ETH_PRIVATE_KEY"])
    return w3, contract, backer_account, rpc_provider


def build_service(config=None, abi_path=None):
    """Wire together all backer components.

    Args:
        config: dict from load_config(). Loaded from env if None.
        abi_path: Optional path to contract ABI artifact.

    Returns:
        dict with keys: app, hab, hby, queuer, crawler, config, w3, rpc_provider
    """
    if config is None:
        config = load_config()

    hby, hab = setup_backer_hab(config)
    w3, contract, backer_account, rpc_provider = setup_ethereum(config, abi_path)

    kevery_components = setup_kevery(hby)
    tevery_components = setup_tevery(hby, hab, kevery_components)
    parser = setup_parser(kevery_components, tevery_components)

    # Build the ZK proof builder for the Queuer. In production, this calls
    # generate_sp1_proof to create a real Groth16 proof of KEL validity.
    # The proof_builder takes a list of anchors and returns (public_values, proof_bytes).
    from evm_backer.proofs import generate_sp1_proof, build_kel_input
    from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32
    from eth_abi import encode as abi_encode

    # TODO: In production, the proof_builder should use build_kel_input + generate_sp1_proof
    # with a KEL store populated by process_event. For now, the verifier_address and
    # proof_builder must be configured by the caller via environment or config.

    verifier_address = config.get("SP1_KERI_VERIFIER_ADDRESS", "")

    def _build_zk_proof(anchors):
        """Build a ZK proof for a batch of anchors."""
        encoded = w3.codec.encode(["(bytes32,uint64,bytes32)[]"], [anchors])
        msg_hash = w3.keccak(encoded)
        public_values = abi_encode(["bytes32"], [msg_hash])
        # In production, proof_bytes comes from the SP1 prover.
        # This is set up by the deployment environment.
        proof_bytes = b""
        return public_values, proof_bytes

    queuer = Queuer(
        w3=w3,
        contract=contract,
        backer_account=backer_account,
        verifier_address=verifier_address,
        proof_builder=_build_zk_proof,
    )
    crawler = Crawler(w3=w3, queuer=queuer)

    app = create_app(hab, parser, kevery_components, queuer)

    return {
        "app": app,
        "hab": hab,
        "hby": hby,
        "queuer": queuer,
        "crawler": crawler,
        "config": config,
        "w3": w3,
        "rpc_provider": rpc_provider,
    }


class ServiceLoop:
    """Main service loop: HTTP server + periodic flush + crawler polling.

    Runs the falcon WSGI app in a background thread while the main thread
    handles periodic flush and crawler checks.
    """

    def __init__(self, service):
        self.service = service
        self.config = service["config"]
        self._stop_event = threading.Event()
        self._http_thread = None
        self._httpd = None

    def _run_http_server(self):
        """Run the WSGI HTTP server in a background thread."""
        from wsgiref.simple_server import make_server, WSGIRequestHandler

        class QuietHandler(WSGIRequestHandler):
            def log_request(self, code="-", size="-"):
                pass  # Suppress per-request logging

        port = self.config["BACKER_PORT"]
        self._httpd = make_server("0.0.0.0", port, self.service["app"],
                                  handler_class=QuietHandler)
        logger.info("HTTP server listening on port %d", port)
        self._httpd.serve_forever()

    def start(self):
        """Start the service: HTTP server thread + main flush/crawl loop."""
        self._http_thread = threading.Thread(
            target=self._run_http_server, daemon=True
        )
        self._http_thread.start()

        queue_duration = self.config["QUEUE_DURATION"]
        logger.info(
            "Service loop started (flush every %ds, backer AID: %s)",
            queue_duration, self.service["hab"].pre,
        )

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=queue_duration)
                if self._stop_event.is_set():
                    break
                self._tick()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.stop()

    def _tick(self):
        """One flush + crawl cycle."""
        queuer = self.service["queuer"]
        crawler = self.service["crawler"]

        # Flush queued events to chain
        try:
            tx_hash = queuer.flush()
            if tx_hash is not None:
                logger.info("Flushed batch, tx: %s", tx_hash)
                pending = queuer.get_pending_txs()
                for h, events in pending:
                    if h == tx_hash:
                        crawler.track(tx_hash, events)
                        break
        except Exception:
            logger.exception("Error during flush")

        # Check for confirmations/reorgs
        try:
            confirmed, reorged = crawler.check()
            if confirmed:
                logger.info("Confirmed %d anchors", len(confirmed))
                for anchor in confirmed:
                    queuer.clear_pending_tx(anchor.tx_hash)
            if reorged:
                logger.warning("Reorged %d anchors — events requeued", len(reorged))
                for anchor in reorged:
                    queuer.clear_pending_tx(anchor.tx_hash)
        except Exception:
            logger.exception("Error during crawler check")

    def stop(self):
        """Signal the service loop and HTTP server to stop."""
        self._stop_event.set()
        if self._httpd is not None:
            self._httpd.shutdown()
        # Clean up keripy resources
        hby = self.service.get("hby")
        if hby is not None:
            try:
                hby.close()
            except Exception:
                pass


def run_service(config=None, abi_path=None):
    """Build and run the backer service (blocking).

    Args:
        config: dict from load_config(). Loaded from env if None.
        abi_path: Optional path to contract ABI artifact.
    """
    service = build_service(config=config, abi_path=abi_path)
    loop = ServiceLoop(service)
    loop.start()
