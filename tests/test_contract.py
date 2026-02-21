# -*- encoding: utf-8 -*-
"""
Python-stack integration tests for KERIBacker.sol.

Behavioral tests (first-seen policy, access control, batch semantics, key
rotation) are covered in full by Foundry (contracts/test/KERIBacker.t.sol).

These tests cover Python-specific concerns only:
  1. forge deploy + web3.py connect + signed tx via eth_account (full stack)
  2. ABI tuple encoding for anchorBatch (Anchor struct array from Python)
  3. Event log parsing via contract.events.KERIEventAnchored().process_receipt()
  4. Revert detection (receipt.status == 0 for unauthorized caller)

Reference:
  - evm-backer-spec.md section 3 (Smart Contract)
  - contracts/test/KERIBacker.t.sol (behavioral coverage via Foundry)
"""

from keri.core import eventing
from keri.core.signing import Signer

from nacl.signing import SigningKey
from web3 import Web3

from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32
from tests.conftest import SEED_0, _send_anchor_tx, ED25519_SIGNING_KEY


def _build_golden_icp():
    """Create the golden non-transferable inception event from the fixed seed."""
    signer = Signer(raw=SEED_0, transferable=False)
    keys = [signer.verfer.qb64]
    return eventing.incept(keys=keys)


class TestPythonStackIntegration:
    """Prove the Python web3.py ↔ KERIBacker.sol stack works end-to-end.

    Foundry covers all contract logic. These tests cover Python glue only.
    """

    def test_anchor_and_query_via_python_stack(self, w3, contract, backer_account):
        """forge deploy + eth_account sign + web3.py view call.

        Proves the full stack: forge compiles, anvil runs, web3.py connects,
        eth_account signs, and isAnchored() returns the right answer.
        """
        serder = _build_golden_icp()
        prefix_b32 = prefix_to_bytes32(serder.ked["i"])
        said_b32 = said_to_bytes32(serder.said)

        receipt = _send_anchor_tx(w3, contract, backer_account, prefix_b32, 0, said_b32)
        assert receipt.status == 1

        assert contract.functions.isAnchored(prefix_b32, 0, said_b32).call() is True
        assert contract.functions.isAnchored(prefix_b32, 0, b'\x00' * 32).call() is False

    def test_batch_tuple_encoding_and_log_parsing(self, w3, contract, backer_account):
        """anchorBatch Anchor[] struct array via Python tuples + event log parsing.

        Proves two Python-specific behaviors:
          - web3.py encodes Python tuples as Solidity struct arrays correctly
          - contract.events.KERIEventAnchored().process_receipt() parses all logs
        """
        anchors = [
            (b'\xd3' * 32, 0, b'\xe3' * 32),
            (b'\xd4' * 32, 0, b'\xe4' * 32),
        ]
        # Sign the batch with Ed25519
        encoded = w3.codec.encode(
            ["(bytes32,uint64,bytes32)[]"],
            [anchors],
        )
        msg_hash = Web3.keccak(encoded)
        sig = ED25519_SIGNING_KEY.sign(msg_hash).signature

        tx = contract.functions.anchorBatch(anchors, sig).build_transaction({
            "from": backer_account.address,
            "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
            "chainId": w3.eth.chain_id,
            "gas": 1_000_000,
        })
        signed = backer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        assert receipt.status == 1
        logs = contract.events.KERIEventAnchored().process_receipt(receipt)
        assert len(logs) == 2, "Each anchor in the batch must emit KERIEventAnchored"

    def test_revert_detection(self, w3, contract, deployer_account):
        """Invalid signature — tx is mined but receipt.status == 0.

        Proves web3.py correctly surfaces failed txs: send_raw_transaction
        succeeds (tx enters mempool), but the mined receipt has status 0.
        """
        bad_sig = b'\x00' * 64
        tx = contract.functions.anchorEvent(
            b'\xf0' * 32, 0, b'\xf1' * 32, bad_sig
        ).build_transaction({
            "from": deployer_account.address,
            "nonce": w3.eth.get_transaction_count(deployer_account.address, "pending"),
            "chainId": w3.eth.chain_id,
            "gas": 500_000,
        })
        signed = deployer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        assert receipt.status == 0, "Invalid Ed25519 signature must revert"
