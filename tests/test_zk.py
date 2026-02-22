# -*- encoding: utf-8 -*-
"""
EVM Backer ZK Integration Tests

Tests for the SP1 ZK proof path via SP1KERIVerifier + SP1MockVerifier.
All tests use make_mock_sp1_proof() — no real SP1 toolchain required.

The SP1 guest now proves the full KERI KEL. Public values are 32 bytes:
    abi.encode(bytes32 messageHash)

(Previously 64 bytes with backerPubKey; the KEL proof makes an
approvedBackers whitelist unnecessary.)

Fixtures contract_with_zk and mock_sp1_verifier are session-scoped and
defined in conftest.py.
"""

import pytest
from web3 import Web3

from evm_backer.proofs import make_mock_sp1_proof


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_and_send(w3, contract_fn, backer_account):
    """Build, sign and send a contract transaction; return the receipt."""
    tx = contract_fn.build_transaction({
        "from": backer_account.address,
        "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
        "chainId": w3.eth.chain_id,
        "gas": 500_000,
    })
    signed = backer_account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestZKAnchorSingleEvent:
    """anchorEvent with SP1KERIVerifier proof → isAnchored returns True."""

    def test_zk_anchor_single_event_via_sp1_proof(
        self, w3, contract_with_zk, backer_account
    ):
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix_b32 = Web3.keccak(text="zk_single_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="zk_single_said")

        # keccak256(abi.encode(prefix, sn, eventSAID)) — same as contract
        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, sn, said_b32],
        )
        msg_hash = Web3.keccak(encoded)
        contract_proof, _ = make_mock_sp1_proof(msg_hash)

        receipt = _build_and_send(
            w3,
            contract.functions.anchorEvent(
                prefix_b32, sn, said_b32, sp1_verifier, contract_proof
            ),
            backer_account,
        )

        assert receipt.status == 1
        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call()


class TestZKAnchorBatch:
    """anchorBatch with SP1KERIVerifier proof anchors all events."""

    def test_zk_anchor_batch_via_sp1_proof(
        self, w3, contract_with_zk, backer_account
    ):
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        anchors = [
            (Web3.keccak(text="zk_batch_p1"), 0, Web3.keccak(text="zk_batch_s1")),
            (Web3.keccak(text="zk_batch_p2"), 1, Web3.keccak(text="zk_batch_s2")),
            (Web3.keccak(text="zk_batch_p3"), 0, Web3.keccak(text="zk_batch_s3")),
        ]

        encoded = w3.codec.encode(["(bytes32,uint64,bytes32)[]"], [anchors])
        msg_hash = Web3.keccak(encoded)
        contract_proof, _ = make_mock_sp1_proof(msg_hash)

        receipt = _build_and_send(
            w3,
            contract.functions.anchorBatch(anchors, sp1_verifier, contract_proof),
            backer_account,
        )

        assert receipt.status == 1
        for prefix, sn, said in anchors:
            assert contract.functions.isAnchored(prefix, sn, said).call()


class TestZKRejections:
    """ZK proof path rejects malformed or unauthorised inputs."""

    def test_zk_rejects_wrong_message_in_public_values(
        self, w3, contract_with_zk, backer_account
    ):
        """Public values carry a different messageHash than what the contract computed."""
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]
        prefix_b32 = Web3.keccak(text="zk_wrong_msg_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="zk_wrong_msg_said")

        wrong_msg_hash = Web3.keccak(text="totally_wrong_message")
        contract_proof, _ = make_mock_sp1_proof(wrong_msg_hash)

        tx = contract.functions.anchorEvent(
            prefix_b32, sn, said_b32, sp1_verifier, contract_proof
        ).build_transaction({
            "from": backer_account.address,
            "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
            "chainId": w3.eth.chain_id,
            "gas": 500_000,
        })
        signed = backer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt.status == 0  # revert: SP1KERIVerifier: wrong message

    def test_zk_rejects_unapproved_verifier(
        self, w3, contract_with_zk, backer_account
    ):
        """Attempt anchorEvent with an unregistered verifier address."""
        contract = contract_with_zk["contract"]
        unregistered = "0x0000000000000000000000000000000000001234"
        prefix_b32 = Web3.keccak(text="zk_unapproved_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="zk_unapproved_said")

        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, sn, said_b32],
        )
        msg_hash = Web3.keccak(encoded)
        contract_proof, _ = make_mock_sp1_proof(msg_hash)

        tx = contract.functions.anchorEvent(
            prefix_b32, sn, said_b32, unregistered, contract_proof
        ).build_transaction({
            "from": backer_account.address,
            "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
            "chainId": w3.eth.chain_id,
            "gas": 200_000,
        })
        signed = backer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt.status == 0  # revert: KERIBacker: verifier not approved
