# -*- encoding: utf-8 -*-
"""
EVM Backer ZK Integration Tests

Tests for the SP1 ZK proof path: anchorEventWithZKProof and anchorBatchWithZKProof.

All tests use make_mock_sp1_proof() + SP1MockVerifier — no real SP1 toolchain
required. SP1MockVerifier accepts any call where proofBytes.length == 0.

Fixtures contract_with_zk and mock_sp1_verifier are session-scoped and defined
in conftest.py.
"""

import json
import subprocess

import pytest
from web3 import Web3

from tests.conftest import (
    ANVIL_BACKER_KEY,
    ANVIL_DEPLOYER_KEY,
    ANVIL_RPC_URL,
    CONTRACTS_DIR,
    ED25519_PUBKEY_HEX,
)
from evm_backer.proofs import make_mock_sp1_proof


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BACKER_PUBKEY_BYTES = bytes.fromhex(ED25519_PUBKEY_HEX)


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
    """anchorEventWithZKProof → isAnchored returns True."""

    def test_zk_anchor_single_event_via_sp1_proof(
        self, w3, contract_with_zk, backer_account
    ):
        contract = contract_with_zk["contract"]
        prefix_b32 = Web3.keccak(text="zk_single_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="zk_single_said")

        # keccak256(abi.encode(prefix, sn, eventSAID)) — same as contract
        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, sn, said_b32],
        )
        msg_hash = Web3.keccak(encoded)
        proof_bytes, public_values = make_mock_sp1_proof(BACKER_PUBKEY_BYTES, msg_hash)

        receipt = _build_and_send(
            w3,
            contract.functions.anchorEventWithZKProof(
                prefix_b32, sn, said_b32, public_values, proof_bytes
            ),
            backer_account,
        )

        assert receipt.status == 1
        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call()


class TestZKAnchorBatch:
    """anchorBatchWithZKProof anchors all events in a batch."""

    def test_zk_anchor_batch_via_sp1_proof(
        self, w3, contract_with_zk, backer_account
    ):
        contract = contract_with_zk["contract"]
        anchors = [
            (Web3.keccak(text="zk_batch_p1"), 0, Web3.keccak(text="zk_batch_s1")),
            (Web3.keccak(text="zk_batch_p2"), 1, Web3.keccak(text="zk_batch_s2")),
            (Web3.keccak(text="zk_batch_p3"), 0, Web3.keccak(text="zk_batch_s3")),
        ]

        encoded = w3.codec.encode(["(bytes32,uint64,bytes32)[]"], [anchors])
        msg_hash = Web3.keccak(encoded)
        proof_bytes, public_values = make_mock_sp1_proof(BACKER_PUBKEY_BYTES, msg_hash)

        receipt = _build_and_send(
            w3,
            contract.functions.anchorBatchWithZKProof(
                anchors, public_values, proof_bytes
            ),
            backer_account,
        )

        assert receipt.status == 1
        for prefix, sn, said in anchors:
            assert contract.functions.isAnchored(prefix, sn, said).call()


class TestZKRejections:
    """ZK proof path rejects malformed or unauthorised inputs."""

    def test_zk_rejects_wrong_pubkey_in_public_values(
        self, w3, contract_with_zk, backer_account
    ):
        contract = contract_with_zk["contract"]
        prefix_b32 = Web3.keccak(text="zk_wrong_pk_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="zk_wrong_pk_said")

        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, sn, said_b32],
        )
        msg_hash = Web3.keccak(encoded)

        wrong_pubkey = Web3.keccak(text="not_the_backer_key")
        _, public_values = make_mock_sp1_proof(wrong_pubkey, msg_hash)

        tx = contract.functions.anchorEventWithZKProof(
            prefix_b32, sn, said_b32, public_values, b""
        ).build_transaction({
            "from": backer_account.address,
            "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
            "chainId": w3.eth.chain_id,
            "gas": 500_000,
        })
        signed = backer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt.status == 0  # revert: ZK proof wrong pubkey

    def test_zk_rejects_if_verifier_not_configured(
        self, w3, backer_account
    ):
        """Attempt anchorEventWithZKProof on a contract with no ZK verifier set."""
        from eth_account import Account

        # Deploy a fresh KERIBacker without calling setZKVerifier
        deployer = Account.from_key(ANVIL_DEPLOYER_KEY)
        pubkey_arg = "0x" + ED25519_PUBKEY_HEX

        deploy_result = subprocess.run(
            [
                "forge", "create",
                "--root", CONTRACTS_DIR,
                "--rpc-url", ANVIL_RPC_URL,
                "--private-key", ANVIL_DEPLOYER_KEY,
                "--broadcast",
                "src/KERIBacker.sol:KERIBacker",
                "--constructor-args", pubkey_arg,
            ],
            capture_output=True,
            text=True,
        )
        assert deploy_result.returncode == 0, deploy_result.stderr

        contract_address = None
        for line in deploy_result.stdout.splitlines():
            if "Deployed to:" in line:
                contract_address = line.split("Deployed to:")[-1].strip()
                break
        assert contract_address is not None

        import os
        abi_path = os.path.join(CONTRACTS_DIR, "out", "KERIBacker.sol", "KERIBacker.json")
        with open(abi_path) as f:
            artifact = json.load(f)
        unconfigured = w3.eth.contract(address=contract_address, abi=artifact["abi"])

        prefix_b32 = Web3.keccak(text="zk_unconfigured_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="zk_unconfigured_said")

        tx = unconfigured.functions.anchorEventWithZKProof(
            prefix_b32, sn, said_b32, b"\x00" * 64, b""
        ).build_transaction({
            "from": backer_account.address,
            "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
            "chainId": w3.eth.chain_id,
            "gas": 200_000,
        })
        signed = backer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt.status == 0  # revert: ZK verifier not configured
