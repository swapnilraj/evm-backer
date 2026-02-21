# -*- encoding: utf-8 -*-
"""
EVM Backer Real SP1 Prover Integration Tests

Two test classes:

TestRealProverBinaryFast
  - Runs the actual sp1-prover binary with SP1_PROVER=mock.
  - The guest ELF executes in simulation: signature is verified, public values
    are committed (pubkey || msg_hash).  Proof bytes are empty.
  - SP1MockVerifier accepts empty proofs, so the full on-chain path is tested.
  - Skipped only if the prover binary is missing.

TestRealGroth16Proof  (requires REAL_SP1_PROOF=1 env var)
  - SP1_PROVER=cpu: real STARK proving + Groth16 wrapping via native-gnark.
  - Deploys SP1VerifierGroth16 (real on-chain verifier) and verifies the proof.
  - Takes 5-30 minutes; skip in CI unless REAL_SP1_PROOF=1 is set.

Run fast path only:
    uv run pytest tests/test_zk_real.py::TestRealProverBinaryFast -v -s

Run real Groth16 proof (takes minutes):
    REAL_SP1_PROOF=1 uv run pytest tests/test_zk_real.py::TestRealGroth16Proof -v -s
"""

import json
import os
import subprocess

import pytest
from web3 import Web3

from tests.conftest import (
    ANVIL_BACKER_KEY,
    ANVIL_DEPLOYER_KEY,
    ANVIL_RPC_URL,
    CONTRACTS_DIR,
    ED25519_PUBKEY_HEX,
    ED25519_SIGNING_KEY,
)
from evm_backer.proofs import PROVER_BIN, generate_sp1_proof

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BACKER_PUBKEY_BYTES = bytes.fromhex(ED25519_PUBKEY_HEX)

SP1_PROVER_AVAILABLE = PROVER_BIN.exists()
REAL_SP1_PROOF_REQUESTED = os.environ.get("REAL_SP1_PROOF", "").lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deploy_contract(contracts_dir, rpc_url, deployer_key, contract_ref, *constructor_args):
    """Deploy a contract via forge create; return its address."""
    cmd = [
        "forge", "create",
        "--root", contracts_dir,
        "--rpc-url", rpc_url,
        "--private-key", deployer_key,
        "--broadcast",
        contract_ref,
    ]
    if constructor_args:
        cmd += ["--constructor-args"] + list(constructor_args)

    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"forge create {contract_ref} failed:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    for line in result.stdout.splitlines():
        if "Deployed to:" in line:
            return line.split("Deployed to:")[-1].strip()

    raise AssertionError(
        f"Could not parse address from forge create output:\n{result.stdout}"
    )


def _build_and_send(w3, account, contract_fn, gas=2_000_000):
    """Build, sign, send a transaction and return the receipt."""
    tx = contract_fn.build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address, "pending"),
        "chainId": w3.eth.chain_id,
        "gas": gas,
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


def _load_abi(contracts_dir, contract_name):
    """Load ABI from forge build artifacts."""
    abi_path = os.path.join(
        contracts_dir, "out", f"{contract_name}.sol", f"{contract_name}.json"
    )
    with open(abi_path) as f:
        return json.load(f)["abi"]


def _configure_zk_verifier(w3, contract, verifier_address, sp1_vkey_bytes, nonce, account):
    """Call setZKVerifier on contract, signed with the test Ed25519 key."""
    verifier_addr_bytes = bytes.fromhex(verifier_address.lstrip("0x").zfill(40))
    # abi.encodePacked(address, bytes32, uint256) = 20 + 32 + 32 bytes
    packed = verifier_addr_bytes + sp1_vkey_bytes + nonce.to_bytes(32, "big")
    msg_hash = Web3.keccak(packed)
    sig = ED25519_SIGNING_KEY.sign(msg_hash).signature

    receipt = _build_and_send(
        w3, account,
        contract.functions.setZKVerifier(verifier_address, sp1_vkey_bytes, sig, nonce),
        gas=1_500_000,  # Ed25519.verify costs ~692k gas
    )
    assert receipt.status == 1, (
        f"setZKVerifier reverted. Gas used: {receipt.gasUsed}. "
        f"verifier={verifier_address}, vkey={sp1_vkey_bytes.hex()}, nonce={nonce}"
    )


# ---------------------------------------------------------------------------
# Fast path: real binary, mock proving, SP1MockVerifier
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not SP1_PROVER_AVAILABLE,
    reason=f"sp1-prover binary not found at {PROVER_BIN}. "
           "Build with: cargo build --release",
)
class TestRealProverBinaryFast:
    """Run the actual sp1-prover binary with SP1_PROVER=mock.

    SP1_PROVER=mock causes the SP1 SDK to execute the guest ELF in simulation
    (real Ed25519 verification runs inside the zkVM), commit the public values,
    and return an empty proof bytes.  SP1MockVerifier accepts empty proofs, so
    the complete Python → Rust binary → Ethereum path is validated here.
    """

    def test_binary_produces_correct_public_values(self, backer_signing_key):
        """Guest ELF executes; public values = backer_pubkey (32) || msg_hash (32)."""
        pubkey_bytes = backer_signing_key.verify_key.encode()
        msg_hash = bytes(range(32))  # deterministic 32-byte input

        old_val = os.environ.get("SP1_PROVER")
        os.environ["SP1_PROVER"] = "mock"
        try:
            proof_bytes, public_values, vkey = generate_sp1_proof(
                backer_signing_key, msg_hash, pubkey_bytes
            )
        finally:
            if old_val is None:
                os.environ.pop("SP1_PROVER", None)
            else:
                os.environ["SP1_PROVER"] = old_val

        # Mock mode: proof is empty (SP1MockVerifier accepts this)
        assert proof_bytes == b"", f"mock proof should be empty, got {len(proof_bytes)} bytes"

        # Public values: raw 64 bytes = pubkey || msg_hash
        # (same as abi.encode(bytes32, bytes32) since both are already 32 bytes)
        assert len(public_values) == 64, (
            f"Expected 64 bytes of public values, got {len(public_values)}"
        )
        assert public_values[:32] == pubkey_bytes, "First 32 bytes must be backer pubkey"
        assert public_values[32:] == msg_hash, "Last 32 bytes must be message hash"

        # vkey: 0x-prefixed 32-byte hex
        assert vkey.startswith("0x"), f"vkey must start with 0x, got: {vkey!r}"
        assert len(bytes.fromhex(vkey[2:])) == 32, f"vkey must be 32 bytes: {vkey}"

    def test_anchor_event_full_pipeline(self, w3, contract_with_zk, backer_account, backer_signing_key):
        """Full end-to-end: sp1-prover binary → anchorEventWithZKProof → isAnchored.

        Uses SP1_PROVER=mock so the guest runs but proof bytes are empty.
        SP1MockVerifier (already configured in contract_with_zk) accepts empty proofs.
        """
        contract = contract_with_zk["contract"]
        prefix_b32 = Web3.keccak(text="real_prover_single_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="real_prover_single_said")

        pubkey_bytes = backer_signing_key.verify_key.encode()

        # Contract computes: keccak256(abi.encode(prefix, sn, eventSAID))
        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, sn, said_b32],
        )
        msg_hash = Web3.keccak(encoded)

        old_val = os.environ.get("SP1_PROVER")
        os.environ["SP1_PROVER"] = "mock"
        try:
            proof_bytes, public_values, vkey = generate_sp1_proof(
                backer_signing_key, msg_hash, pubkey_bytes
            )
        finally:
            if old_val is None:
                os.environ.pop("SP1_PROVER", None)
            else:
                os.environ["SP1_PROVER"] = old_val

        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorEventWithZKProof(
                prefix_b32, sn, said_b32, public_values, proof_bytes
            ),
            gas=500_000,
        )
        assert receipt.status == 1, (
            f"anchorEventWithZKProof reverted. Gas used: {receipt.gasUsed}"
        )
        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call(), (
            "isAnchored() should return True after anchoring with sp1-prover binary"
        )

    def test_anchor_batch_full_pipeline(self, w3, contract_with_zk, backer_account, backer_signing_key):
        """Full end-to-end: sp1-prover binary → anchorBatchWithZKProof → isAnchored."""
        contract = contract_with_zk["contract"]
        pubkey_bytes = backer_signing_key.verify_key.encode()

        anchors = [
            (Web3.keccak(text="rb_p1"), 0, Web3.keccak(text="rb_s1")),
            (Web3.keccak(text="rb_p2"), 1, Web3.keccak(text="rb_s2")),
        ]

        # Contract computes: keccak256(abi.encode(anchors))
        encoded = w3.codec.encode(["(bytes32,uint64,bytes32)[]"], [anchors])
        msg_hash = Web3.keccak(encoded)

        old_val = os.environ.get("SP1_PROVER")
        os.environ["SP1_PROVER"] = "mock"
        try:
            proof_bytes, public_values, vkey = generate_sp1_proof(
                backer_signing_key, msg_hash, pubkey_bytes
            )
        finally:
            if old_val is None:
                os.environ.pop("SP1_PROVER", None)
            else:
                os.environ["SP1_PROVER"] = old_val

        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorBatchWithZKProof(anchors, public_values, proof_bytes),
            gas=500_000,
        )
        assert receipt.status == 1, (
            f"anchorBatchWithZKProof reverted. Gas used: {receipt.gasUsed}"
        )
        for prefix, sn, said in anchors:
            assert contract.functions.isAnchored(prefix, sn, said).call(), (
                f"isAnchored({prefix.hex()}, {sn}, {said.hex()}) should return True"
            )

    def test_wrong_pubkey_in_public_values_reverts(self, w3, contract_with_zk, backer_account, backer_signing_key):
        """If public values carry wrong pubkey, anchorEventWithZKProof must revert.

        The prover binary signs with the wrong key; the contract checks
        pvPubKey == backerPubKey and reverts on mismatch.
        """
        import nacl.signing

        contract = contract_with_zk["contract"]
        prefix_b32 = Web3.keccak(text="rb_wrong_pk_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="rb_wrong_pk_said")

        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, sn, said_b32],
        )
        msg_hash = Web3.keccak(encoded)

        # Use a different key — the binary will produce publicValues with wrong pubkey
        other_key = nacl.signing.SigningKey.generate()
        other_pubkey = other_key.verify_key.encode()

        old_val = os.environ.get("SP1_PROVER")
        os.environ["SP1_PROVER"] = "mock"
        try:
            proof_bytes, public_values, _ = generate_sp1_proof(
                other_key, msg_hash, other_pubkey
            )
        finally:
            if old_val is None:
                os.environ.pop("SP1_PROVER", None)
            else:
                os.environ["SP1_PROVER"] = old_val

        tx = contract.functions.anchorEventWithZKProof(
            prefix_b32, sn, said_b32, public_values, proof_bytes
        ).build_transaction({
            "from": backer_account.address,
            "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
            "chainId": w3.eth.chain_id,
            "gas": 500_000,
        })
        signed = backer_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt.status == 0, (
            "anchorEventWithZKProof should revert when public values carry wrong pubkey"
        )


# ---------------------------------------------------------------------------
# Slow path: real local Groth16 proof + SP1VerifierGroth16
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not SP1_PROVER_AVAILABLE,
    reason=f"sp1-prover binary not found at {PROVER_BIN}.",
)
@pytest.mark.skipif(
    not REAL_SP1_PROOF_REQUESTED,
    reason="Set REAL_SP1_PROOF=1 to run real Groth16 proof tests (takes 5-30 min).",
)
class TestRealGroth16Proof:
    """Generate a real Groth16 proof and verify it on-chain.

    Requires SP1_PROVER=cpu (default) and the native-gnark feature compiled
    into the sp1-prover binary.  Proof generation takes several minutes.

    Run with:
        REAL_SP1_PROOF=1 uv run pytest tests/test_zk_real.py::TestRealGroth16Proof -v -s
    """

    def test_real_groth16_proof_anchors_event_on_chain(
        self, w3, anvil_process, backer_account
    ):
        """Full cryptographic pipeline: local Groth16 → SP1VerifierGroth16 → KERIBacker."""
        from eth_account import Account

        prefix_b32 = Web3.keccak(text="groth16_prefix")
        sn = 0
        said_b32 = Web3.keccak(text="groth16_said")

        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, sn, said_b32],
        )
        msg_hash = Web3.keccak(encoded)

        # Generate real Groth16 proof (SP1_PROVER defaults to "local")
        proof_bytes, public_values, vkey = generate_sp1_proof(
            ED25519_SIGNING_KEY,
            msg_hash,
            BACKER_PUBKEY_BYTES,
        )

        assert len(proof_bytes) > 0, (
            "Real Groth16 proof should be non-empty. "
            "If you see empty bytes, the prover ran in mock mode."
        )
        assert len(public_values) == 64
        assert public_values[:32] == BACKER_PUBKEY_BYTES
        assert public_values[32:] == msg_hash

        # Deploy real SP1VerifierGroth16 (v6.0.0)
        verifier_address = _deploy_contract(
            CONTRACTS_DIR,
            ANVIL_RPC_URL,
            ANVIL_DEPLOYER_KEY,
            "lib/sp1-contracts/contracts/src/v6.0.0/SP1VerifierGroth16.sol:SP1Verifier",
        )

        # Deploy fresh KERIBacker
        contract_address = _deploy_contract(
            CONTRACTS_DIR,
            ANVIL_RPC_URL,
            ANVIL_DEPLOYER_KEY,
            "src/KERIBacker.sol:KERIBacker",
            "0x" + ED25519_PUBKEY_HEX,
        )
        abi = _load_abi(CONTRACTS_DIR, "KERIBacker")
        contract = w3.eth.contract(address=contract_address, abi=abi)

        # Configure ZK verifier with the real vkey
        sp1_vkey_bytes = bytes.fromhex(vkey.replace("0x", ""))
        _configure_zk_verifier(w3, contract, verifier_address, sp1_vkey_bytes, 999, backer_account)

        # Anchor with real proof
        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorEventWithZKProof(
                prefix_b32, sn, said_b32, public_values, proof_bytes
            ),
            gas=2_000_000,
        )
        assert receipt.status == 1, (
            f"anchorEventWithZKProof with real Groth16 proof reverted. "
            f"Gas used: {receipt.gasUsed}"
        )
        assert contract.functions.isAnchored(prefix_b32, sn, said_b32).call()
