# -*- encoding: utf-8 -*-
"""
EVM Backer Real SP1 Prover Integration Tests

Two test classes:

TestRealProverBinaryFast
  - Runs the actual sp1-prover binary with SP1_PROVER=mock.
  - Builds a real KERI KEL using keripy (icp, icp+ixn, icp+ixn+rot).
  - The guest ELF executes in simulation: all KERI verification runs inside
    the zkVM (blake3, ed25519, pre-rotation checks). Proof bytes are empty.
  - SP1MockVerifier accepts empty proofs, so the full on-chain path is tested.
  - Skipped only if the prover binary is missing.

TestRealGroth16Proof  (requires REAL_SP1_PROOF=1 env var)
  - SP1_PROVER=cpu: real STARK proving + Groth16 wrapping via native-gnark.
  - Deploys SP1VerifierGroth16 (real on-chain verifier) and verifies the proof.
  - Takes ~7 minutes on ARM Mac; skip in CI unless REAL_SP1_PROOF=1.

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

from keri.app import habbing
from keri.core.coring import Diger, MtrDex
from keri.core.eventing import incept, interact, rotate
from keri.core.signing import Signer

from tests.conftest import (
    ANVIL_BACKER_KEY,
    ANVIL_DEPLOYER_ADDRESS,
    ANVIL_DEPLOYER_KEY,
    ANVIL_RPC_URL,
    CONTRACTS_DIR,
    SEED_0,
    SEED_1,
    SEED_2,
)
from evm_backer.proofs import (
    PROVER_BIN,
    TEL_PROVER_BIN,
    build_kel_input,
    generate_sp1_proof,
    make_mock_sp1_proof,
    make_mock_tel_proof,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SP1_PROVER_AVAILABLE = PROVER_BIN.exists()
REAL_SP1_PROOF_REQUESTED = os.environ.get("REAL_SP1_PROOF", "").lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# KEL building helpers
# ---------------------------------------------------------------------------


def _make_icp_kel_store():
    """Build a 1-event KEL (icp only) from SEED_0.

    Returns (prefix_qb64, kel_store, icp_serder).
    """
    signer0 = Signer(raw=SEED_0, transferable=True)
    signer1 = Signer(raw=SEED_1, transferable=True)

    keys0 = [signer0.verfer.qb64]
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]

    icp_serder = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
    pre = icp_serder.ked["i"]

    # Sign: controller signs the icp event with key0.
    # Signer.sign() without index= returns a Cigar; .raw is the 64-byte signature.
    icp_sig = signer0.sign(ser=icp_serder.raw).raw  # 64 bytes

    kel_store = {
        (pre, 0): {"serder": icp_serder, "sigs": [(0, icp_sig)]},
    }
    return pre, kel_store, icp_serder


def _make_icp_ixn_rot_kel_store():
    """Build a 3-event KEL (icp → ixn → rot) from SEED_0 / SEED_1 / SEED_2.

    The rotation uses SEED_1 as the new signing key, with SEED_2 as the
    next pre-rotation commitment.

    Returns (prefix_qb64, kel_store, rot_serder).
    """
    signer0 = Signer(raw=SEED_0, transferable=True)
    signer1 = Signer(raw=SEED_1, transferable=True)
    signer2 = Signer(raw=SEED_2, transferable=True)

    keys0 = [signer0.verfer.qb64]
    keys1 = [signer1.verfer.qb64]
    nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]
    nxt2 = [Diger(ser=signer2.verfer.qb64b).qb64]

    # sn=0: inception
    icp_serder = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
    pre = icp_serder.ked["i"]
    icp_sig = signer0.sign(ser=icp_serder.raw).raw

    # sn=1: interaction (signed with key0)
    ixn_serder = interact(pre=pre, dig=icp_serder.said, sn=1)
    ixn_sig = signer0.sign(ser=ixn_serder.raw).raw

    # sn=2: rotation to key1 (still signed with OLD key0)
    rot_serder = rotate(
        pre=pre, keys=keys1, dig=ixn_serder.said, ndigs=nxt2, sn=2
    )
    rot_sig = signer0.sign(ser=rot_serder.raw).raw

    kel_store = {
        (pre, 0): {"serder": icp_serder, "sigs": [(0, icp_sig)]},
        (pre, 1): {"serder": ixn_serder, "sigs": [(0, ixn_sig)]},
        (pre, 2): {"serder": rot_serder, "sigs": [(0, rot_sig)]},
    }
    return pre, kel_store, rot_serder


# ---------------------------------------------------------------------------
# Deployment helpers
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
    raise AssertionError(f"Could not parse address from forge create output:\n{result.stdout}")


def _build_and_send(w3, account, contract_fn, gas=2_000_000):
    """Build, sign, send and return a transaction receipt."""
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
    abi_path = os.path.join(
        contracts_dir, "out", f"{contract_name}.sol", f"{contract_name}.json"
    )
    with open(abi_path) as f:
        return json.load(f)["abi"]


def _run_sp1_prover_mock(kel_input: dict) -> tuple[bytes, bytes, str]:
    """Run generate_sp1_proof with SP1_PROVER=mock, restoring env afterwards."""
    old_val = os.environ.get("SP1_PROVER")
    os.environ["SP1_PROVER"] = "mock"
    try:
        return generate_sp1_proof(kel_input)
    finally:
        if old_val is None:
            os.environ.pop("SP1_PROVER", None)
        else:
            os.environ["SP1_PROVER"] = old_val


# ---------------------------------------------------------------------------
# Fast path: real binary, mock proving, SP1MockVerifier
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not SP1_PROVER_AVAILABLE,
    reason=f"sp1-prover binary not found at {PROVER_BIN}. Build with: cargo build --release",
)
class TestRealProverBinaryFast:
    """Run the actual sp1-prover binary with SP1_PROVER=mock.

    SP1_PROVER=mock causes the SP1 SDK to execute the guest ELF in simulation
    (real blake3, ed25519, pre-rotation verification inside the zkVM), commit
    the 32-byte messageHash as public values, and return empty proof bytes.
    SP1MockVerifier accepts empty proofs, so the complete Python → Rust binary
    → Ethereum path is validated here.
    """

    def test_binary_produces_correct_public_values(self):
        """Guest ELF executes; public values = 32-byte messageHash."""
        from eth_abi import decode as abi_decode

        pre, kel_store, icp_serder = _make_icp_kel_store()
        kel_input = build_kel_input(kel_store, pre, target_sn=0)

        contract_proof, public_values, vkey = _run_sp1_prover_mock(kel_input)

        # Public values: exactly 32 bytes = abi.encode(bytes32 messageHash)
        assert len(public_values) == 32, (
            f"Expected 32 bytes of public values (messageHash only), "
            f"got {len(public_values)}"
        )

        # vkey: 0x-prefixed 32-byte hex
        assert vkey.startswith("0x"), f"vkey must start with 0x, got: {vkey!r}"
        assert len(bytes.fromhex(vkey[2:])) == 32, f"vkey must be 32 bytes: {vkey}"

        # contract_proof = abi.encode(publicValues, proofBytes)
        inner_pv, inner_pb = abi_decode(["bytes", "bytes"], contract_proof)
        assert inner_pv == public_values
        assert inner_pb == b"", "mock mode must produce empty inner proof bytes"

    def test_icp_only_pipeline(self, w3, contract_with_zk, backer_account):
        """1-event KEL (icp only): real guest execution → anchorEvent → isAnchored."""
        from eth_abi import decode as abi_decode

        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        pre, kel_store, icp_serder = _make_icp_kel_store()
        kel_input = build_kel_input(kel_store, pre, target_sn=0)

        contract_proof, public_values, _ = _run_sp1_prover_mock(kel_input)

        # Derive on-chain arguments from the KEL.
        from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32
        prefix_b32 = prefix_to_bytes32(pre)
        said_b32 = said_to_bytes32(icp_serder.said)

        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorEvent(
                prefix_b32, 0, said_b32, sp1_verifier, contract_proof
            ),
            gas=500_000,
        )
        assert receipt.status == 1, (
            f"anchorEvent (icp-only ZK path) reverted. Gas used: {receipt.gasUsed}"
        )
        assert contract.functions.isAnchored(prefix_b32, 0, said_b32).call(), (
            "isAnchored() should return True after icp-only ZK anchor"
        )

    def test_icp_ixn_rot_pipeline(self, w3, contract_with_zk, backer_account):
        """3-event KEL (icp→ixn→rot): real guest handles rotation, on-chain verify."""
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        pre, kel_store, rot_serder = _make_icp_ixn_rot_kel_store()
        kel_input = build_kel_input(kel_store, pre, target_sn=2)

        contract_proof, public_values, _ = _run_sp1_prover_mock(kel_input)

        from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32
        prefix_b32 = prefix_to_bytes32(pre)
        said_b32 = said_to_bytes32(rot_serder.said)

        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorEvent(
                prefix_b32, 2, said_b32, sp1_verifier, contract_proof
            ),
            gas=500_000,
        )
        assert receipt.status == 1, (
            f"anchorEvent (icp+ixn+rot ZK path) reverted. Gas used: {receipt.gasUsed}"
        )
        assert contract.functions.isAnchored(prefix_b32, 2, said_b32).call(), (
            "isAnchored() should return True after rotation ZK anchor"
        )

    def test_wrong_message_reverts(self, w3, contract_with_zk, backer_account):
        """Tamper with messageHash after proof generation → anchorEvent must revert.

        The sp1-prover generates a valid proof for the correct messageHash.
        We then pass a *different* (prefix, sn, said) to anchorEvent so the
        contract computes a different messageHash. SP1KERIVerifier checks
        pvMessageHash == messageHash and reverts.
        """
        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        # Prove the icp event.
        pre, kel_store, icp_serder = _make_icp_kel_store()
        kel_input = build_kel_input(kel_store, pre, target_sn=0)
        contract_proof, _, _ = _run_sp1_prover_mock(kel_input)

        # Anchor with different SAID → contract's messageHash ≠ proof's messageHash.
        wrong_said_b32 = Web3.keccak(text="definitely_wrong_said")
        from evm_backer.transactions import prefix_to_bytes32
        prefix_b32 = prefix_to_bytes32(pre)

        tx = contract.functions.anchorEvent(
            prefix_b32, 0, wrong_said_b32, sp1_verifier, contract_proof
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
            "anchorEvent should revert when message_hash in proof differs from computed"
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
    reason="Set REAL_SP1_PROOF=1 to run real Groth16 proof tests (takes ~7 min).",
)
class TestRealGroth16Proof:
    """Generate a real Groth16 proof and verify it on-chain.

    Requires SP1_PROVER=cpu (default) and the native-gnark feature compiled
    into the sp1-prover binary. Proof generation takes several minutes.

    Run with:
        REAL_SP1_PROOF=1 uv run pytest tests/test_zk_real.py::TestRealGroth16Proof -v -s
    """

    def test_real_groth16_proof_anchors_event_on_chain(
        self, w3, anvil_process, backer_account
    ):
        """Full cryptographic pipeline: local Groth16 → SP1VerifierGroth16 → KERIBacker."""
        from eth_abi import decode as abi_decode
        from eth_account import Account

        # Build a 3-event KEL.
        pre, kel_store, rot_serder = _make_icp_ixn_rot_kel_store()
        kel_input = build_kel_input(kel_store, pre, target_sn=2)

        # Generate real Groth16 proof (SP1_PROVER defaults to "cpu").
        contract_proof, public_values, vkey = generate_sp1_proof(kel_input)

        # Verify real proof was generated (inner proof_bytes must be non-empty).
        _, inner_pb = abi_decode(["bytes", "bytes"], contract_proof)
        assert len(inner_pb) > 0, (
            "Real Groth16 proof should be non-empty. "
            "If you see empty bytes, the prover ran in mock mode."
        )
        assert len(public_values) == 32, (
            f"KEL guest public values must be 32 bytes, got {len(public_values)}"
        )

        # Deploy real SP1VerifierGroth16 (v6.0.0).
        sp1_verifier_address = _deploy_contract(
            CONTRACTS_DIR,
            ANVIL_RPC_URL,
            ANVIL_DEPLOYER_KEY,
            "lib/sp1-contracts/contracts/src/v6.0.0/SP1VerifierGroth16.sol:SP1Verifier",
        )

        # Deploy permissionless SP1KERIVerifier with the real vkey.
        sp1_vkey_bytes = bytes.fromhex(vkey.replace("0x", ""))
        sp1_keri_verifier_address = _deploy_contract(
            CONTRACTS_DIR,
            ANVIL_RPC_URL,
            ANVIL_DEPLOYER_KEY,
            "src/SP1KERIVerifier.sol:SP1KERIVerifier",
            sp1_verifier_address,
            "0x" + sp1_vkey_bytes.hex(),
        )

        # Deploy fresh KERIBacker and approve the SP1KERIVerifier.
        deployer = Account.from_key(ANVIL_DEPLOYER_KEY)
        kb_address = _deploy_contract(
            CONTRACTS_DIR,
            ANVIL_RPC_URL,
            ANVIL_DEPLOYER_KEY,
            "src/KERIBacker.sol:KERIBacker",
            ANVIL_DEPLOYER_ADDRESS,
        )
        kb_abi = _load_abi(CONTRACTS_DIR, "KERIBacker")
        kb_contract = w3.eth.contract(address=kb_address, abi=kb_abi)
        _build_and_send(
            w3, deployer,
            kb_contract.functions.approveVerifier(sp1_keri_verifier_address),
            gas=500_000,
        )

        # Anchor with real Groth16 proof.
        from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32
        prefix_b32 = prefix_to_bytes32(pre)
        said_b32 = said_to_bytes32(rot_serder.said)

        receipt = _build_and_send(
            w3, backer_account,
            kb_contract.functions.anchorEvent(
                prefix_b32, 2, said_b32, sp1_keri_verifier_address, contract_proof
            ),
            gas=2_000_000,
        )
        assert receipt.status == 1, (
            f"anchorEvent with real Groth16 proof reverted. "
            f"Gas used: {receipt.gasUsed}"
        )
        assert kb_contract.functions.isAnchored(prefix_b32, 2, said_b32).call()


# ---------------------------------------------------------------------------
# Delegated KEL tests (dip/drt) using real prover binary with mock proving
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not SP1_PROVER_AVAILABLE,
    reason=f"sp1-prover binary not found at {PROVER_BIN}. Build with: cargo build --release",
)
class TestDelegatedKEL:
    """Test dip/drt (delegated inception/rotation) with real sp1-prover binary.

    Uses SP1_PROVER=mock for fast execution. The guest ELF verifies
    the full delegated KEL including delegation seal checks.
    """

    def _make_dip_kel_store(self):
        """Build a delegated KEL store with dip event.

        Delegating AID: SEED_0 (icp), with approval seal for dip.
        Delegatee AID: SEED_2 (dip), self-addressing prefix.

        Returns (delegatee_pre, kel_store, dip_serder).
        """
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        signer2 = Signer(raw=SEED_2, transferable=True)

        # Build delegating AID: icp with key0, pre-rotation to key1.
        keys0 = [signer0.verfer.qb64]
        nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]
        del_icp_serder = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
        delegating_pre = del_icp_serder.ked["i"]
        del_icp_sig = signer0.sign(ser=del_icp_serder.raw).raw

        # Build delegatee dip event (self-addressing, delegating_pre = delegating_pre).
        keys2 = [signer2.verfer.qb64]
        nxt2 = [Diger(ser=signer2.verfer.qb64b).qb64]
        dip_serder = incept(
            keys=keys2, ndigs=nxt2, code=MtrDex.Blake3_256, delpre=delegating_pre
        )
        delegatee_pre = dip_serder.ked["i"]
        dip_sig = signer2.sign(ser=dip_serder.raw).raw

        # Build delegating AID ixn with approval seal for dip (sn=1).
        del_ixn_serder = interact(
            pre=delegating_pre,
            dig=del_icp_serder.said,
            sn=1,
            data=[{"i": delegatee_pre, "s": "0", "d": dip_serder.said}],
        )
        del_ixn_sig = signer0.sign(ser=del_ixn_serder.raw).raw

        kel_store = {
            (delegating_pre, 0): {"serder": del_icp_serder, "sigs": [(0, del_icp_sig)]},
            (delegating_pre, 1): {"serder": del_ixn_serder, "sigs": [(0, del_ixn_sig)]},
            (delegatee_pre, 0): {"serder": dip_serder, "sigs": [(0, dip_sig)]},
        }
        return delegatee_pre, kel_store, dip_serder

    def _make_dip_drt_kel_store(self):
        """Build a delegated KEL store with dip + drt events.

        drt events do not include a 'di' field per the KERI spec — the delegation
        relationship is established by dip. Use rotate(..., ilk='drt') not delpre=.

        Returns (delegatee_pre, kel_store, drt_serder).
        """
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        signer2 = Signer(raw=SEED_2, transferable=True)

        # Build delegating AID: icp with key0.
        keys0 = [signer0.verfer.qb64]
        nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]
        del_icp_serder = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
        delegating_pre = del_icp_serder.ked["i"]
        del_icp_sig = signer0.sign(ser=del_icp_serder.raw).raw

        # Build delegatee dip (SEED_2 key), with pre-rotation commitment to signer1.
        keys2 = [signer2.verfer.qb64]
        nxt_for_drt = [Diger(ser=signer1.verfer.qb64b).qb64]
        dip_serder = incept(
            keys=keys2, ndigs=nxt_for_drt, code=MtrDex.Blake3_256, delpre=delegating_pre
        )
        delegatee_pre = dip_serder.ked["i"]
        dip_sig = signer2.sign(ser=dip_serder.raw).raw

        # Delegating AID: ixn1 seals dip, ixn2 seals drt.
        del_ixn1_serder = interact(
            pre=delegating_pre,
            dig=del_icp_serder.said,
            sn=1,
            data=[{"i": delegatee_pre, "s": "0", "d": dip_serder.said}],
        )
        del_ixn1_sig = signer0.sign(ser=del_ixn1_serder.raw).raw

        # Delegatee drt: rotate from signer2 → signer1 (satisfies dip's pre-rotation).
        # Use ilk='drt' — drt events have no 'di' field per the KERI spec.
        keys1 = [signer1.verfer.qb64]
        nxt2 = [Diger(ser=signer2.verfer.qb64b).qb64]
        drt_serder = rotate(
            pre=delegatee_pre,
            keys=keys1,
            dig=dip_serder.said,
            ndigs=nxt2,
            sn=1,
            ilk="drt",
        )
        drt_sig = signer2.sign(ser=drt_serder.raw).raw

        del_ixn2_serder = interact(
            pre=delegating_pre,
            dig=del_ixn1_serder.said,
            sn=2,
            data=[{"i": delegatee_pre, "s": "1", "d": drt_serder.said}],
        )
        del_ixn2_sig = signer0.sign(ser=del_ixn2_serder.raw).raw

        kel_store = {
            (delegating_pre, 0): {"serder": del_icp_serder, "sigs": [(0, del_icp_sig)]},
            (delegating_pre, 1): {"serder": del_ixn1_serder, "sigs": [(0, del_ixn1_sig)]},
            (delegating_pre, 2): {"serder": del_ixn2_serder, "sigs": [(0, del_ixn2_sig)]},
            (delegatee_pre, 0): {"serder": dip_serder, "sigs": [(0, dip_sig)]},
            (delegatee_pre, 1): {"serder": drt_serder, "sigs": [(0, drt_sig)]},
        }
        return delegatee_pre, kel_store, drt_serder

    def test_dip_pipeline(self, w3, contract_with_zk, backer_account):
        """Delegated inception: real guest execution → anchorEvent → isAnchored."""
        from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32

        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        delegatee_pre, kel_store, dip_serder = self._make_dip_kel_store()
        kel_input = build_kel_input(kel_store, delegatee_pre, target_sn=0)

        contract_proof, public_values, _ = _run_sp1_prover_mock(kel_input)

        prefix_b32 = prefix_to_bytes32(delegatee_pre)
        said_b32 = said_to_bytes32(dip_serder.said)

        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorEvent(
                prefix_b32, 0, said_b32, sp1_verifier, contract_proof
            ),
            gas=500_000,
        )
        assert receipt.status == 1, (
            f"anchorEvent (dip) reverted. Gas: {receipt.gasUsed}"
        )
        assert contract.functions.isAnchored(prefix_b32, 0, said_b32).call(), (
            "isAnchored() should return True after dip anchor"
        )

    def test_dip_drt_pipeline(self, w3, contract_with_zk, backer_account):
        """Delegated rotation: dip + drt KEL → real guest → anchorEvent → isAnchored."""
        from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32

        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        delegatee_pre, kel_store, drt_serder = self._make_dip_drt_kel_store()

        kel_input = build_kel_input(kel_store, delegatee_pre, target_sn=1)

        contract_proof, public_values, _ = _run_sp1_prover_mock(kel_input)

        prefix_b32 = prefix_to_bytes32(delegatee_pre)
        said_b32 = said_to_bytes32(drt_serder.said)

        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorEvent(
                prefix_b32, 1, said_b32, sp1_verifier, contract_proof
            ),
            gas=500_000,
        )
        assert receipt.status == 1, (
            f"anchorEvent (dip+drt) reverted. Gas: {receipt.gasUsed}"
        )
        assert contract.functions.isAnchored(prefix_b32, 1, said_b32).call()


# ---------------------------------------------------------------------------
# TEL prover binary tests (uses sp1-tel-prover with SP1_PROVER=mock)
# ---------------------------------------------------------------------------

import os as _os  # noqa: E402 — needed for TEL_PROVER_AVAILABLE check

TEL_PROVER_AVAILABLE = TEL_PROVER_BIN.exists()


@pytest.mark.skipif(
    not TEL_PROVER_AVAILABLE,
    reason=f"sp1-tel-prover binary not found at {TEL_PROVER_BIN}. Build with: cargo build --release",
)
class TestTELProverBinaryFast:
    """Run sp1-tel-prover binary with SP1_PROVER=mock.

    The TEL guest ELF executes in simulation: blake3 SAID verification
    and anchor seal check run inside the zkVM. Proof bytes are empty.
    SP1MockVerifier accepts empty proofs.
    """

    def _run_tel_prover_mock(self, tel_input: dict) -> tuple[bytes, bytes, str]:
        """Run generate_tel_proof with SP1_PROVER=mock."""
        from evm_backer.proofs import generate_tel_proof
        old_val = os.environ.get("SP1_PROVER")
        os.environ["SP1_PROVER"] = "mock"
        try:
            return generate_tel_proof(tel_input)
        finally:
            if old_val is None:
                os.environ.pop("SP1_PROVER", None)
            else:
                os.environ["SP1_PROVER"] = old_val

    def _make_tel_iss_store(self):
        """Build kel_store + TEL iss serder for testing."""
        from tests.test_tel import _make_iss_event

        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        keys0 = [signer0.verfer.qb64]
        nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]
        icp_serder = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
        ctrl_pre = icp_serder.ked["i"]
        icp_sig = signer0.sign(ser=icp_serder.raw).raw

        registry_prefix = "ETestTELRegistryForBinaryTest0000000000000"
        iss_serder = _make_iss_event(registry_prefix, tel_sn=0)

        ixn_serder = interact(
            pre=ctrl_pre,
            dig=icp_serder.said,
            sn=1,
            data=[{"i": registry_prefix, "s": "0", "d": iss_serder.said}],
        )
        ixn_sig = signer0.sign(ser=ixn_serder.raw).raw

        kel_store = {
            (ctrl_pre, 0): {"serder": icp_serder, "sigs": [(0, icp_sig)]},
            (ctrl_pre, 1): {"serder": ixn_serder, "sigs": [(0, ixn_sig)]},
        }
        return ctrl_pre, kel_store, iss_serder, registry_prefix

    def test_tel_binary_produces_correct_public_values(self):
        """TEL guest ELF executes; public values = 192-byte abi.encode."""
        from eth_abi import decode as abi_decode
        from evm_backer.proofs import build_tel_input

        ctrl_pre, kel_store, iss_serder, registry_prefix = self._make_tel_iss_store()
        tel_input = build_tel_input(
            kel_store, iss_serder, registry_prefix, ctrl_pre, tel_sn=0
        )

        contract_proof, public_values, vkey = self._run_tel_prover_mock(tel_input)

        # Public values must be 192 bytes.
        assert len(public_values) == 192, (
            f"TEL public values must be 192 bytes, got {len(public_values)}"
        )

        # vkey: 0x-prefixed 32-byte hex.
        assert vkey.startswith("0x"), f"vkey must start with 0x, got: {vkey!r}"
        assert len(bytes.fromhex(vkey[2:])) == 32

        # contract_proof = abi.encode(publicValues, proofBytes).
        inner_pv, inner_pb = abi_decode(["bytes", "bytes"], contract_proof)
        assert inner_pv == public_values
        assert inner_pb == b"", "mock mode must produce empty proof bytes"

    def test_iss_pipeline(self, w3, contract_with_zk, backer_account):
        """iss event: anchor controller ixn on-chain → TEL proof → anchorEvent → isAnchored."""
        pytest.skip(
            "Full iss pipeline requires separate tel_contracts fixture — use test_tel.py"
        )

    def test_wrong_anchor_reverts(self, w3, tel_contracts, backer_account):
        """TEL proof with wrong anchor sn → revert from SP1TELVerifier."""
        from evm_backer.proofs import build_tel_input
        from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32

        kb = tel_contracts["kb"]
        kel_verifier = tel_contracts["kel_verifier_addr"]
        tel_verifier = tel_contracts["tel_verifier_addr"]

        from eth_account import Account
        backer = Account.from_key(ANVIL_BACKER_KEY)

        ctrl_pre, kel_store, iss_serder, registry_prefix = self._make_tel_iss_store()

        # Anchor controller ixn on THIS kb (tel_contracts fixture's KERIBacker).
        ctrl_prefix_b32 = prefix_to_bytes32(ctrl_pre)
        ixn_serder = kel_store[(ctrl_pre, 1)]["serder"]
        ixn_said_b32 = said_to_bytes32(ixn_serder.said)

        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [ctrl_prefix_b32, 1, ixn_said_b32],
        )
        kel_msg_hash = Web3.keccak(encoded)
        kel_contract_proof, _ = make_mock_sp1_proof(kel_msg_hash)

        receipt = _build_and_send(
            w3, backer,
            kb.functions.anchorEvent(
                ctrl_prefix_b32, 1, ixn_said_b32, kel_verifier, kel_contract_proof
            ),
        )
        assert receipt.status == 1, "KEL anchor failed"

        # Build TEL input and proof via the binary.
        tel_input = build_tel_input(
            kel_store, iss_serder, registry_prefix, ctrl_pre, tel_sn=0
        )
        contract_proof, public_values, _ = self._run_tel_prover_mock(tel_input)

        # Try to anchor with WRONG anchor_sn (99 instead of 1) → should revert.
        registry_b32 = Web3.keccak(text=registry_prefix)
        tel_said_b32 = said_to_bytes32(iss_serder.said)
        wrong_anchor_said_b32 = Web3.keccak(text="wrong_anchor_said_for_sn99")

        # Build proof that claims anchor_sn=99 (not on-chain).
        wrong_tel_proof, _ = make_mock_tel_proof(
            registry_b32, 0, tel_said_b32,
            ctrl_prefix_b32, 99, wrong_anchor_said_b32,
        )

        tx = kb.functions.anchorEvent(
            registry_b32, 0, tel_said_b32, tel_verifier, wrong_tel_proof
        ).build_transaction({
            "from": backer.address,
            "nonce": w3.eth.get_transaction_count(backer.address, "pending"),
            "chainId": w3.eth.chain_id,
            "gas": 500_000,
        })
        signed = backer.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt.status == 0, (
            "anchorEvent should revert when anchor_sn not on-chain"
        )


# ---------------------------------------------------------------------------
# Multi-sig KEL tests (2-of-3 threshold signing)
# ---------------------------------------------------------------------------


class TestMultiSigKEL:
    """Tests for M-of-N threshold signing in KERI KEL verification.

    Uses keripy's incept() with kt="2" to build real 2-of-3 multi-sig events,
    runs build_kel_input() → make_mock_sp1_proof() → anchorEvent → isAnchored.
    """

    def _make_2of3_kel_store(self):
        """Build a 2-of-3 icp KEL store.

        Returns (prefix_qb64, kel_store, icp_serder).
        """
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        signer2 = Signer(raw=SEED_2, transferable=True)

        keys = [signer0.verfer.qb64, signer1.verfer.qb64, signer2.verfer.qb64]
        # Next key digests: commit to signer0, signer1, signer2 again (for rotation)
        nxt = [
            Diger(ser=signer0.verfer.qb64b).qb64,
            Diger(ser=signer1.verfer.qb64b).qb64,
            Diger(ser=signer2.verfer.qb64b).qb64,
        ]

        # isith=2 sets kt="2" in the event KED; nsith=2 sets nt="2".
        icp_serder = incept(keys=keys, ndigs=nxt, isith=2, nsith=2, code=MtrDex.Blake3_256)
        pre = icp_serder.ked["i"]

        # Sign with signer0 (idx=0) and signer1 (idx=1) — 2-of-3.
        sig0 = signer0.sign(ser=icp_serder.raw).raw
        sig1 = signer1.sign(ser=icp_serder.raw).raw

        kel_store = {
            (pre, 0): {"serder": icp_serder, "sigs": [(0, sig0), (1, sig1)]},
        }
        return pre, kel_store, icp_serder

    def _make_2of3_with_rotation_kel_store(self):
        """Build a 2-of-3 icp → rot KEL store.

        icp: keys=[k0,k1,k2], isith=2, signed by k0+k1.
        rot: rotates to [k0,k1,k2] again (same keys for simplicity), signed by k0+k1.

        Returns (prefix_qb64, kel_store, rot_serder).
        """
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        signer2 = Signer(raw=SEED_2, transferable=True)

        keys = [signer0.verfer.qb64, signer1.verfer.qb64, signer2.verfer.qb64]
        # Pre-rotation commitment: commit to all three keys again.
        nxt = [
            Diger(ser=signer0.verfer.qb64b).qb64,
            Diger(ser=signer1.verfer.qb64b).qb64,
            Diger(ser=signer2.verfer.qb64b).qb64,
        ]

        icp_serder = incept(keys=keys, ndigs=nxt, isith=2, nsith=2, code=MtrDex.Blake3_256)
        pre = icp_serder.ked["i"]
        sig0_icp = signer0.sign(ser=icp_serder.raw).raw
        sig1_icp = signer1.sign(ser=icp_serder.raw).raw

        # rot: new keys = same 3 keys, signed by current k0+k1.
        rot_serder = rotate(
            pre=pre, keys=keys, dig=icp_serder.said, ndigs=[], sn=1, isith=2
        )
        sig0_rot = signer0.sign(ser=rot_serder.raw).raw
        sig1_rot = signer1.sign(ser=rot_serder.raw).raw

        kel_store = {
            (pre, 0): {"serder": icp_serder, "sigs": [(0, sig0_icp), (1, sig1_icp)]},
            (pre, 1): {"serder": rot_serder, "sigs": [(0, sig0_rot), (1, sig1_rot)]},
        }
        return pre, kel_store, rot_serder

    def test_2of3_icp_mock_proof(self, w3, contract_with_zk, backer_account):
        """2-of-3 icp: build_kel_input → make_mock_sp1_proof → anchorEvent → isAnchored."""
        from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32

        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        pre, kel_store, icp_serder = self._make_2of3_kel_store()
        kel_input = build_kel_input(kel_store, pre, target_sn=0)

        # Verify the kel_input has 2 sigs and kt=2.
        assert len(kel_input["events"][0]["signatures"]) == 2
        assert kel_input["events"][0]["kt"] == 2
        assert len(kel_input["initial_keys_qb64"]) == 3

        prefix_b32 = prefix_to_bytes32(pre)
        said_b32 = said_to_bytes32(icp_serder.said)

        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, 0, said_b32],
        )
        msg_hash = Web3.keccak(encoded)
        contract_proof, _ = make_mock_sp1_proof(msg_hash)

        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorEvent(
                prefix_b32, 0, said_b32, sp1_verifier, contract_proof
            ),
        )
        assert receipt.status == 1, (
            f"anchorEvent (2-of-3 icp) reverted. Gas: {receipt.gasUsed}"
        )
        assert contract.functions.isAnchored(prefix_b32, 0, said_b32).call(), (
            "isAnchored() should return True after 2-of-3 icp anchor"
        )

    def test_2of3_rotation(self, w3, contract_with_zk, backer_account):
        """2-of-3 icp → rot: build_kel_input → make_mock_sp1_proof → anchorEvent → isAnchored."""
        from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32

        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        pre, kel_store, rot_serder = self._make_2of3_with_rotation_kel_store()
        kel_input = build_kel_input(kel_store, pre, target_sn=1)

        # Verify the kel_input structure.
        assert len(kel_input["events"][1]["signatures"]) == 2
        assert kel_input["events"][1]["kt"] == 2
        assert len(kel_input["events"][1]["new_key_qb64s"]) == 3

        prefix_b32 = prefix_to_bytes32(pre)
        said_b32 = said_to_bytes32(rot_serder.said)

        encoded = w3.codec.encode(
            ["bytes32", "uint64", "bytes32"],
            [prefix_b32, 1, said_b32],
        )
        msg_hash = Web3.keccak(encoded)
        contract_proof, _ = make_mock_sp1_proof(msg_hash)

        receipt = _build_and_send(
            w3, backer_account,
            contract.functions.anchorEvent(
                prefix_b32, 1, said_b32, sp1_verifier, contract_proof
            ),
        )
        assert receipt.status == 1, (
            f"anchorEvent (2-of-3 rotation) reverted. Gas: {receipt.gasUsed}"
        )
        assert contract.functions.isAnchored(prefix_b32, 1, said_b32).call(), (
            "isAnchored() should return True after 2-of-3 rotation anchor"
        )

    @pytest.mark.skipif(
        not SP1_PROVER_AVAILABLE,
        reason=f"sp1-prover binary not found at {PROVER_BIN}. Build with: cargo build --release",
    )
    def test_threshold_not_met_panics(self):
        """build_kel_input with only 1 sig when kt=2: guest reports threshold violation.

        In SP1 mock mode, guest panics appear in stderr and publicValues is empty
        (no valid message_hash committed). The Rust unit test test_multisig_threshold_not_met
        verifies the panic behavior at the library level.
        """
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        signer2 = Signer(raw=SEED_2, transferable=True)

        keys = [signer0.verfer.qb64, signer1.verfer.qb64, signer2.verfer.qb64]
        icp_serder = incept(keys=keys, ndigs=[], isith=2, code=MtrDex.Blake3_256)
        pre = icp_serder.ked["i"]
        # Only sign with signer0 — kt=2 requires 2.
        sig0 = signer0.sign(ser=icp_serder.raw).raw

        kel_store = {
            (pre, 0): {"serder": icp_serder, "sigs": [(0, sig0)]},
        }
        kel_input = build_kel_input(kel_store, pre, target_sn=0)

        # Verify kt=2 but only 1 sig in the kel_input.
        assert kel_input["events"][0]["kt"] == 2
        assert len(kel_input["events"][0]["signatures"]) == 1

        # Run the sp1-prover binary; the guest should detect the threshold violation.
        import subprocess
        import json as _json
        json_bytes = _json.dumps(kel_input).encode()
        result = subprocess.run(
            [str(PROVER_BIN), json_bytes.hex()],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "SP1_PROVER": "mock"},
        )
        # In SP1 mock mode, the guest panic is logged to stderr.
        assert "threshold not met" in (result.stderr + result.stdout), (
            f"Expected 'threshold not met' in output.\nstderr: {result.stderr}\nstdout: {result.stdout}"
        )
        # The prover exits 0 in mock mode but emits empty publicValues (no committed hash).
        if result.returncode == 0:
            data = _json.loads(result.stdout.strip().splitlines()[-1])
            assert data.get("publicValues", "") == "", (
                f"Expected empty publicValues on threshold violation, got: {data.get('publicValues')}"
            )
