# -*- encoding: utf-8 -*-
"""
EVM Backer TEL Mock Proof Integration Tests

Tests for SP1TELVerifier using SP1MockVerifier.

These tests verify:
- TEL events (iss, rev) can be anchored on KERIBacker via SP1TELVerifier.
- The controller's KEL anchor event must be on-chain before TEL anchoring.
- Wrong TEL message hash causes revert.
- Missing KEL anchor event causes revert.

All tests use mock SP1 proofs (SP1_PROVER is not needed).

Run:
    uv run pytest tests/test_tel.py -v
"""

import json

import pytest
from web3 import Web3

from keri.core.coring import Diger, MtrDex
from keri.core.eventing import incept, interact
from keri.core.signing import Signer

from tests.conftest import (
    ANVIL_BACKER_KEY,
    ANVIL_DEPLOYER_ADDRESS,
    ANVIL_DEPLOYER_KEY,
    CONTRACTS_DIR,
    SEED_0,
    SEED_1,
    _forge_create,
    _load_abi,
    _call_contract,
)
from evm_backer.proofs import (
    build_tel_input,
    make_mock_sp1_proof,
    make_mock_tel_proof,
)
from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32

# ---------------------------------------------------------------------------
# TEL event helpers
# ---------------------------------------------------------------------------


class _MinimalSerder:
    """Minimal stand-in for keripy Serder with .raw, .said, and .ked."""

    def __init__(self, raw: bytes, said: str, ked: dict):
        self.raw = raw
        self.said = said
        self.ked = ked


def _make_iss_event(registry_prefix_qb64: str, tel_sn: int = 0) -> _MinimalSerder:
    """Build a minimal KERI TEL iss event with a proper blake3 SAID.

    Creates a minimal iss event JSON, computes its SAID via Diger (blake3),
    and returns a serder-like object with .raw and .said attributes.
    """
    placeholder = b"#" * 44
    ked_template = {
        "t": "iss",
        "d": "#" * 44,
        "ri": registry_prefix_qb64,
        "s": str(tel_sn),
    }
    preimage = json.dumps(ked_template, separators=(",", ":")).encode()
    diger = Diger(ser=preimage, code=MtrDex.Blake3_256)
    said_qb64 = diger.qb64
    raw = preimage.replace(placeholder, said_qb64.encode())
    ked = dict(ked_template)
    ked["d"] = said_qb64
    return _MinimalSerder(raw, said_qb64, ked)


def _make_rev_event(
    registry_prefix_qb64: str, tel_sn: int, prev_said_qb64: str
) -> _MinimalSerder:
    """Build a minimal KERI TEL rev event."""
    placeholder = b"#" * 44
    ked_template = {
        "t": "rev",
        "d": "#" * 44,
        "ri": registry_prefix_qb64,
        "s": str(tel_sn),
        "p": prev_said_qb64,
    }
    preimage = json.dumps(ked_template, separators=(",", ":")).encode()
    diger = Diger(ser=preimage, code=MtrDex.Blake3_256)
    said_qb64 = diger.qb64
    raw = preimage.replace(placeholder, said_qb64.encode())
    ked = dict(ked_template)
    ked["d"] = said_qb64
    return _MinimalSerder(raw, said_qb64, ked)


# ---------------------------------------------------------------------------
# Build and send helper
# ---------------------------------------------------------------------------


def _build_and_send(w3, account, contract_fn, gas=500_000):
    """Build, sign, send, and return a transaction receipt."""
    tx = contract_fn.build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address, "pending"),
        "chainId": w3.eth.chain_id,
        "gas": gas,
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


# ---------------------------------------------------------------------------
# Contract setup fixture (class-scoped to avoid state conflicts)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helpers for anchoring KEL events
# ---------------------------------------------------------------------------


def _anchor_kel_event(w3, kb, kel_verifier_addr, backer_account,
                      ctrl_prefix_b32, sn, said_b32):
    """Anchor a controller KEL event using mock SP1 ZK proof."""
    encoded = w3.codec.encode(
        ["bytes32", "uint64", "bytes32"],
        [ctrl_prefix_b32, sn, said_b32],
    )
    msg_hash = Web3.keccak(encoded)
    contract_proof, _ = make_mock_sp1_proof(msg_hash)
    return _build_and_send(
        w3, backer_account,
        kb.functions.anchorEvent(
            ctrl_prefix_b32, sn, said_b32, kel_verifier_addr, contract_proof
        ),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTELMockProofs:
    """TEL event anchoring tests using SP1MockVerifier."""

    def test_mock_tel_anchor_iss_event(
        self, w3, tel_contracts, backer_account
    ):
        """Build iss TEL event, anchor controller ixn on-chain, anchor TEL iss."""
        kb = tel_contracts["kb"]
        kel_verifier = tel_contracts["kel_verifier_addr"]
        tel_verifier = tel_contracts["tel_verifier_addr"]

        from eth_account import Account
        backer = Account.from_key(ANVIL_BACKER_KEY)

        # Create a controller KEL (icp only).
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        keys0 = [signer0.verfer.qb64]
        nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]
        icp_serder = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
        ctrl_pre = icp_serder.ked["i"]

        # Create TEL registry and iss event.
        registry_prefix = "ETestTELRegistry000000000000000000000000000"
        iss_serder = _make_iss_event(registry_prefix, tel_sn=0)

        # Create controller ixn with the TEL anchor seal (sn=1).
        ixn_serder = interact(
            pre=ctrl_pre,
            dig=icp_serder.said,
            sn=1,
            data=[{"i": registry_prefix, "s": "0", "d": iss_serder.said}],
        )
        ixn_sig = signer0.sign(ser=ixn_serder.raw).raw

        kel_store = {
            (ctrl_pre, 0): {"serder": icp_serder, "sigs": [(0, signer0.sign(ser=icp_serder.raw).raw)]},
            (ctrl_pre, 1): {"serder": ixn_serder, "sigs": [(0, ixn_sig)]},
        }

        # Anchor controller ixn on KERIBacker (KEL ZK path).
        ctrl_prefix_b32 = prefix_to_bytes32(ctrl_pre)
        ixn_said_b32 = said_to_bytes32(ixn_serder.said)
        receipt = _anchor_kel_event(
            w3, kb, kel_verifier, backer, ctrl_prefix_b32, 1, ixn_said_b32
        )
        assert receipt.status == 1, "KEL anchor failed"
        assert kb.functions.isAnchored(ctrl_prefix_b32, 1, ixn_said_b32).call()

        # Build TEL input and anchor via SP1TELVerifier.
        registry_b32 = Web3.keccak(text=registry_prefix)
        tel_said_b32 = said_to_bytes32(iss_serder.said)
        anchor_said_b32 = said_to_bytes32(ixn_serder.said)

        tel_proof, _ = make_mock_tel_proof(
            registry_b32, 0, tel_said_b32,
            ctrl_prefix_b32, 1, anchor_said_b32,
        )

        receipt = _build_and_send(
            w3, backer,
            kb.functions.anchorEvent(
                registry_b32, 0, tel_said_b32, tel_verifier, tel_proof
            ),
        )
        assert receipt.status == 1, (
            f"TEL anchorEvent failed. Gas: {receipt.gasUsed}"
        )
        assert kb.functions.isAnchored(registry_b32, 0, tel_said_b32).call(), (
            "isAnchored() should be True after TEL iss anchor"
        )

    def test_mock_tel_anchor_rev_event(
        self, w3, tel_contracts, backer_account
    ):
        """Build iss+rev TEL events, anchor rev on-chain."""
        kb = tel_contracts["kb"]
        kel_verifier = tel_contracts["kel_verifier_addr"]
        tel_verifier = tel_contracts["tel_verifier_addr"]

        from eth_account import Account
        backer = Account.from_key(ANVIL_BACKER_KEY)

        # Create controller KEL.
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        keys0 = [signer0.verfer.qb64]
        nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]
        icp_serder = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
        ctrl_pre = icp_serder.ked["i"]

        # Create TEL iss event.
        registry_prefix = "ETestTELRegistry111111111111111111111111111"
        iss_serder = _make_iss_event(registry_prefix, tel_sn=0)

        # Create TEL rev event (sn=1).
        rev_serder = _make_rev_event(registry_prefix, tel_sn=1, prev_said_qb64=iss_serder.said)

        # Create two controller ixn events: one for iss, one for rev.
        ixn1_serder = interact(
            pre=ctrl_pre,
            dig=icp_serder.said,
            sn=1,
            data=[{"i": registry_prefix, "s": "0", "d": iss_serder.said}],
        )
        ixn2_serder = interact(
            pre=ctrl_pre,
            dig=ixn1_serder.said,
            sn=2,
            data=[{"i": registry_prefix, "s": "1", "d": rev_serder.said}],
        )

        # Anchor both controller ixn events on KERIBacker.
        ctrl_prefix_b32 = prefix_to_bytes32(ctrl_pre)
        ixn1_said_b32 = said_to_bytes32(ixn1_serder.said)
        ixn2_said_b32 = said_to_bytes32(ixn2_serder.said)

        _anchor_kel_event(w3, kb, kel_verifier, backer, ctrl_prefix_b32, 1, ixn1_said_b32)
        _anchor_kel_event(w3, kb, kel_verifier, backer, ctrl_prefix_b32, 2, ixn2_said_b32)

        # Anchor TEL rev event via SP1TELVerifier.
        registry_b32 = Web3.keccak(text=registry_prefix)
        rev_said_b32 = said_to_bytes32(rev_serder.said)

        tel_proof, _ = make_mock_tel_proof(
            registry_b32, 1, rev_said_b32,
            ctrl_prefix_b32, 2, ixn2_said_b32,
        )

        receipt = _build_and_send(
            w3, backer,
            kb.functions.anchorEvent(
                registry_b32, 1, rev_said_b32, tel_verifier, tel_proof
            ),
        )
        assert receipt.status == 1, f"TEL rev anchor failed. Gas: {receipt.gasUsed}"
        assert kb.functions.isAnchored(registry_b32, 1, rev_said_b32).call()

    def test_wrong_tel_message_reverts(
        self, w3, tel_contracts, backer_account
    ):
        """Tampered TEL SAID in the proof → anchorEvent must revert."""
        kb = tel_contracts["kb"]
        kel_verifier = tel_contracts["kel_verifier_addr"]
        tel_verifier = tel_contracts["tel_verifier_addr"]

        from eth_account import Account
        backer = Account.from_key(ANVIL_BACKER_KEY)

        # Set up a controller KEL and TEL iss event.
        signer0 = Signer(raw=SEED_0, transferable=True)
        signer1 = Signer(raw=SEED_1, transferable=True)
        keys0 = [signer0.verfer.qb64]
        nxt1 = [Diger(ser=signer1.verfer.qb64b).qb64]
        icp_serder = incept(keys=keys0, ndigs=nxt1, code=MtrDex.Blake3_256)
        ctrl_pre = icp_serder.ked["i"]

        registry_prefix = "ETestTELRegistry222222222222222222222222222"
        iss_serder = _make_iss_event(registry_prefix, tel_sn=0)

        ixn_serder = interact(
            pre=ctrl_pre,
            dig=icp_serder.said,
            sn=1,
            data=[{"i": registry_prefix, "s": "0", "d": iss_serder.said}],
        )

        ctrl_prefix_b32 = prefix_to_bytes32(ctrl_pre)
        ixn_said_b32 = said_to_bytes32(ixn_serder.said)
        _anchor_kel_event(w3, kb, kel_verifier, backer, ctrl_prefix_b32, 1, ixn_said_b32)

        registry_b32 = Web3.keccak(text=registry_prefix)
        tel_said_b32 = said_to_bytes32(iss_serder.said)
        anchor_said_b32 = said_to_bytes32(ixn_serder.said)

        # Build proof with correct tel_said, but anchor with WRONG said.
        wrong_said_b32 = Web3.keccak(text="wrong_tel_said")
        tel_proof, _ = make_mock_tel_proof(
            registry_b32, 0, tel_said_b32,  # proof says correct SAID
            ctrl_prefix_b32, 1, anchor_said_b32,
        )

        # anchorEvent computes msgHash from (registry_b32, 0, wrong_said_b32)
        # but proof attests (registry_b32, 0, tel_said_b32) → mismatch → revert.
        tx = kb.functions.anchorEvent(
            registry_b32, 0, wrong_said_b32, tel_verifier, tel_proof
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
            "anchorEvent should revert when TEL proof SAID differs from passed SAID"
        )

    def test_missing_kel_anchor_reverts(
        self, w3, tel_contracts, backer_account
    ):
        """TEL proof where controller KEL event is NOT on-chain → revert."""
        kb = tel_contracts["kb"]
        tel_verifier = tel_contracts["tel_verifier_addr"]

        from eth_account import Account
        backer = Account.from_key(ANVIL_BACKER_KEY)

        # Build TEL iss event (do NOT anchor any KEL event).
        registry_prefix = "ETestTELRegistry333333333333333333333333333"
        iss_serder = _make_iss_event(registry_prefix, tel_sn=0)

        registry_b32 = Web3.keccak(text=registry_prefix)
        tel_said_b32 = said_to_bytes32(iss_serder.said)

        # Use a non-existent controller event.
        ctrl_prefix_b32 = Web3.keccak(text="nonexistent_controller")
        fake_anchor_said_b32 = Web3.keccak(text="nonexistent_anchor")

        tel_proof, _ = make_mock_tel_proof(
            registry_b32, 0, tel_said_b32,
            ctrl_prefix_b32, 5, fake_anchor_said_b32,  # not on-chain
        )

        tx = kb.functions.anchorEvent(
            registry_b32, 0, tel_said_b32, tel_verifier, tel_proof
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
            "anchorEvent should revert when controller KEL event not on-chain"
        )
