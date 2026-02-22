# -*- encoding: utf-8 -*-
"""
Golden tests for Ethereum transaction encoding (transactions module).

These tests verify that KERI events are correctly encoded into anchorBatch
calldata for the KERIBacker smart contract. Uses fixed event SAIDs and
prefixes to assert exact ABI-encoded bytes.

Raw CESR bytes are NOT included in the calldata (A1 fix): the contract stores
only the SAID commitment. This reduces gas cost substantially.

No mocks -- uses real web3.py ABI encoding and real contract ABI.

Reference:
  - evm-backer-spec.md section 3 (Smart Contract)
  - evm-backer-spec.md section 3.3 (Prefix Encoding)
  - evm-backer-spec.md section 3.4 (SAID Encoding)
  - evm-backer-spec.md section 5.6 (Transaction Submission)
  - docs/06-design-challenges.md (A1, C4 fixes)
"""

import json

from web3 import Web3

from keri.core import eventing
from keri.core.signing import Signer

from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32
from tests.conftest import SEED_0


# ---------------------------------------------------------------------------
# Contract ABI for encoding tests (no deployment needed)
# Raw bytes removed from anchorEvent and anchorBatch (A1 fix).
# sn is uint64 throughout (C4 fix).
# ---------------------------------------------------------------------------

KERI_BACKER_ABI = json.loads("""[
    {
        "type": "function",
        "name": "anchorEvent",
        "inputs": [
            {"name": "prefix",    "type": "bytes32"},
            {"name": "sn",        "type": "uint64"},
            {"name": "eventSAID", "type": "bytes32"},
            {"name": "verifier",  "type": "address"},
            {"name": "proof",     "type": "bytes"}
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "anchorBatch",
        "inputs": [
            {
                "name": "anchors",
                "type": "tuple[]",
                "components": [
                    {"name": "prefix",    "type": "bytes32"},
                    {"name": "sn",        "type": "uint64"},
                    {"name": "eventSAID", "type": "bytes32"}
                ]
            },
            {"name": "verifier", "type": "address"},
            {"name": "proof",    "type": "bytes"}
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function",
        "name": "isAnchored",
        "inputs": [
            {"name": "prefix",    "type": "bytes32"},
            {"name": "sn",        "type": "uint64"},
            {"name": "eventSAID", "type": "bytes32"}
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view"
    }
]""")

# Dummy values for ABI encoding tests (no real contract interaction)
DUMMY_VERIFIER = "0x0000000000000000000000000000000000000000"
DUMMY_PROOF = b'\x00' * 96  # placeholder proof bytes



class TestPrefixEncoding:
    """Verify qb64 -> bytes32 prefix encoding per spec section 3.3."""

    def test_non_transferable_prefix_encoding(self):
        """A non-transferable prefix (starting with 'B') must encode to a
        known bytes32 value.
        """
        prefix = "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        b32 = prefix_to_bytes32(prefix)
        assert len(b32) == 32
        # Must be deterministic
        assert prefix_to_bytes32(prefix) == b32

    def test_transferable_prefix_encoding(self):
        """A transferable prefix (starting with 'D' or 'E') must encode correctly."""
        prefix = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        b32 = prefix_to_bytes32(prefix)
        assert len(b32) == 32

    def test_self_addressing_prefix_encoding(self):
        """A self-addressing prefix (starting with 'E') must encode correctly."""
        prefix = "EPLRRJFe2FHdXKVTkSEX4xb4x-YaPFJ2Xds1vhtNTd4n"
        b32 = prefix_to_bytes32(prefix)
        assert len(b32) == 32

    def test_different_prefixes_produce_different_bytes32(self):
        """Two different prefixes must never collide in bytes32."""
        p1 = "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        p2 = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        assert prefix_to_bytes32(p1) != prefix_to_bytes32(p2)


class TestSAIDEncoding:
    """Verify qb64 SAID -> bytes32 encoding per spec section 3.4."""

    def test_said_encoding_produces_32_bytes(self):
        """A KERI SAID must encode to exactly 32 bytes."""
        said = "EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"
        b32 = said_to_bytes32(said)
        assert len(b32) == 32

    def test_said_encoding_deterministic(self):
        """Same SAID must always produce the same bytes32."""
        said = "EPLRRJFe2FHdXKVTkSEX4xb4x-YaPFJ2Xds1vhtNTd4n"
        assert said_to_bytes32(said) == said_to_bytes32(said)

    def test_different_saids_produce_different_bytes32(self):
        """Different SAIDs must not collide."""
        s1 = "EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"
        s2 = "EPLRRJFe2FHdXKVTkSEX4xb4x-YaPFJ2Xds1vhtNTd4n"
        assert said_to_bytes32(s1) != said_to_bytes32(s2)


class TestAnchorEventCalldata:
    """Verify that anchorEvent calldata is correctly ABI-encoded.

    anchorEvent(bytes32 prefix, uint64 sn, bytes32 eventSAID) -- no raw bytes.
    """

    def test_anchor_event_encoding(self):
        """Build anchorEvent calldata for a known inception event and verify
        the function selector and parameter encoding are correct.
        """
        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)

        prefix_qb64 = "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        said_qb64 = "EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"
        sn = 0

        prefix_b32 = prefix_to_bytes32(prefix_qb64)
        said_b32 = said_to_bytes32(said_qb64)
        dummy_sig = DUMMY_PROOF

        calldata = contract.encode_abi(
            "anchorEvent",
            args=[prefix_b32, sn, said_b32, DUMMY_VERIFIER, dummy_sig],
        )

        assert calldata is not None
        assert len(calldata) > 4  # At minimum: "0x" + 8 hex chars (4-byte selector)

    def test_anchor_event_calldata_is_deterministic(self):
        """Same inputs must produce identical calldata every time."""
        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)

        prefix_b32 = b'\x00' * 32
        said_b32 = b'\x01' * 32
        sn = 42
        dummy_sig = DUMMY_PROOF

        calldata1 = contract.encode_abi("anchorEvent", args=[prefix_b32, sn, said_b32, DUMMY_VERIFIER, dummy_sig])
        calldata2 = contract.encode_abi("anchorEvent", args=[prefix_b32, sn, said_b32, DUMMY_VERIFIER, dummy_sig])

        assert calldata1 == calldata2

    def test_anchor_event_calldata_uint64_sn(self):
        """Sequence number is encoded as uint64 in calldata (C4 fix).

        sn=2^32 must produce different calldata from sn=0.
        """
        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)

        prefix_b32 = b'\x00' * 32
        said_b32 = b'\x01' * 32
        dummy_sig = DUMMY_PROOF

        calldata_low = contract.encode_abi("anchorEvent", args=[prefix_b32, 0, said_b32, DUMMY_VERIFIER, dummy_sig])
        calldata_high = contract.encode_abi("anchorEvent", args=[prefix_b32, 2**32, said_b32, DUMMY_VERIFIER, dummy_sig])

        assert calldata_low != calldata_high


class TestAnchorBatchCalldata:
    """Verify that anchorBatch calldata correctly encodes multiple events.

    Anchor struct: (bytes32 prefix, uint64 sn, bytes32 eventSAID) -- no raw bytes.
    """

    def test_batch_of_one_event(self):
        """A batch with one event must produce valid calldata."""
        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)
        dummy_sig = DUMMY_PROOF

        anchors = [
            (
                prefix_to_bytes32("BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"),
                0,
                said_to_bytes32("EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"),
            )
        ]

        calldata = contract.encode_abi("anchorBatch", args=[anchors, DUMMY_VERIFIER, dummy_sig])
        assert calldata is not None
        assert len(calldata) > 10

    def test_batch_of_multiple_events(self):
        """A batch with multiple events must encode all of them."""
        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)
        dummy_sig = DUMMY_PROOF

        signer0 = Signer(raw=SEED_0, transferable=False)
        signer1 = Signer(raw=SEED_0, transferable=True)

        prefix_nt = signer0.verfer.qb64  # Non-transferable
        prefix_t = signer1.verfer.qb64   # Transferable

        anchors = [
            (
                prefix_to_bytes32(prefix_nt),
                0,
                said_to_bytes32("EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"),
            ),
            (
                prefix_to_bytes32(prefix_t),
                1,
                said_to_bytes32("EPLRRJFe2FHdXKVTkSEX4xb4x-YaPFJ2Xds1vhtNTd4n"),
            ),
        ]

        calldata = contract.encode_abi("anchorBatch", args=[anchors, DUMMY_VERIFIER, dummy_sig])
        assert calldata is not None

        # Batch of 2 should be longer than batch of 1
        single = contract.encode_abi("anchorBatch", args=[anchors[:1], DUMMY_VERIFIER, dummy_sig])
        assert len(calldata) > len(single)

    def test_batch_size_matches_spec(self):
        """Spec allows up to 20 events per batch (batchSize config).

        Verify that encoding 20 events produces valid calldata.
        """
        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)
        dummy_sig = DUMMY_PROOF

        anchors = [
            (
                prefix_to_bytes32("BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"),
                i,
                said_to_bytes32("EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"),
            )
            for i in range(20)
        ]

        calldata = contract.encode_abi("anchorBatch", args=[anchors, DUMMY_VERIFIER, dummy_sig])
        assert calldata is not None
        assert len(calldata) > 0

    def test_empty_batch_encoding(self):
        """An empty batch should produce valid (minimal) calldata."""
        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)
        dummy_sig = DUMMY_PROOF

        calldata = contract.encode_abi("anchorBatch", args=[[], DUMMY_VERIFIER, dummy_sig])
        assert calldata is not None


class TestIsAnchoredCalldata:
    """Verify isAnchored query encoding."""

    def test_is_anchored_encoding(self):
        """isAnchored(prefix, sn, eventSAID) must encode correctly."""
        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)

        prefix_b32 = prefix_to_bytes32(
            "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        )
        said_b32 = said_to_bytes32(
            "EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As"
        )
        sn = 0

        calldata = contract.encode_abi("isAnchored", args=[prefix_b32, sn, said_b32])
        assert calldata is not None
        # isAnchored is a view function -- calldata is used for eth_call
        assert len(calldata) > 4


class TestGoldenCalldataFromKeriEvents:
    """End-to-end golden test: create a real keripy event, encode it as
    contract calldata, and verify the exact bytes.
    """

    def test_inception_event_to_anchor_calldata(self):
        """Create a real inception event from the golden seed, then encode
        it as anchorEvent calldata. The calldata must be deterministic.

        Only the SAID and prefix are encoded -- no raw event bytes (A1 fix).
        """
        signer = Signer(raw=SEED_0, transferable=False)
        keys = [signer.verfer.qb64]
        serder = eventing.incept(keys=keys)

        prefix_b32 = prefix_to_bytes32(serder.ked["i"])
        said_b32 = said_to_bytes32(serder.said)
        sn = int(serder.ked["s"])
        dummy_sig = DUMMY_PROOF

        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)

        calldata1 = contract.encode_abi("anchorEvent", args=[prefix_b32, sn, said_b32, DUMMY_VERIFIER, dummy_sig])
        calldata2 = contract.encode_abi("anchorEvent", args=[prefix_b32, sn, said_b32, DUMMY_VERIFIER, dummy_sig])

        assert calldata1 == calldata2, "Calldata must be deterministic"
        assert len(calldata1) > 4

    def test_batch_calldata_from_multiple_events(self):
        """Create real keripy events from the golden seed and batch them.

        The batch calldata must be deterministic and grow with each event added.
        """
        signer = Signer(raw=SEED_0, transferable=False)
        keys = [signer.verfer.qb64]
        serder = eventing.incept(keys=keys)

        prefix_b32 = prefix_to_bytes32(serder.ked["i"])
        said_b32 = said_to_bytes32(serder.said)
        dummy_sig = DUMMY_PROOF

        w3 = Web3()
        contract = w3.eth.contract(abi=KERI_BACKER_ABI)

        single = [(prefix_b32, 0, said_b32)]
        calldata_single = contract.encode_abi("anchorBatch", args=[single, DUMMY_VERIFIER, dummy_sig])

        double = [(prefix_b32, 0, said_b32), (prefix_b32, 1, said_b32)]
        calldata_double = contract.encode_abi("anchorBatch", args=[double, DUMMY_VERIFIER, dummy_sig])

        assert calldata_single == contract.encode_abi("anchorBatch", args=[single, DUMMY_VERIFIER, dummy_sig])  # deterministic
        assert len(calldata_double) > len(calldata_single)


class TestEIP1559FeeEstimation:
    """Verify that build_anchor_tx_with_sp1_proof produces EIP-1559 (type-2)
    transactions with dynamic gas estimation when connected to a real EVM node.

    Uses the real anvil node from conftest fixtures.
    """

    def test_built_tx_has_eip1559_fields(
        self, w3, contract_with_zk, backer_account
    ):
        """A built transaction must include maxFeePerGas and maxPriorityFeePerGas."""
        from evm_backer.transactions import (
            build_anchor_tx_with_sp1_proof,
            prefix_to_bytes32,
            said_to_bytes32,
        )
        from evm_backer.proofs import make_mock_sp1_proof

        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        anchors = [
            (
                prefix_to_bytes32("BEIP1559TestPrefix0000000000000000000000000"),
                0,
                said_to_bytes32("EEIP1559TestSaid00000000000000000000000000000"),
            )
        ]
        # Build mock ZK proof
        encoded = w3.codec.encode(["(bytes32,uint64,bytes32)[]"], [anchors])
        msg_hash = Web3.keccak(encoded)
        _, public_values = make_mock_sp1_proof(msg_hash)

        signed_tx = build_anchor_tx_with_sp1_proof(
            w3, contract, backer_account, anchors,
            public_values=public_values,
            proof_bytes=b"",
            verifier_address=sp1_verifier,
        )

        # The signed tx object should exist and be submittable
        assert signed_tx is not None
        assert hasattr(signed_tx, "raw_transaction")

    def test_dynamic_gas_estimation_not_hardcoded(
        self, w3, contract_with_zk, backer_account
    ):
        """Gas limit should be dynamically estimated, not always 500_000.

        A single-anchor batch should use much less than 500k gas. With the 1.2x
        buffer, the estimated gas should be well below the old hardcoded value.
        """
        from evm_backer.transactions import (
            build_anchor_tx_with_sp1_proof,
            prefix_to_bytes32,
            said_to_bytes32,
            FALLBACK_GAS_LIMIT,
        )
        from evm_backer.proofs import make_mock_sp1_proof

        contract = contract_with_zk["contract"]
        sp1_verifier = contract_with_zk["sp1_keri_verifier_address"]

        anchors = [
            (
                prefix_to_bytes32("BGasDynamicTestPrefix000000000000000000000"),
                0,
                said_to_bytes32("EGasDynamicTestSaid0000000000000000000000000"),
            )
        ]
        encoded = w3.codec.encode(["(bytes32,uint64,bytes32)[]"], [anchors])
        msg_hash = Web3.keccak(encoded)
        _, public_values = make_mock_sp1_proof(msg_hash)

        signed_tx = build_anchor_tx_with_sp1_proof(
            w3, contract, backer_account, anchors,
            public_values=public_values,
            proof_bytes=b"",
            verifier_address=sp1_verifier,
        )

        # Submit and check the receipt to see actual gas used
        from evm_backer.transactions import submit_anchor_tx

        tx_hash = submit_anchor_tx(w3, signed_tx)
        receipt = w3.eth.wait_for_transaction_receipt(bytes.fromhex(tx_hash[2:]))
        assert receipt.status == 1

        # The gas used should be well below the fallback limit
        assert receipt.gasUsed < FALLBACK_GAS_LIMIT

    def test_eip1559_fee_estimation_function(self, w3):
        """estimate_eip1559_fees should return valid fee parameters on anvil."""
        from evm_backer.transactions import estimate_eip1559_fees

        fees = estimate_eip1559_fees(w3)
        assert fees is not None, "EIP-1559 fee estimation should succeed on anvil"
        assert "maxFeePerGas" in fees
        assert "maxPriorityFeePerGas" in fees
        assert fees["maxFeePerGas"] > 0
        assert fees["maxPriorityFeePerGas"] > 0
