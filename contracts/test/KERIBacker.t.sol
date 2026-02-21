// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {KERIBacker} from "../src/KERIBacker.sol";
import {Ed25519Verifier} from "../src/Ed25519Verifier.sol";
import {SP1KERIVerifier} from "../src/SP1KERIVerifier.sol";
import {Ed25519} from "../src/Ed25519.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";

// =============================================================================
// Shared base: FFI signing helpers and the common Ed25519 test key
// =============================================================================

abstract contract KERIBackerTestBase is Test {
    // Ed25519 test key pair (RFC 8032 test vector 3)
    // seed: c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
    // pubkey: fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
    bytes32 public constant BACKER_PUBKEY =
        0xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025;

    /// @dev Sign a message with the test Ed25519 key via Python FFI and return
    ///      the encoded Ed25519Verifier proof: abi.encode(backerPubKey, r, s).
    function _sign(bytes memory message) internal returns (bytes memory) {
        string[] memory cmd = new string[](3);
        cmd[0] = "python3";
        cmd[1] = "test/sign_ed25519.py";
        cmd[2] = _toHex(message);
        bytes memory sig = vm.ffi(cmd);  // 64 bytes: r (32) + s (32)
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
        }
        return abi.encode(BACKER_PUBKEY, r, s);
    }

    function _toHex(bytes memory data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            result[i * 2]     = hexChars[uint8(data[i]) >> 4];
            result[i * 2 + 1] = hexChars[uint8(data[i]) & 0x0f];
        }
        return string(result);
    }
}

// =============================================================================
// Standard path tests (Ed25519 on-chain verification via Ed25519Verifier)
// =============================================================================

contract KERIBackerTest is KERIBackerTestBase {
    KERIBacker      public kb;
    Ed25519Verifier public ed25519Verifier;

    bytes32 public prefix1 = keccak256("AID_prefix_1");
    bytes32 public prefix2 = keccak256("AID_prefix_2");
    bytes32 public said1   = keccak256("event_said_1");
    bytes32 public said2   = keccak256("event_said_2");
    bytes32 public said3   = keccak256("event_said_3");

    event KERIEventAnchored(
        bytes32 indexed prefix,
        uint64  indexed sn,
        bytes32 indexed eventSAID,
        address         verifier
    );

    event DuplicityDetected(
        bytes32 indexed prefix,
        uint64  indexed sn,
        bytes32         firstSeenSAID,
        bytes32         conflictingSAID
    );

    event VerifierApproved(address indexed verifier);
    event VerifierRevoked(address indexed verifier);

    function setUp() public {
        // Deploy Ed25519Verifier with this test contract as owner, pre-approve test key
        ed25519Verifier = new Ed25519Verifier(address(this));
        ed25519Verifier.approveBacker(BACKER_PUBKEY);

        // Deploy KERIBacker with this test contract as owner, approve the verifier
        kb = new KERIBacker(address(this));
        kb.approveVerifier(address(ed25519Verifier));
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    function test_constructor_setsOwner() public view {
        assertEq(kb.owner(), address(this));
    }

    function test_constructor_rejectsZeroOwner() public {
        vm.expectRevert("KERIBacker: zero owner");
        new KERIBacker(address(0));
    }

    // =========================================================================
    // Ed25519 library
    // =========================================================================

    function test_ed25519_rfc8032_vector3() public pure {
        bytes32 pubKey = 0xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025;
        bytes32 r = 0x6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac;
        bytes32 s = 0x18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a;
        bytes memory message = hex"af82";
        assertTrue(Ed25519.verify(pubKey, r, s, message), "RFC 8032 test vector 3 should verify");
    }

    function test_ed25519_rejects_invalid_signature() public pure {
        bytes32 pubKey = 0xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025;
        bytes32 r = 0x6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac;
        bytes32 s = 0x18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a;
        bytes memory wrongMessage = hex"af83";
        assertFalse(Ed25519.verify(pubKey, r, s, wrongMessage), "Invalid signature should not verify");
    }

    // =========================================================================
    // Governance
    // =========================================================================

    function test_approveVerifier_setsMapping() public {
        address newVerifier = address(0xBEEF);
        assertFalse(kb.approvedVerifiers(newVerifier));
        kb.approveVerifier(newVerifier);
        assertTrue(kb.approvedVerifiers(newVerifier));
    }

    function test_approveVerifier_emitsEvent() public {
        address newVerifier = address(0xCAFE);
        vm.expectEmit(true, false, false, false);
        emit VerifierApproved(newVerifier);
        kb.approveVerifier(newVerifier);
    }

    function test_approveVerifier_onlyOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert("KERIBacker: not owner");
        kb.approveVerifier(address(0x1234));
    }

    function test_revokeVerifier_preventsAnchoring() public {
        // Revoke the verifier
        kb.revokeVerifier(address(ed25519Verifier));
        assertFalse(kb.approvedVerifiers(address(ed25519Verifier)));

        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        vm.expectRevert("KERIBacker: verifier not approved");
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof);
    }

    function test_revokeVerifier_emitsEvent() public {
        vm.expectEmit(true, false, false, false);
        emit VerifierRevoked(address(ed25519Verifier));
        kb.revokeVerifier(address(ed25519Verifier));
    }

    // =========================================================================
    // Access control
    // =========================================================================

    function test_anchorEvent_rejectsUnregisteredVerifier() public {
        address fakeVerifier = address(0x1234);
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        vm.expectRevert("KERIBacker: verifier not approved");
        kb.anchorEvent(prefix1, 0, said1, fakeVerifier, proof);
    }

    function test_anchorEvent_revertsWithInvalidSig() public {
        // Proof has correct structure but invalid r,s (all zeros)
        bytes memory badProof = abi.encode(BACKER_PUBKEY, bytes32(0), bytes32(0));
        vm.expectRevert("KERIBacker: verification failed");
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), badProof);
    }

    // =========================================================================
    // anchorEvent
    // =========================================================================

    function test_anchorEvent_storesRecord() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof);

        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertTrue(rec.exists);
        assertEq(rec.eventSAID, said1);
        assertEq(rec.blockNumber, uint64(block.number));
        assertEq(rec.verifier, address(ed25519Verifier));
    }

    function test_anchorEvent_emitsKERIEventAnchored() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _sign(abi.encodePacked(msgHash));

        vm.expectEmit(true, true, true, true);
        emit KERIEventAnchored(prefix1, 0, said1, address(ed25519Verifier));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof);
    }

    function test_anchorEvent_multipleSequenceNumbers() public {
        for (uint64 sn = 0; sn < 3; sn++) {
            bytes32 said = sn == 0 ? said1 : (sn == 1 ? said2 : said3);
            bytes32 msgHash = keccak256(abi.encode(prefix1, sn, said));
            bytes memory proof = _sign(abi.encodePacked(msgHash));
            kb.anchorEvent(prefix1, sn, said, address(ed25519Verifier), proof);
        }
        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix1, 1, said2));
        assertTrue(kb.isAnchored(prefix1, 2, said3));
    }

    function test_anchorEvent_multiplePrefixes() public {
        bytes32 msg1 = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof1 = _sign(abi.encodePacked(msg1));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof1);

        bytes32 msg2 = keccak256(abi.encode(prefix2, uint64(0), said2));
        bytes memory proof2 = _sign(abi.encodePacked(msg2));
        kb.anchorEvent(prefix2, 0, said2, address(ed25519Verifier), proof2);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix2, 0, said2));
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    // =========================================================================
    // First-seen policy
    // =========================================================================

    function test_firstSeen_idempotentResubmission() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof);

        vm.recordLogs();
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof);

        VmSafe.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            assertTrue(
                logs[i].topics[0] != keccak256("DuplicityDetected(bytes32,uint64,bytes32,bytes32)"),
                "Unexpected DuplicityDetected event"
            );
        }
        assertTrue(kb.isAnchored(prefix1, 0, said1));
    }

    function test_firstSeen_conflictingSAIDDoesNotOverwrite() public {
        bytes32 msg1 = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof1 = _sign(abi.encodePacked(msg1));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof1);

        bytes32 msg2 = keccak256(abi.encode(prefix1, uint64(0), said2));
        bytes memory proof2 = _sign(abi.encodePacked(msg2));
        kb.anchorEvent(prefix1, 0, said2, address(ed25519Verifier), proof2);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    function test_firstSeen_emitsDuplicityDetected() public {
        bytes32 msg1 = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof1 = _sign(abi.encodePacked(msg1));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof1);

        vm.expectEmit(true, true, false, true);
        emit DuplicityDetected(prefix1, 0, said1, said2);

        bytes32 msg2 = keccak256(abi.encode(prefix1, uint64(0), said2));
        bytes memory proof2 = _sign(abi.encodePacked(msg2));
        kb.anchorEvent(prefix1, 0, said2, address(ed25519Verifier), proof2);
    }

    // =========================================================================
    // anchorBatch
    // =========================================================================

    function test_anchorBatch_anchorsMultipleEvents() public {
        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](3);
        anchors[0] = KERIBacker.Anchor(prefix1, 0, said1);
        anchors[1] = KERIBacker.Anchor(prefix1, 1, said2);
        anchors[2] = KERIBacker.Anchor(prefix2, 0, said3);

        bytes32 msgHash = keccak256(abi.encode(anchors));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        kb.anchorBatch(anchors, address(ed25519Verifier), proof);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix1, 1, said2));
        assertTrue(kb.isAnchored(prefix2, 0, said3));
    }

    function test_anchorBatch_emptyArray() public {
        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](0);
        bytes32 msgHash = keccak256(abi.encode(anchors));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        kb.anchorBatch(anchors, address(ed25519Verifier), proof);
        // Empty batch with valid signature should succeed without anchoring anything
        assertFalse(kb.isAnchored(prefix1, 0, said1));
    }

    function test_anchorBatch_handlesDuplicityInBatch() public {
        bytes32 anchorMsg = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory anchorProof = _sign(abi.encodePacked(anchorMsg));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), anchorProof);

        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](2);
        anchors[0] = KERIBacker.Anchor(prefix1, 0, said2);
        anchors[1] = KERIBacker.Anchor(prefix1, 1, said3);

        vm.expectEmit(true, true, false, true);
        emit DuplicityDetected(prefix1, 0, said1, said2);

        bytes32 batchMsg = keccak256(abi.encode(anchors));
        bytes memory batchProof = _sign(abi.encodePacked(batchMsg));
        kb.anchorBatch(anchors, address(ed25519Verifier), batchProof);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertFalse(kb.isAnchored(prefix1, 0, said2));
        assertTrue(kb.isAnchored(prefix1, 1, said3));
    }

    // =========================================================================
    // isAnchored queries
    // =========================================================================

    function test_isAnchored_returnsFalseForUnanchored() public view {
        assertFalse(kb.isAnchored(prefix1, 0, said1));
    }

    function test_isAnchored_returnsFalseForWrongSAID() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof);
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    function test_isAnchored_returnsFalseForWrongSn() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof);
        assertFalse(kb.isAnchored(prefix1, 1, said1));
    }

    // =========================================================================
    // getAnchor queries
    // =========================================================================

    function test_getAnchor_returnsZeroForUnanchored() public view {
        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertFalse(rec.exists);
        assertEq(rec.eventSAID, bytes32(0));
        assertEq(rec.blockNumber, 0);
        assertEq(rec.verifier, address(0));
    }

    function test_getAnchor_recordsBlockNumber() public {
        vm.roll(12345);
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, address(ed25519Verifier), proof);

        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertEq(rec.blockNumber, 12345);
    }
}

// =============================================================================
// SP1 ZK Proof tests (via SP1KERIVerifier + SP1MockVerifier)
// =============================================================================

contract KERIBackerZKTest is KERIBackerTestBase {
    KERIBacker       public kb;
    SP1KERIVerifier  public sp1KeriVerifier;
    SP1MockVerifier  public mockSP1;

    bytes32 public prefix1 = keccak256("AID_prefix_1");
    bytes32 public said1   = keccak256("event_said_1");
    bytes32 public said2   = keccak256("event_said_2");
    bytes32 public said3   = keccak256("event_said_3");

    function setUp() public {
        // Deploy SP1MockVerifier and SP1KERIVerifier with test pubkey pre-approved
        mockSP1 = new SP1MockVerifier();
        sp1KeriVerifier = new SP1KERIVerifier(address(mockSP1), bytes32(0), address(this));
        sp1KeriVerifier.approveBacker(BACKER_PUBKEY);

        // Deploy KERIBacker and approve the SP1 verifier
        kb = new KERIBacker(address(this));
        kb.approveVerifier(address(sp1KeriVerifier));
    }

    /// @dev Build a mock SP1 proof for testing:
    ///      publicValues = abi.encode(backerPubKey, msgHash)
    ///      proof        = abi.encode(publicValues, "")  [empty proofBytes for MockVerifier]
    function _makeZKProof(bytes32 msgHash) internal pure returns (bytes memory proof) {
        bytes memory publicValues = abi.encode(BACKER_PUBKEY, msgHash);
        proof = abi.encode(publicValues, bytes(""));
    }

    // =========================================================================
    // anchorEvent with SP1 ZK proof
    // =========================================================================

    function test_anchorEventWithZKProof_storesRecord() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _makeZKProof(msgHash);

        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertTrue(rec.exists);
        assertEq(rec.eventSAID, said1);
        assertEq(rec.verifier, address(sp1KeriVerifier));
    }

    // =========================================================================
    // anchorBatch with SP1 ZK proof
    // =========================================================================

    function test_anchorBatchWithZKProof_anchorsMultipleEvents() public {
        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](3);
        anchors[0] = KERIBacker.Anchor(prefix1, 0, said1);
        anchors[1] = KERIBacker.Anchor(prefix1, 1, said2);
        anchors[2] = KERIBacker.Anchor(prefix1, 2, said3);

        bytes32 msgHash = keccak256(abi.encode(anchors));
        bytes memory proof = _makeZKProof(msgHash);

        kb.anchorBatch(anchors, address(sp1KeriVerifier), proof);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix1, 1, said2));
        assertTrue(kb.isAnchored(prefix1, 2, said3));
    }

    // =========================================================================
    // Rejection tests
    // =========================================================================

    function test_anchorWithZKProof_rejectsWrongPubkey() public {
        bytes32 wrongPubkey = keccak256("wrong_pubkey");
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory publicValues = abi.encode(wrongPubkey, msgHash);
        bytes memory proof = abi.encode(publicValues, bytes(""));

        vm.expectRevert("SP1KERIVerifier: backer not approved");
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);
    }

    function test_anchorWithZKProof_rejectsWrongMessage() public {
        bytes32 wrongMsgHash = keccak256("wrong_message");
        bytes memory publicValues = abi.encode(BACKER_PUBKEY, wrongMsgHash);
        bytes memory proof = abi.encode(publicValues, bytes(""));

        vm.expectRevert("SP1KERIVerifier: wrong message");
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);
    }
}
