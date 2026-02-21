// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {KERIBacker} from "../src/KERIBacker.sol";
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

    /// @dev Sign a message with the test Ed25519 key via Python FFI.
    ///      The Python script outputs "0x" + hex(signature), which forge
    ///      decodes into raw bytes automatically.
    function _sign(bytes memory message) internal returns (bytes memory) {
        string[] memory cmd = new string[](3);
        cmd[0] = "python3";
        cmd[1] = "test/sign_ed25519.py";
        cmd[2] = _toHex(message);
        return vm.ffi(cmd);
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
// Standard path tests (Ed25519 on-chain verification)
// =============================================================================

contract KERIBackerTest is KERIBackerTestBase {
    KERIBacker public kb;

    bytes32 public prefix1 = keccak256("AID_prefix_1");
    bytes32 public prefix2 = keccak256("AID_prefix_2");
    bytes32 public said1 = keccak256("event_said_1");
    bytes32 public said2 = keccak256("event_said_2");
    bytes32 public said3 = keccak256("event_said_3");

    event KERIEventAnchored(
        bytes32 indexed prefix,
        uint64 indexed sn,
        bytes32 indexed eventSAID
    );

    event DuplicityDetected(
        bytes32 indexed prefix,
        uint64 indexed sn,
        bytes32 firstSeenSAID,
        bytes32 conflictingSAID
    );

    event BackerRotated(
        bytes32 indexed oldPubKey,
        bytes32 indexed newPubKey
    );

    function setUp() public {
        kb = new KERIBacker(BACKER_PUBKEY);
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    function test_constructor_setsBacker() public view {
        assertEq(kb.backerPubKey(), BACKER_PUBKEY);
    }

    function test_constructor_rejectsZeroPubkey() public {
        vm.expectRevert("KERIBacker: zero pubkey");
        new KERIBacker(bytes32(0));
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
    // Access control
    // =========================================================================

    function test_anchorEvent_revertsWithInvalidSig() public {
        bytes memory badSig = new bytes(64);
        vm.expectRevert("KERIBacker: invalid signature");
        kb.anchorEvent(prefix1, 0, said1, badSig);
    }

    function test_anchorEvent_revertsWithWrongSigLength() public {
        bytes memory shortSig = new bytes(32);
        vm.expectRevert("KERIBacker: invalid sig length");
        kb.anchorEvent(prefix1, 0, said1, shortSig);
    }

    // =========================================================================
    // anchorEvent
    // =========================================================================

    function test_anchorEvent_storesRecord() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, sig);

        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertTrue(rec.exists);
        assertEq(rec.eventSAID, said1);
        assertEq(rec.blockNumber, uint64(block.number));
    }

    function test_anchorEvent_emitsKERIEventAnchored() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory sig = _sign(abi.encodePacked(msgHash));

        vm.expectEmit(true, true, true, true);
        emit KERIEventAnchored(prefix1, 0, said1);
        kb.anchorEvent(prefix1, 0, said1, sig);
    }

    function test_anchorEvent_multipleSequenceNumbers() public {
        for (uint64 sn = 0; sn < 3; sn++) {
            bytes32 said = sn == 0 ? said1 : (sn == 1 ? said2 : said3);
            bytes32 msgHash = keccak256(abi.encode(prefix1, sn, said));
            bytes memory sig = _sign(abi.encodePacked(msgHash));
            kb.anchorEvent(prefix1, sn, said, sig);
        }
        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix1, 1, said2));
        assertTrue(kb.isAnchored(prefix1, 2, said3));
    }

    function test_anchorEvent_multiplePrefixes() public {
        bytes32 msg1 = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory sig1 = _sign(abi.encodePacked(msg1));
        kb.anchorEvent(prefix1, 0, said1, sig1);

        bytes32 msg2 = keccak256(abi.encode(prefix2, uint64(0), said2));
        bytes memory sig2 = _sign(abi.encodePacked(msg2));
        kb.anchorEvent(prefix2, 0, said2, sig2);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix2, 0, said2));
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    // =========================================================================
    // First-seen policy
    // =========================================================================

    function test_firstSeen_idempotentResubmission() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, sig);

        vm.recordLogs();
        kb.anchorEvent(prefix1, 0, said1, sig);

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
        bytes memory sig1 = _sign(abi.encodePacked(msg1));
        kb.anchorEvent(prefix1, 0, said1, sig1);

        bytes32 msg2 = keccak256(abi.encode(prefix1, uint64(0), said2));
        bytes memory sig2 = _sign(abi.encodePacked(msg2));
        kb.anchorEvent(prefix1, 0, said2, sig2);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    function test_firstSeen_emitsDuplicityDetected() public {
        bytes32 msg1 = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory sig1 = _sign(abi.encodePacked(msg1));
        kb.anchorEvent(prefix1, 0, said1, sig1);

        vm.expectEmit(true, true, false, true);
        emit DuplicityDetected(prefix1, 0, said1, said2);

        bytes32 msg2 = keccak256(abi.encode(prefix1, uint64(0), said2));
        bytes memory sig2 = _sign(abi.encodePacked(msg2));
        kb.anchorEvent(prefix1, 0, said2, sig2);
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
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.anchorBatch(anchors, sig);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix1, 1, said2));
        assertTrue(kb.isAnchored(prefix2, 0, said3));
    }

    function test_anchorBatch_emptyArray() public {
        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](0);
        bytes32 msgHash = keccak256(abi.encode(anchors));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.anchorBatch(anchors, sig);
        // Empty batch with valid signature should succeed without anchoring anything
        assertFalse(kb.isAnchored(prefix1, 0, said1));
    }

    function test_anchorBatch_handlesDuplicityInBatch() public {
        bytes32 anchorMsg = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory anchorSig = _sign(abi.encodePacked(anchorMsg));
        kb.anchorEvent(prefix1, 0, said1, anchorSig);

        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](2);
        anchors[0] = KERIBacker.Anchor(prefix1, 0, said2);
        anchors[1] = KERIBacker.Anchor(prefix1, 1, said3);

        vm.expectEmit(true, true, false, true);
        emit DuplicityDetected(prefix1, 0, said1, said2);

        bytes32 batchMsg = keccak256(abi.encode(anchors));
        bytes memory batchSig = _sign(abi.encodePacked(batchMsg));
        kb.anchorBatch(anchors, batchSig);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertFalse(kb.isAnchored(prefix1, 0, said2));
        assertTrue(kb.isAnchored(prefix1, 1, said3));
    }

    // =========================================================================
    // rotateBacker
    // =========================================================================

    function test_rotateBacker_updatesBackerPubKey() public {
        bytes32 newPubKey = keccak256("newPubKey");
        uint256 nonce = 1;
        bytes32 msgHash = keccak256(abi.encodePacked(newPubKey, nonce));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.rotateBacker(newPubKey, sig, nonce);
        assertEq(kb.backerPubKey(), newPubKey);
    }

    function test_rotateBacker_rejectsZeroPubkey() public {
        uint256 nonce = 2;
        bytes32 msgHash = keccak256(abi.encodePacked(bytes32(0), nonce));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        vm.expectRevert("KERIBacker: zero pubkey");
        kb.rotateBacker(bytes32(0), sig, nonce);
    }

    function test_rotateBacker_rejectsReusedNonce() public {
        bytes32 newPubKey1 = keccak256("newPubKey1");
        uint256 nonce = 3;
        bytes32 msgHash1 = keccak256(abi.encodePacked(newPubKey1, nonce));
        bytes memory sig1 = _sign(abi.encodePacked(msgHash1));
        kb.rotateBacker(newPubKey1, sig1, nonce);

        bytes32 newPubKey2 = keccak256("newPubKey2");
        bytes32 msgHash2 = keccak256(abi.encodePacked(newPubKey2, nonce));
        bytes memory sig2 = _sign(abi.encodePacked(msgHash2));
        vm.expectRevert("KERIBacker: nonce reused");
        kb.rotateBacker(newPubKey2, sig2, nonce);
    }

    function test_rotateBacker_emitsBackerRotatedEvent() public {
        bytes32 newPubKey = keccak256("newPubKeyForEvent");
        uint256 nonce = 4;
        bytes32 msgHash = keccak256(abi.encodePacked(newPubKey, nonce));
        bytes memory sig = _sign(abi.encodePacked(msgHash));

        vm.expectEmit(true, true, false, false);
        emit BackerRotated(BACKER_PUBKEY, newPubKey);
        kb.rotateBacker(newPubKey, sig, nonce);
    }

    function test_rotateBacker_oldKeyCannotAnchorAfterRotation() public {
        bytes32 newPubKey = keccak256("newPubKeyOldKeyTest");
        uint256 nonce = 5;
        bytes32 rotMsg = keccak256(abi.encodePacked(newPubKey, nonce));
        bytes memory rotSig = _sign(abi.encodePacked(rotMsg));
        kb.rotateBacker(newPubKey, rotSig, nonce);

        bytes32 anchorMsg = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory anchorSig = _sign(abi.encodePacked(anchorMsg));
        vm.expectRevert("KERIBacker: invalid signature");
        kb.anchorEvent(prefix1, 0, said1, anchorSig);
    }

    function test_rotateBacker_preservesHistoricalAnchors() public {
        bytes32 anchorMsg = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory anchorSig = _sign(abi.encodePacked(anchorMsg));
        kb.anchorEvent(prefix1, 0, said1, anchorSig);

        bytes32 newPubKey = keccak256("newPubKeyHistory");
        uint256 nonce = 6;
        bytes32 rotMsg = keccak256(abi.encodePacked(newPubKey, nonce));
        bytes memory rotSig = _sign(abi.encodePacked(rotMsg));
        kb.rotateBacker(newPubKey, rotSig, nonce);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
    }

    // =========================================================================
    // isAnchored queries
    // =========================================================================

    function test_isAnchored_returnsFalseForUnanchored() public view {
        assertFalse(kb.isAnchored(prefix1, 0, said1));
    }

    function test_isAnchored_returnsFalseForWrongSAID() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, sig);
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    function test_isAnchored_returnsFalseForWrongSn() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, sig);
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
    }

    function test_getAnchor_recordsBlockNumber() public {
        vm.roll(12345);
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.anchorEvent(prefix1, 0, said1, sig);

        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertEq(rec.blockNumber, 12345);
    }
}

// =============================================================================
// SP1 ZK Proof tests
// =============================================================================

contract KERIBackerZKTest is KERIBackerTestBase {
    KERIBacker public kb;
    SP1MockVerifier public mockSP1;

    bytes32 public prefix1 = keccak256("AID_prefix_1");
    bytes32 public said1   = keccak256("event_said_1");
    bytes32 public said2   = keccak256("event_said_2");
    bytes32 public said3   = keccak256("event_said_3");

    function setUp() public {
        kb = new KERIBacker(BACKER_PUBKEY);
        mockSP1 = new SP1MockVerifier();

        // Configure ZK verifier: sign keccak256(abi.encodePacked(address, vkey, nonce))
        uint256 nonce = 99;
        bytes32 msgHash = keccak256(abi.encodePacked(address(mockSP1), bytes32(0), nonce));
        bytes memory sig = _sign(abi.encodePacked(msgHash));
        kb.setZKVerifier(address(mockSP1), bytes32(0), sig, nonce);
    }

    // =========================================================================
    // setZKVerifier
    // =========================================================================

    function test_setZKVerifier_updatesState() public view {
        assertEq(address(kb.sp1Verifier()), address(mockSP1));
        assertEq(kb.sp1VKey(), bytes32(0));
    }

    function test_setZKVerifier_rejectsReusedNonce() public {
        // nonce 99 was consumed in setUp(); any sig will do since nonce check runs first
        bytes memory anySig = new bytes(64);
        vm.expectRevert("KERIBacker: nonce reused");
        kb.setZKVerifier(address(mockSP1), bytes32(0), anySig, 99);
    }

    // =========================================================================
    // anchorEventWithZKProof
    // =========================================================================

    function test_anchorEventWithZKProof_storesRecord() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory publicValues = abi.encode(BACKER_PUBKEY, msgHash);

        kb.anchorEventWithZKProof(prefix1, 0, said1, publicValues, "");

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertTrue(rec.exists);
        assertEq(rec.eventSAID, said1);
    }

    // =========================================================================
    // anchorBatchWithZKProof
    // =========================================================================

    function test_anchorBatchWithZKProof_anchorsMultipleEvents() public {
        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](3);
        anchors[0] = KERIBacker.Anchor(prefix1, 0, said1);
        anchors[1] = KERIBacker.Anchor(prefix1, 1, said2);
        anchors[2] = KERIBacker.Anchor(prefix1, 2, said3);

        bytes32 msgHash = keccak256(abi.encode(anchors));
        bytes memory publicValues = abi.encode(BACKER_PUBKEY, msgHash);

        kb.anchorBatchWithZKProof(anchors, publicValues, "");

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

        vm.expectRevert("KERIBacker: ZK proof wrong pubkey");
        kb.anchorEventWithZKProof(prefix1, 0, said1, publicValues, "");
    }

    function test_anchorWithZKProof_rejectsWrongMessage() public {
        bytes32 wrongMsgHash = keccak256("wrong_message");
        bytes memory publicValues = abi.encode(BACKER_PUBKEY, wrongMsgHash);

        vm.expectRevert("KERIBacker: ZK proof wrong message");
        kb.anchorEventWithZKProof(prefix1, 0, said1, publicValues, "");
    }
}
