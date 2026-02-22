// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {KERIBacker} from "../src/KERIBacker.sol";
import {SP1KERIVerifier} from "../src/SP1KERIVerifier.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";

// =============================================================================
// All tests use SP1 ZK verification via SP1MockVerifier
// =============================================================================

contract KERIBackerTest is Test {
    KERIBacker       public kb;
    SP1KERIVerifier  public sp1KeriVerifier;
    SP1MockVerifier  public mockSP1;

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
        // Deploy SP1MockVerifier and permissionless SP1KERIVerifier
        mockSP1 = new SP1MockVerifier();
        sp1KeriVerifier = new SP1KERIVerifier(address(mockSP1), bytes32(0));

        // Deploy KERIBacker with this test contract as owner, approve the verifier
        kb = new KERIBacker(address(this));
        kb.approveVerifier(address(sp1KeriVerifier));
    }

    /// @dev Build a mock SP1 proof for testing:
    ///      publicValues = abi.encode(msgHash)   [32 bytes]
    ///      proof        = abi.encode(publicValues, "")  [empty proofBytes for MockVerifier]
    function _makeZKProof(bytes32 msgHash) internal pure returns (bytes memory proof) {
        bytes memory publicValues = abi.encode(msgHash);
        proof = abi.encode(publicValues, bytes(""));
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
        kb.revokeVerifier(address(sp1KeriVerifier));
        assertFalse(kb.approvedVerifiers(address(sp1KeriVerifier)));

        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _makeZKProof(msgHash);
        vm.expectRevert("KERIBacker: verifier not approved");
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);
    }

    function test_revokeVerifier_emitsEvent() public {
        vm.expectEmit(true, false, false, false);
        emit VerifierRevoked(address(sp1KeriVerifier));
        kb.revokeVerifier(address(sp1KeriVerifier));
    }

    // =========================================================================
    // Access control
    // =========================================================================

    function test_anchorEvent_rejectsUnregisteredVerifier() public {
        address fakeVerifier = address(0x1234);
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _makeZKProof(msgHash);
        vm.expectRevert("KERIBacker: verifier not approved");
        kb.anchorEvent(prefix1, 0, said1, fakeVerifier, proof);
    }

    function test_anchorEvent_revertsWithWrongMessageInProof() public {
        // Proof carries a different messageHash than what the contract computes
        bytes32 wrongMsgHash = keccak256("wrong_message");
        bytes memory proof = _makeZKProof(wrongMsgHash);
        vm.expectRevert("SP1KERIVerifier: wrong message");
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);
    }

    // =========================================================================
    // anchorEvent
    // =========================================================================

    function test_anchorEvent_storesRecord() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _makeZKProof(msgHash);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);

        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertTrue(rec.exists);
        assertEq(rec.eventSAID, said1);
        assertEq(rec.blockNumber, uint64(block.number));
        assertEq(rec.verifier, address(sp1KeriVerifier));
    }

    function test_anchorEvent_emitsKERIEventAnchored() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _makeZKProof(msgHash);

        vm.expectEmit(true, true, true, true);
        emit KERIEventAnchored(prefix1, 0, said1, address(sp1KeriVerifier));
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);
    }

    function test_anchorEvent_multipleSequenceNumbers() public {
        for (uint64 sn = 0; sn < 3; sn++) {
            bytes32 said = sn == 0 ? said1 : (sn == 1 ? said2 : said3);
            bytes32 msgHash = keccak256(abi.encode(prefix1, sn, said));
            bytes memory proof = _makeZKProof(msgHash);
            kb.anchorEvent(prefix1, sn, said, address(sp1KeriVerifier), proof);
        }
        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix1, 1, said2));
        assertTrue(kb.isAnchored(prefix1, 2, said3));
    }

    function test_anchorEvent_multiplePrefixes() public {
        bytes32 msg1 = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof1 = _makeZKProof(msg1);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof1);

        bytes32 msg2 = keccak256(abi.encode(prefix2, uint64(0), said2));
        bytes memory proof2 = _makeZKProof(msg2);
        kb.anchorEvent(prefix2, 0, said2, address(sp1KeriVerifier), proof2);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix2, 0, said2));
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    // =========================================================================
    // First-seen policy
    // =========================================================================

    function test_firstSeen_idempotentResubmission() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _makeZKProof(msgHash);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);

        vm.recordLogs();
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);

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
        bytes memory proof1 = _makeZKProof(msg1);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof1);

        bytes32 msg2 = keccak256(abi.encode(prefix1, uint64(0), said2));
        bytes memory proof2 = _makeZKProof(msg2);
        kb.anchorEvent(prefix1, 0, said2, address(sp1KeriVerifier), proof2);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    function test_firstSeen_emitsDuplicityDetected() public {
        bytes32 msg1 = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof1 = _makeZKProof(msg1);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof1);

        vm.expectEmit(true, true, false, true);
        emit DuplicityDetected(prefix1, 0, said1, said2);

        bytes32 msg2 = keccak256(abi.encode(prefix1, uint64(0), said2));
        bytes memory proof2 = _makeZKProof(msg2);
        kb.anchorEvent(prefix1, 0, said2, address(sp1KeriVerifier), proof2);
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
        bytes memory proof = _makeZKProof(msgHash);
        kb.anchorBatch(anchors, address(sp1KeriVerifier), proof);

        assertTrue(kb.isAnchored(prefix1, 0, said1));
        assertTrue(kb.isAnchored(prefix1, 1, said2));
        assertTrue(kb.isAnchored(prefix2, 0, said3));
    }

    function test_anchorBatch_emptyArray() public {
        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](0);
        bytes32 msgHash = keccak256(abi.encode(anchors));
        bytes memory proof = _makeZKProof(msgHash);
        kb.anchorBatch(anchors, address(sp1KeriVerifier), proof);
        // Empty batch with valid proof should succeed without anchoring anything
        assertFalse(kb.isAnchored(prefix1, 0, said1));
    }

    function test_anchorBatch_handlesDuplicityInBatch() public {
        bytes32 anchorMsg = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory anchorProof = _makeZKProof(anchorMsg);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), anchorProof);

        KERIBacker.Anchor[] memory anchors = new KERIBacker.Anchor[](2);
        anchors[0] = KERIBacker.Anchor(prefix1, 0, said2);
        anchors[1] = KERIBacker.Anchor(prefix1, 1, said3);

        vm.expectEmit(true, true, false, true);
        emit DuplicityDetected(prefix1, 0, said1, said2);

        bytes32 batchMsg = keccak256(abi.encode(anchors));
        bytes memory batchProof = _makeZKProof(batchMsg);
        kb.anchorBatch(anchors, address(sp1KeriVerifier), batchProof);

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
        bytes memory proof = _makeZKProof(msgHash);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);
        assertFalse(kb.isAnchored(prefix1, 0, said2));
    }

    function test_isAnchored_returnsFalseForWrongSn() public {
        bytes32 msgHash = keccak256(abi.encode(prefix1, uint64(0), said1));
        bytes memory proof = _makeZKProof(msgHash);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);
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
        bytes memory proof = _makeZKProof(msgHash);
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);

        KERIBacker.AnchorRecord memory rec = kb.getAnchor(prefix1, 0);
        assertEq(rec.blockNumber, 12345);
    }

    // =========================================================================
    // ZK-specific rejection tests
    // =========================================================================

    function test_anchorWithZKProof_rejectsWrongMessage() public {
        bytes32 wrongMsgHash = keccak256("wrong_message");
        bytes memory publicValues = abi.encode(wrongMsgHash);
        bytes memory proof = abi.encode(publicValues, bytes(""));

        vm.expectRevert("SP1KERIVerifier: wrong message");
        kb.anchorEvent(prefix1, 0, said1, address(sp1KeriVerifier), proof);
    }
}
