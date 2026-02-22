// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/KERIBacker.sol";
import "../src/SP1KERIVerifier.sol";
import "../src/SP1TELVerifier.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";

contract SP1TELVerifierTest is Test {
    KERIBacker      internal kb;
    SP1MockVerifier internal mockSP1;
    SP1KERIVerifier internal kelVerifier;
    SP1TELVerifier  internal telVerifier;

    // Deterministic test values
    bytes32 internal constant REGISTRY_PREFIX_B32   = keccak256("ETestRegistryPrefix");
    bytes32 internal constant TEL_SAID_B32          = keccak256("ETestTelSaid");
    bytes32 internal constant CONTROLLER_PREFIX_B32 = keccak256("BTestControllerPrefix");
    bytes32 internal constant ANCHOR_SAID_B32       = keccak256("ETestAnchorSaid");
    uint64  internal constant TEL_SN    = 0;
    uint64  internal constant ANCHOR_SN = 1;

    function setUp() public {
        // Deploy SP1MockVerifier (accepts empty proofBytes).
        mockSP1 = new SP1MockVerifier();

        // Deploy KERIBacker with test contract as owner.
        kb = new KERIBacker(address(this));

        // Deploy SP1KERIVerifier (KEL path — vkey=0 for mock).
        kelVerifier = new SP1KERIVerifier(address(mockSP1), bytes32(0));
        kb.approveVerifier(address(kelVerifier));

        // Deploy SP1TELVerifier (TEL path — vkey=0 for mock, points to same KERIBacker).
        telVerifier = new SP1TELVerifier(address(mockSP1), bytes32(0), address(kb));
        kb.approveVerifier(address(telVerifier));
    }

    /// @dev Pre-seed a controller KEL event in KERIBacker using the KEL ZK path.
    function _seedKelAnchor(
        bytes32 controllerPrefixB32,
        uint64  anchorSn,
        bytes32 anchorSaidB32
    ) internal {
        // messageHash = keccak256(abi.encode(prefix, sn, said)) — same as contract computes.
        bytes32 msgHash = keccak256(abi.encode(controllerPrefixB32, anchorSn, anchorSaidB32));
        // publicValues = abi.encode(bytes32 messageHash) [32 bytes for SP1KERIVerifier].
        bytes memory kelPv = abi.encode(msgHash);
        bytes memory kelProof = abi.encode(kelPv, bytes(""));
        kb.anchorEvent(controllerPrefixB32, anchorSn, anchorSaidB32, address(kelVerifier), kelProof);
    }

    /// @dev Build a mock TEL proof for SP1TELVerifier.
    function _makeTelProof(
        bytes32 registryPrefixB32,
        uint64  telSn,
        bytes32 telSaidB32,
        bytes32 controllerPrefixB32,
        uint64  anchorSn,
        bytes32 anchorSaidB32
    ) internal pure returns (bytes memory proof, bytes32 telMsgHash) {
        bytes memory pv = abi.encode(
            registryPrefixB32, telSn, telSaidB32,
            controllerPrefixB32, anchorSn, anchorSaidB32
        );
        proof = abi.encode(pv, bytes(""));
        telMsgHash = keccak256(abi.encode(registryPrefixB32, telSn, telSaidB32));
    }

    function test_telAnchorWithMockProof_storesRecord() public {
        // Pre-seed the controller KEL anchor event.
        _seedKelAnchor(CONTROLLER_PREFIX_B32, ANCHOR_SN, ANCHOR_SAID_B32);
        assertTrue(kb.isAnchored(CONTROLLER_PREFIX_B32, ANCHOR_SN, ANCHOR_SAID_B32));

        // Build mock TEL proof.
        (bytes memory proof, ) = _makeTelProof(
            REGISTRY_PREFIX_B32, TEL_SN, TEL_SAID_B32,
            CONTROLLER_PREFIX_B32, ANCHOR_SN, ANCHOR_SAID_B32
        );

        // Anchor TEL event.
        kb.anchorEvent(REGISTRY_PREFIX_B32, TEL_SN, TEL_SAID_B32, address(telVerifier), proof);
        assertTrue(kb.isAnchored(REGISTRY_PREFIX_B32, TEL_SN, TEL_SAID_B32));
    }

    function test_telAnchorWithMockProof_rejectsWrongTelMessage() public {
        // Pre-seed the controller KEL anchor event.
        _seedKelAnchor(CONTROLLER_PREFIX_B32, ANCHOR_SN, ANCHOR_SAID_B32);

        // Build a proof that attests TEL_SAID_B32, but submit anchorEvent with wrongTelSaidB32.
        // The proof's pv contains TEL_SAID_B32, but anchorEvent computes
        // msgHash from wrongTelSaidB32 — mismatch causes SP1TELVerifier to revert.
        bytes32 wrongTelSaidB32 = keccak256("wrong_tel_said");

        bytes memory pvWrong = abi.encode(
            REGISTRY_PREFIX_B32, TEL_SN, TEL_SAID_B32,  // proof attests TEL_SAID_B32
            CONTROLLER_PREFIX_B32, ANCHOR_SN, ANCHOR_SAID_B32
        );
        bytes memory proofWrong = abi.encode(pvWrong, bytes(""));

        // anchorEvent computes msgHash = keccak256(abi.encode(REGISTRY_PREFIX_B32, TEL_SN, wrongTelSaidB32))
        // SP1TELVerifier computes computedTelHash from pv = keccak256(...TEL_SAID_B32...)
        // These differ → revert with "SP1TELVerifier: wrong TEL message".
        vm.expectRevert();
        kb.anchorEvent(REGISTRY_PREFIX_B32, TEL_SN, wrongTelSaidB32, address(telVerifier), proofWrong);
    }

    function test_telAnchorWithMockProof_rejectsUnanchoredKELEvent() public {
        // Do NOT seed the controller KEL anchor event.

        (bytes memory proof, ) = _makeTelProof(
            REGISTRY_PREFIX_B32, TEL_SN, TEL_SAID_B32,
            CONTROLLER_PREFIX_B32, ANCHOR_SN, ANCHOR_SAID_B32
        );

        // SP1TELVerifier.verify() should revert because isAnchored() returns false.
        vm.expectRevert();
        kb.anchorEvent(REGISTRY_PREFIX_B32, TEL_SN, TEL_SAID_B32, address(telVerifier), proof);
    }
}
