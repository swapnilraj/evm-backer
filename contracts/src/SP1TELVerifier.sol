// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./IKERIVerifier.sol";
import "./IKERIBacker.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title  SP1TELVerifier
/// @notice SP1 ZK verifier for KERI TEL event anchoring.
///
/// The guest program proves:
/// 1. The TEL event SAID is correct (blake3).
/// 2. The controller's KEL anchor event contains the matching seal.
///
/// SP1TELVerifier additionally checks (at proof-verify time, not in zkVM):
/// 3. The controller's KEL anchor event is on-chain via keriBacker.isAnchored().
///
/// Public values: 192 bytes = abi.encode(
///   bytes32 registryPrefixB32,   // keccak256(registry_prefix_qb64)
///   uint64  telSn,
///   bytes32 telSaidB32,          // keccak256(tel_said_qb64)
///   bytes32 controllerPrefixB32, // keccak256(controller_prefix_qb64)
///   uint64  anchorSn,
///   bytes32 anchorSaidB32,       // keccak256(anchor_event_said_qb64)
/// )
///
/// telMessageHash = keccak256(abi.encode(registryPrefixB32, telSn, telSaidB32))
///
/// Proof format: abi.encode(bytes memory publicValues, bytes memory proofBytes)
/// SP1MockVerifier: pass proofBytes = "" (empty).
contract SP1TELVerifier is IKERIVerifier {

    ISP1Verifier  public immutable sp1Verifier;
    bytes32       public immutable sp1VKey;
    IKERIBacker   public immutable keriBacker;

    constructor(address _sp1Verifier, bytes32 _sp1VKey, address _keriBacker) {
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        sp1VKey     = _sp1VKey;
        keriBacker  = IKERIBacker(_keriBacker);
    }

    /// @notice Verify a TEL event anchor proof.
    /// @param  telMessageHash  keccak256(abi.encode(registryPrefixB32, telSn, telSaidB32))
    /// @param  proof           abi.encode(bytes publicValues, bytes proofBytes)
    function verify(bytes32 telMessageHash, bytes calldata proof) external view returns (bool) {
        (bytes memory pv, bytes memory proofBytes) = abi.decode(proof, (bytes, bytes));

        // Verify the SP1 proof.
        sp1Verifier.verifyProof(sp1VKey, pv, proofBytes);

        // Decode the 192-byte public values.
        (
            bytes32 registryPrefixB32,
            uint64  telSn,
            bytes32 telSaidB32,
            bytes32 controllerPrefixB32,
            uint64  anchorSn,
            bytes32 anchorSaidB32
        ) = abi.decode(pv, (bytes32, uint64, bytes32, bytes32, uint64, bytes32));

        // Verify the TEL message hash matches what the proof attests.
        bytes32 computedTelHash = keccak256(abi.encode(registryPrefixB32, telSn, telSaidB32));
        require(
            computedTelHash == telMessageHash,
            "SP1TELVerifier: wrong TEL message"
        );

        // Verify the controller's KEL anchor event is on-chain.
        require(
            keriBacker.isAnchored(controllerPrefixB32, anchorSn, anchorSaidB32),
            "SP1TELVerifier: anchor KEL event not on-chain"
        );

        return true;
    }
}
