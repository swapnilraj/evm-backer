// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./IKERIVerifier.sol";
import "./Ed25519.sol";

/// @title  Ed25519Verifier
/// @notice Permissionless Ed25519 signature verifier for KERI event anchoring.
///
/// Submission is permissionless: any caller with a valid Ed25519 key pair can
/// anchor events. Authorization is handled at the KERI protocol level —
/// controllers designate their backer in the `b` field of their KEL, and
/// downstream verifiers check the on-chain record against the KEL.
///
/// Proof format: abi.encode(bytes32 backerPubKey, bytes32 r, bytes32 s)
///
/// The backer signs keccak256(abi.encode(anchors)) (for anchorBatch) or
/// keccak256(abi.encode(prefix, sn, eventSAID)) (for anchorEvent).
contract Ed25519Verifier is IKERIVerifier {

    /// @notice Verify an Ed25519 signature over messageHash.
    /// @param  messageHash  keccak256 of the anchor payload.
    /// @param  proof        abi.encode(bytes32 backerPubKey, bytes32 r, bytes32 s)
    function verify(bytes32 messageHash, bytes calldata proof) external pure returns (bool) {
        (bytes32 backerPubKey, bytes32 r, bytes32 s) = abi.decode(proof, (bytes32, bytes32, bytes32));
        return Ed25519.verify(backerPubKey, r, s, abi.encodePacked(messageHash));
    }
}
