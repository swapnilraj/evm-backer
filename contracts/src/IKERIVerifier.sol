// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title  IKERIVerifier
/// @notice Interface that all KERI verifier contracts must implement.
///
/// KERIBacker delegates signature/proof verification to registered verifiers.
/// Each verifier type encodes its own authorization logic (key approval,
/// ZK proof verification, etc.) in the proof bytes it accepts.
interface IKERIVerifier {
    /// @notice Verify that the given proof authorises anchoring at messageHash.
    /// @param  messageHash  keccak256 of the anchor payload (computed by KERIBacker).
    /// @param  proof        Verifier-specific bytes — ZK proof, etc.
    /// @return              True if the proof is valid; false or revert otherwise.
    function verify(bytes32 messageHash, bytes calldata proof) external view returns (bool);
}
