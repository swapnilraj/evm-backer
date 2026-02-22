// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./IKERIVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title  SP1KERIVerifier
/// @notice Permissionless SP1 ZK verifier for KERI event anchoring.
///
/// The guest program verifies the complete KERI Key Event Log (KEL):
/// every event's SAID (blake3), the chain (p fields), the controller's
/// signatures at each step, and key rotations via pre-rotation
/// commitments. Only the controller who holds the private key(s) can
/// generate a valid proof — no separate `approvedBackers` registry needed.
///
/// Public values: 32 bytes = abi.encode(bytes32 messageHash)
/// where messageHash = keccak256(abi.encode(prefix_b32, sn, said_b32)).
///
/// One deployment per SP1 program version (vkey).
///
/// Proof format: abi.encode(bytes memory publicValues, bytes memory proofBytes)
/// where publicValues = abi.encode(bytes32 messageHash)   [32 bytes].
///
/// SP1MockVerifier: pass proofBytes = "" (empty) — MockVerifier asserts len == 0.
contract SP1KERIVerifier is IKERIVerifier {

    ISP1Verifier public immutable sp1Verifier;
    bytes32      public immutable sp1VKey;

    constructor(address _sp1Verifier, bytes32 _sp1VKey) {
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        sp1VKey     = _sp1VKey;
    }

    /// @notice Verify an SP1 ZK proof that the KERI KEL is valid up to messageHash.
    /// @param  messageHash  keccak256(abi.encode(prefix_b32, sn, said_b32)).
    /// @param  proof        abi.encode(bytes publicValues, bytes proofBytes)
    ///                      publicValues = abi.encode(bytes32 messageHash)  [32 bytes]
    function verify(bytes32 messageHash, bytes calldata proof) external view returns (bool) {
        (bytes memory publicValues, bytes memory proofBytes) = abi.decode(proof, (bytes, bytes));
        sp1Verifier.verifyProof(sp1VKey, publicValues, proofBytes);
        bytes32 pvMessageHash = abi.decode(publicValues, (bytes32));
        require(pvMessageHash == messageHash, "SP1KERIVerifier: wrong message");
        return true;
    }
}
