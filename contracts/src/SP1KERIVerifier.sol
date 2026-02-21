// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./IKERIVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title  SP1KERIVerifier
/// @notice Permissionless SP1 ZK verifier for KERI event anchoring.
///
/// Submission is permissionless: any caller with a valid Ed25519 key pair can
/// anchor events. Authorization is handled at the KERI protocol level —
/// controllers designate their backer in the `b` field of their KEL, and
/// downstream verifiers check the on-chain record against the KEL.
///
/// One deployment per SP1 program version (vkey).
///
/// Proof format: abi.encode(bytes memory publicValues, bytes memory proofBytes)
/// where publicValues = abi.encode(bytes32 backerPubKey, bytes32 messageHash).
///
/// SP1MockVerifier: pass proofBytes = "" (empty) — MockVerifier asserts len == 0.
contract SP1KERIVerifier is IKERIVerifier {

    ISP1Verifier public immutable sp1Verifier;
    bytes32      public immutable sp1VKey;

    constructor(address _sp1Verifier, bytes32 _sp1VKey) {
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        sp1VKey     = _sp1VKey;
    }

    /// @notice Verify an SP1 ZK proof that a backer signed messageHash.
    /// @param  messageHash  keccak256 of the anchor payload.
    /// @param  proof        abi.encode(bytes publicValues, bytes proofBytes)
    ///                      publicValues = abi.encode(bytes32 backerPubKey, bytes32 msgHash)
    function verify(bytes32 messageHash, bytes calldata proof) external view returns (bool) {
        (bytes memory publicValues, bytes memory proofBytes) = abi.decode(proof, (bytes, bytes));
        sp1Verifier.verifyProof(sp1VKey, publicValues, proofBytes);
        (, bytes32 pvMsgHash) = abi.decode(publicValues, (bytes32, bytes32));
        require(pvMsgHash == messageHash, "SP1KERIVerifier: wrong message");
        return true;
    }
}
