// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./IKERIVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title  SP1KERIVerifier
/// @notice GLEIF-operated verifier that checks SP1 ZK proofs of Ed25519 signing
///         against an approved set of QVI backer public keys.
///
/// One deployment per SP1 program version (vkey). GLEIF approves each QVI's
/// backer pubkey as part of accreditation.
///
/// Proof format: abi.encode(bytes memory publicValues, bytes memory proofBytes)
/// where publicValues = abi.encode(bytes32 backerPubKey, bytes32 messageHash).
///
/// SP1MockVerifier: pass proofBytes = "" (empty) — MockVerifier asserts len == 0.
contract SP1KERIVerifier is IKERIVerifier {

    ISP1Verifier public immutable sp1Verifier;
    bytes32      public immutable sp1VKey;
    address      public owner;
    mapping(bytes32 => bool) public approvedBackers;

    event BackerApproved(bytes32 indexed backerPubKey);
    event BackerRevoked(bytes32 indexed backerPubKey);

    modifier onlyOwner() {
        require(msg.sender == owner, "SP1KERIVerifier: not owner");
        _;
    }

    constructor(address _sp1Verifier, bytes32 _sp1VKey, address _owner) {
        require(_owner != address(0), "SP1KERIVerifier: zero owner");
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        sp1VKey     = _sp1VKey;
        owner       = _owner;
    }

    /// @notice Add a QVI backer pubkey to the approved set.
    function approveBacker(bytes32 backerPubKey) external onlyOwner {
        approvedBackers[backerPubKey] = true;
        emit BackerApproved(backerPubKey);
    }

    /// @notice Remove a QVI backer pubkey from the approved set.
    function revokeBacker(bytes32 backerPubKey) external onlyOwner {
        approvedBackers[backerPubKey] = false;
        emit BackerRevoked(backerPubKey);
    }

    /// @notice Verify an SP1 ZK proof that an approved backer signed messageHash.
    /// @param  messageHash  keccak256 of the anchor payload.
    /// @param  proof        abi.encode(bytes publicValues, bytes proofBytes)
    ///                      publicValues = abi.encode(bytes32 backerPubKey, bytes32 msgHash)
    function verify(bytes32 messageHash, bytes calldata proof) external view returns (bool) {
        (bytes memory publicValues, bytes memory proofBytes) = abi.decode(proof, (bytes, bytes));
        sp1Verifier.verifyProof(sp1VKey, publicValues, proofBytes);
        (bytes32 backerPubKey, bytes32 pvMsgHash) = abi.decode(publicValues, (bytes32, bytes32));
        require(approvedBackers[backerPubKey], "SP1KERIVerifier: backer not approved");
        require(pvMsgHash == messageHash, "SP1KERIVerifier: wrong message");
        return true;
    }
}
