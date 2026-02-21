// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./IKERIVerifier.sol";
import "./Ed25519.sol";

/// @title  Ed25519Verifier
/// @notice GLEIF-operated verifier that checks Ed25519 signatures against an
///         approved set of QVI backer public keys.
///
/// One deployment serves the whole KERI ecosystem. GLEIF approves each QVI's
/// backer Ed25519 pubkey as part of the QVI accreditation process.
///
/// Proof format: abi.encode(bytes32 backerPubKey, bytes32 r, bytes32 s)
///
/// The backer signs keccak256(abi.encode(anchors)) (for anchorBatch) or
/// keccak256(abi.encode(prefix, sn, eventSAID)) (for anchorEvent).
contract Ed25519Verifier is IKERIVerifier {

    address public owner;
    mapping(bytes32 => bool) public approvedBackers;

    event BackerApproved(bytes32 indexed backerPubKey);
    event BackerRevoked(bytes32 indexed backerPubKey);

    modifier onlyOwner() {
        require(msg.sender == owner, "Ed25519Verifier: not owner");
        _;
    }

    constructor(address _owner) {
        require(_owner != address(0), "Ed25519Verifier: zero owner");
        owner = _owner;
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

    /// @notice Verify an Ed25519 signature from an approved backer.
    /// @param  messageHash  keccak256 of the anchor payload.
    /// @param  proof        abi.encode(bytes32 backerPubKey, bytes32 r, bytes32 s)
    function verify(bytes32 messageHash, bytes calldata proof) external view returns (bool) {
        (bytes32 backerPubKey, bytes32 r, bytes32 s) = abi.decode(proof, (bytes32, bytes32, bytes32));
        require(approvedBackers[backerPubKey], "Ed25519Verifier: backer not approved");
        return Ed25519.verify(backerPubKey, r, s, abi.encodePacked(messageHash));
    }
}
