// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./IKERIVerifier.sol";

/// @title  KERIBacker
/// @notice Global on-chain anchor for KERI key events.
///
/// Deployed once by GLEIF (or equivalent root authority) and shared by all QVIs.
/// Verification is fully delegated to modular verifier contracts registered by
/// the owner. SP1 ZK proofs verify the complete KERI KEL inside a zkVM; new
/// verification methods can be added without touching this contract.
///
/// Any caller may submit an anchor so long as they supply a proof that passes
/// an approved verifier. There is no per-backer setup — GLEIF approves new QVI
/// backer keys inside the verifier contracts as part of QVI accreditation.
///
/// The first-seen policy mirrors KERI's own ordering: once an event is anchored
/// at (prefix, sn), no conflicting event can overwrite it. The ledger's
/// immutability is the duplicity protection mechanism.
///
/// isAnchored(prefix, sn, said) is the key function other contracts call.
contract KERIBacker {

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a KERI key event commitment is anchored on-chain.
    /// @param  verifier  The verifier contract that authorised this anchor.
    event KERIEventAnchored(
        bytes32 indexed prefix,
        uint64  indexed sn,
        bytes32 indexed eventSAID,
        address         verifier
    );

    /// @notice Emitted when a conflicting SAID is submitted at a (prefix, sn)
    ///         that already has a different SAID anchored.
    event DuplicityDetected(
        bytes32 indexed prefix,
        uint64  indexed sn,
        bytes32         firstSeenSAID,
        bytes32         conflictingSAID
    );

    /// @notice Emitted when a verifier is added to the approved set.
    event VerifierApproved(address indexed verifier);

    /// @notice Emitted when a verifier is removed from the approved set.
    event VerifierRevoked(address indexed verifier);

    // -------------------------------------------------------------------------
    // Storage types
    // -------------------------------------------------------------------------

    struct AnchorRecord {
        bytes32 eventSAID;
        uint64  blockNumber;
        address verifier;
        bool    exists;
    }

    /// @notice Batch submission type — one entry per event in anchorBatch.
    struct Anchor {
        bytes32 prefix;
        uint64  sn;
        bytes32 eventSAID;
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /// @notice The owner (GLEIF's multisig / AID-controlled address).
    address public owner;

    /// @notice Verifier contracts approved by the owner.
    mapping(address => bool) public approvedVerifiers;

    /// @dev prefix -> sn -> AnchorRecord
    mapping(bytes32 => mapping(uint64 => AnchorRecord)) private _anchors;

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == owner, "KERIBacker: not owner");
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    constructor(address _owner) {
        require(_owner != address(0), "KERIBacker: zero owner");
        owner = _owner;
    }

    // -------------------------------------------------------------------------
    // Governance
    // -------------------------------------------------------------------------

    /// @notice Approve a verifier contract.
    function approveVerifier(address verifier) external onlyOwner {
        approvedVerifiers[verifier] = true;
        emit VerifierApproved(verifier);
    }

    /// @notice Revoke a previously approved verifier.
    function revokeVerifier(address verifier) external onlyOwner {
        approvedVerifiers[verifier] = false;
        emit VerifierRevoked(verifier);
    }

    // -------------------------------------------------------------------------
    // Anchoring
    // -------------------------------------------------------------------------

    /// @notice Anchor a single KERI key event commitment on-chain.
    /// @param  prefix     Controller AID prefix (bytes32)
    /// @param  sn         Event sequence number
    /// @param  eventSAID  SAID of the event being anchored
    /// @param  verifier   Approved IKERIVerifier contract that validates proof
    /// @param  proof      Verifier-specific bytes (ZK proof, etc.)
    function anchorEvent(
        bytes32        prefix,
        uint64         sn,
        bytes32        eventSAID,
        address        verifier,
        bytes calldata proof
    ) external {
        require(approvedVerifiers[verifier], "KERIBacker: verifier not approved");
        bytes32 messageHash = keccak256(abi.encode(prefix, sn, eventSAID));
        require(IKERIVerifier(verifier).verify(messageHash, proof), "KERIBacker: verification failed");
        _anchor(prefix, sn, eventSAID, verifier);
    }

    /// @notice Anchor multiple KERI key event commitments in a single transaction.
    /// @param  anchors   Array of (prefix, sn, eventSAID) tuples to anchor.
    /// @param  verifier  Approved IKERIVerifier contract that validates proof
    /// @param  proof     Verifier-specific bytes covering keccak256(abi.encode(anchors))
    function anchorBatch(
        Anchor[] calldata anchors,
        address           verifier,
        bytes calldata    proof
    ) external {
        require(approvedVerifiers[verifier], "KERIBacker: verifier not approved");
        bytes32 messageHash = keccak256(abi.encode(anchors));
        require(IKERIVerifier(verifier).verify(messageHash, proof), "KERIBacker: verification failed");
        for (uint256 i = 0; i < anchors.length; i++) {
            _anchor(anchors[i].prefix, anchors[i].sn, anchors[i].eventSAID, verifier);
        }
    }

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    /// @notice Returns the full anchor record for a (prefix, sn) pair.
    function getAnchor(bytes32 prefix, uint64 sn)
        external view returns (AnchorRecord memory)
    {
        return _anchors[prefix][sn];
    }

    /// @notice Returns true if an event with the given SAID is anchored at (prefix, sn).
    function isAnchored(bytes32 prefix, uint64 sn, bytes32 eventSAID)
        external view returns (bool)
    {
        AnchorRecord storage rec = _anchors[prefix][sn];
        return rec.exists && rec.eventSAID == eventSAID;
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    function _anchor(bytes32 prefix, uint64 sn, bytes32 eventSAID, address verifier) internal {
        AnchorRecord storage rec = _anchors[prefix][sn];

        if (rec.exists) {
            if (rec.eventSAID != eventSAID) {
                emit DuplicityDetected(prefix, sn, rec.eventSAID, eventSAID);
            }
            return;
        }

        rec.eventSAID   = eventSAID;
        rec.blockNumber = uint64(block.number);
        rec.verifier    = verifier;
        rec.exists      = true;

        emit KERIEventAnchored(prefix, sn, eventSAID, verifier);
    }
}
