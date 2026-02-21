// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Ed25519.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title  KERIBacker
/// @notice On-chain anchor for KERI key events with Ed25519 signature verification.
///
/// Controllers submit key events to the backer service (off-chain), which
/// validates them via keripy and then anchors each event's SAID here.
/// Other smart contracts call isAnchored() to verify key state without an oracle.
///
/// Access control uses Ed25519 signature verification instead of msg.sender
/// checks. This enables tight identity binding: the backer uses ONE Ed25519
/// key for both its KERI identity and Ethereum authorization (C1 fix per spec).
///
/// The first-seen policy mirrors KERI's own ordering: once an event is anchored
/// at (prefix, sn), no conflicting event can overwrite it. The ledger's
/// immutability is the duplicity protection mechanism.
///
/// Design decisions:
///   - Raw CESR bytes are NOT stored (gas cost, unnecessary for on-chain queries).
///     The backer's HTTP endpoint serves full event bytes. The SAID is sufficient
///     for isAnchored() verification.
///   - sn is uint64 throughout (KERI sequence numbers are unbounded integers;
///     uint32 would silently truncate at ~4 billion events).
///   - backerPubKey is the Ed25519 public key (32 bytes, compressed point).
///     Rotatable via rotateBacker with a signature from the current key.
contract KERIBacker {

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a KERI key event commitment is anchored on-chain.
    event KERIEventAnchored(
        bytes32 indexed prefix,
        uint64  indexed sn,
        bytes32 indexed eventSAID
    );

    /// @notice Emitted when the authorised backer key is rotated.
    event BackerRotated(
        bytes32 indexed oldPubKey,
        bytes32 indexed newPubKey
    );

    /// @notice Emitted when the SP1 ZK verifier address and program key are configured.
    event ZKVerifierConfigured(
        address indexed sp1Verifier,
        bytes32         sp1VKey
    );

    /// @notice Emitted when a conflicting SAID is submitted at a (prefix, sn)
    ///         that already has a different SAID anchored.
    event DuplicityDetected(
        bytes32 indexed prefix,
        uint64  indexed sn,
        bytes32         firstSeenSAID,
        bytes32         conflictingSAID
    );

    // -------------------------------------------------------------------------
    // Storage types
    // -------------------------------------------------------------------------

    struct AnchorRecord {
        bytes32 eventSAID;
        uint64  blockNumber;
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

    /// @notice The Ed25519 public key authorised to sign anchor and rotation operations.
    bytes32 public backerPubKey;

    /// @notice SP1 zkVM verifier contract (address(0) until configured via setZKVerifier).
    ISP1Verifier public sp1Verifier;

    /// @notice SP1 program verification key — keccak256 hash of the guest ELF.
    bytes32 public sp1VKey;

    /// @dev Replay protection: tracks used signature nonces.
    mapping(uint256 => bool) private _usedNonces;

    /// @dev prefix -> sn -> AnchorRecord
    mapping(bytes32 => mapping(uint64 => AnchorRecord)) private _anchors;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    constructor(bytes32 _backerPubKey) {
        require(_backerPubKey != bytes32(0), "KERIBacker: zero pubkey");
        backerPubKey = _backerPubKey;
    }

    // -------------------------------------------------------------------------
    // Signature verification
    // -------------------------------------------------------------------------

    /// @dev Verify an Ed25519 signature over a message hash using the current backer key.
    function _verifySig(bytes32 messageHash, bytes memory sig) internal view {
        require(sig.length == 64, "KERIBacker: invalid sig length");
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
        }
        require(
            Ed25519.verify(backerPubKey, r, s, abi.encodePacked(messageHash)),
            "KERIBacker: invalid signature"
        );
    }

    // -------------------------------------------------------------------------
    // Key rotation
    // -------------------------------------------------------------------------

    /// @notice Rotate the authorised backer key to a new Ed25519 public key.
    /// @dev    The current key must sign the new key to authorise the rotation.
    /// @param  newPubKey  The new Ed25519 public key.
    /// @param  sig        Ed25519 signature of keccak256(abi.encodePacked(newPubKey, nonce))
    ///                    signed by the current backer key.
    /// @param  nonce      Replay protection nonce (must not have been used before).
    function rotateBacker(bytes32 newPubKey, bytes memory sig, uint256 nonce) external {
        require(newPubKey != bytes32(0), "KERIBacker: zero pubkey");
        require(!_usedNonces[nonce], "KERIBacker: nonce reused");
        _usedNonces[nonce] = true;

        bytes32 messageHash = keccak256(abi.encodePacked(newPubKey, nonce));
        _verifySig(messageHash, sig);

        emit BackerRotated(backerPubKey, newPubKey);
        backerPubKey = newPubKey;
    }

    // -------------------------------------------------------------------------
    // ZK verifier configuration
    // -------------------------------------------------------------------------

    /// @notice Configure the SP1 ZK verifier address and program key.
    /// @dev    Authenticated with an Ed25519 signature + nonce replay protection.
    ///         This allows key holders to switch to a new SP1 verifier contract
    ///         (e.g. after a Succinct protocol upgrade) without key rotation.
    /// @param  _sp1Verifier  Address of the ISP1Verifier contract.
    /// @param  _sp1VKey      SP1 program verification key (keccak256 of guest ELF).
    /// @param  sig           Ed25519 signature of keccak256(abi.encodePacked(_sp1Verifier, _sp1VKey, nonce))
    /// @param  nonce         Replay protection nonce (must not have been used before).
    function setZKVerifier(
        address _sp1Verifier,
        bytes32 _sp1VKey,
        bytes memory sig,
        uint256 nonce
    ) external {
        require(!_usedNonces[nonce], "KERIBacker: nonce reused");
        _usedNonces[nonce] = true;

        bytes32 messageHash = keccak256(abi.encodePacked(_sp1Verifier, _sp1VKey, nonce));
        _verifySig(messageHash, sig);

        sp1Verifier = ISP1Verifier(_sp1Verifier);
        sp1VKey = _sp1VKey;

        emit ZKVerifierConfigured(_sp1Verifier, _sp1VKey);
    }

    // -------------------------------------------------------------------------
    // Anchoring
    // -------------------------------------------------------------------------

    /// @notice Anchor a single KERI key event commitment on-chain.
    /// @param  prefix     Controller AID prefix (bytes32)
    /// @param  sn         Event sequence number
    /// @param  eventSAID  SAID of the event being anchored
    /// @param  sig        Ed25519 signature over keccak256(abi.encode(prefix, sn, eventSAID))
    function anchorEvent(
        bytes32 prefix,
        uint64  sn,
        bytes32 eventSAID,
        bytes memory sig
    ) external {
        bytes32 messageHash = keccak256(abi.encode(prefix, sn, eventSAID));
        _verifySig(messageHash, sig);
        _anchor(prefix, sn, eventSAID);
    }

    /// @notice Anchor multiple KERI key event commitments in a single transaction.
    /// @param  anchors  Array of (prefix, sn, eventSAID) tuples to anchor.
    /// @param  sig      Ed25519 signature over keccak256(abi.encode(anchors))
    function anchorBatch(Anchor[] calldata anchors, bytes calldata sig) external {
        bytes32 messageHash = keccak256(abi.encode(anchors));
        _verifySig(messageHash, sig);
        for (uint256 i = 0; i < anchors.length; i++) {
            _anchor(anchors[i].prefix, anchors[i].sn, anchors[i].eventSAID);
        }
    }

    /// @notice Anchor a single KERI key event commitment using an SP1 ZK proof of Ed25519 signing.
    /// @dev    Uses the SP1 zkVM verifier instead of the on-chain Ed25519 library (~275k vs ~692k gas).
    ///         The ZK proof commits to (backerPubKey, messageHash) as public outputs.
    /// @param  prefix        Controller AID prefix (bytes32)
    /// @param  sn            Event sequence number
    /// @param  eventSAID     SAID of the event being anchored
    /// @param  publicValues  64-byte SP1 public output: abi.encode(bytes32 pubKey, bytes32 msgHash)
    /// @param  proofBytes    SP1 proof bytes (empty string "" when using SP1MockVerifier in tests)
    function anchorEventWithZKProof(
        bytes32 prefix,
        uint64  sn,
        bytes32 eventSAID,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external {
        bytes32 messageHash = keccak256(abi.encode(prefix, sn, eventSAID));
        _verifyZKSig(messageHash, publicValues, proofBytes);
        _anchor(prefix, sn, eventSAID);
    }

    /// @notice Anchor multiple KERI key events using a single SP1 ZK proof of Ed25519 signing.
    /// @param  anchors       Array of (prefix, sn, eventSAID) tuples to anchor.
    /// @param  publicValues  64-byte SP1 public output: abi.encode(bytes32 pubKey, bytes32 msgHash)
    /// @param  proofBytes    SP1 proof bytes (empty string "" when using SP1MockVerifier in tests)
    function anchorBatchWithZKProof(
        Anchor[] calldata anchors,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external {
        bytes32 messageHash = keccak256(abi.encode(anchors));
        _verifyZKSig(messageHash, publicValues, proofBytes);
        for (uint256 i = 0; i < anchors.length; i++) {
            _anchor(anchors[i].prefix, anchors[i].sn, anchors[i].eventSAID);
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

    /// @dev Verify an SP1 ZK proof that the backer signed the expected message hash.
    ///      Decodes the SP1 public values and checks both the pubkey and message hash
    ///      match what the contract expects.
    function _verifyZKSig(
        bytes32 expectedMsgHash,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) internal view {
        require(address(sp1Verifier) != address(0), "KERIBacker: ZK verifier not configured");
        sp1Verifier.verifyProof(sp1VKey, publicValues, proofBytes);
        (bytes32 pvPubKey, bytes32 pvMsgHash) = abi.decode(publicValues, (bytes32, bytes32));
        require(pvPubKey == backerPubKey, "KERIBacker: ZK proof wrong pubkey");
        require(pvMsgHash == expectedMsgHash, "KERIBacker: ZK proof wrong message");
    }

    function _anchor(bytes32 prefix, uint64 sn, bytes32 eventSAID) internal {
        AnchorRecord storage rec = _anchors[prefix][sn];

        if (rec.exists) {
            if (rec.eventSAID != eventSAID) {
                emit DuplicityDetected(prefix, sn, rec.eventSAID, eventSAID);
            }
            return;
        }

        rec.eventSAID   = eventSAID;
        rec.blockNumber = uint64(block.number);
        rec.exists      = true;

        emit KERIEventAnchored(prefix, sn, eventSAID);
    }
}
