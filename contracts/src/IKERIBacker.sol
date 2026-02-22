// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title  IKERIBacker
/// @notice Minimal interface for querying KERI event anchors.
interface IKERIBacker {
    /// @notice Returns true if the event (prefix, sn, eventSAID) is on-chain.
    function isAnchored(bytes32 prefix, uint64 sn, bytes32 eventSAID)
        external view returns (bool);
}
