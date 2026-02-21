// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {KERIBacker} from "../src/KERIBacker.sol";
import {Ed25519Verifier} from "../src/Ed25519Verifier.sol";

contract Deploy is Script {
    function run() external {
        address owner = vm.envAddress("OWNER_ADDRESS");
        require(owner != address(0), "Deploy: OWNER_ADDRESS must be set");

        vm.startBroadcast();

        // Deploy permissionless Ed25519Verifier (no approved-pubkeys list)
        Ed25519Verifier ed25519Verifier = new Ed25519Verifier();
        console.log("Ed25519Verifier deployed at:", address(ed25519Verifier));

        // Deploy global KERIBacker (one per ecosystem)
        KERIBacker kb = new KERIBacker(owner);
        console.log("KERIBacker deployed at:", address(kb));

        // Register the verifier with KERIBacker
        kb.approveVerifier(address(ed25519Verifier));

        vm.stopBroadcast();
    }
}
