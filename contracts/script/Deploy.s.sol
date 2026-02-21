// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {KERIBacker} from "../src/KERIBacker.sol";
import {Ed25519Verifier} from "../src/Ed25519Verifier.sol";

contract Deploy is Script {
    function run() external {
        address owner = vm.envAddress("OWNER_ADDRESS");
        require(owner != address(0), "Deploy: OWNER_ADDRESS must be set");

        bytes32 backerPubKey = vm.envBytes32("BACKER_PUBKEY");
        require(backerPubKey != bytes32(0), "Deploy: BACKER_PUBKEY must be set");

        vm.startBroadcast();

        // Deploy global KERIBacker (one per ecosystem)
        KERIBacker kb = new KERIBacker(owner);
        console.log("KERIBacker deployed at:", address(kb));

        // Deploy Ed25519Verifier and pre-approve the first backer pubkey
        Ed25519Verifier ed25519Verifier = new Ed25519Verifier(owner);
        ed25519Verifier.approveBacker(backerPubKey);
        console.log("Ed25519Verifier deployed at:", address(ed25519Verifier));

        // Register the verifier with KERIBacker
        kb.approveVerifier(address(ed25519Verifier));

        vm.stopBroadcast();

        console.log("Backer pubkey approved:");
        console.logBytes32(backerPubKey);
    }
}
