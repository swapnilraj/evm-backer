// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {KERIBacker} from "../src/KERIBacker.sol";
import {SP1KERIVerifier} from "../src/SP1KERIVerifier.sol";

contract Deploy is Script {
    function run() external {
        address owner = vm.envAddress("OWNER_ADDRESS");
        require(owner != address(0), "Deploy: OWNER_ADDRESS must be set");

        address sp1Verifier = vm.envAddress("SP1_VERIFIER_ADDRESS");
        bytes32 sp1VKey = vm.envBytes32("SP1_VKEY");

        vm.startBroadcast();

        // Deploy SP1KERIVerifier (permissionless, one per SP1 program version)
        SP1KERIVerifier sp1KeriVerifier = new SP1KERIVerifier(sp1Verifier, sp1VKey);
        console.log("SP1KERIVerifier deployed at:", address(sp1KeriVerifier));

        // Deploy global KERIBacker (one per ecosystem)
        KERIBacker kb = new KERIBacker(owner);
        console.log("KERIBacker deployed at:", address(kb));

        // Register the verifier with KERIBacker
        kb.approveVerifier(address(sp1KeriVerifier));

        vm.stopBroadcast();
    }
}
