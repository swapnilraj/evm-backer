// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {KERIBacker} from "../src/KERIBacker.sol";

contract Deploy is Script {
    function run() external {
        bytes32 backerPubKey = vm.envBytes32("BACKER_PUBKEY");
        require(backerPubKey != bytes32(0), "Deploy: BACKER_PUBKEY must be set");

        vm.startBroadcast();
        KERIBacker kb = new KERIBacker(backerPubKey);
        vm.stopBroadcast();

        console.log("KERIBacker deployed at:", address(kb));
        console.log("Backer pubkey:");
        console.logBytes32(backerPubKey);
    }
}
