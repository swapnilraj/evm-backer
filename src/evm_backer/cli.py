# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.cli module

Command-line interface for the EVM backer service.

Commands:
  evm-backer start  — Start the backer service
  evm-backer info   — Show backer AID, Ethereum address, config
  evm-backer query  — Query on-chain anchor state
"""

import argparse
import json
import logging
import sys

from evm_backer.service import (
    build_service,
    load_config,
    load_contract_abi,
    run_service,
    setup_backer_hab,
    setup_web3,
)
from evm_backer.transactions import prefix_to_bytes32, said_to_bytes32


def cmd_start(args):
    """Start the backer service."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    run_service()


def cmd_info(args):
    """Show backer AID prefix, Ethereum address, and configuration."""
    config = load_config()
    hby, hab = setup_backer_hab(config)

    eth_address = ""
    if config["ETH_PRIVATE_KEY"]:
        from eth_account import Account
        account = Account.from_key(config["ETH_PRIVATE_KEY"])
        eth_address = account.address

    print(f"Backer AID:        {hab.pre}")
    print(f"Ethereum address:  {eth_address or '(no ETH_PRIVATE_KEY set)'}")
    print(f"Contract address:  {config['ETH_CONTRACT_ADDRESS'] or '(not set)'}")
    print(f"Chain ID:          {config['ETH_CHAIN_ID']}")
    print(f"RPC URL:           {config['ETH_RPC_URL']}")
    print(f"HTTP port:         {config['BACKER_PORT']}")
    print(f"Queue duration:    {config['QUEUE_DURATION']}s")
    print(f"Batch size:        {config['BATCH_SIZE']}")

    hby.close()


def cmd_query(args):
    """Query on-chain anchor state for a given prefix + sequence number."""
    config = load_config()

    if not config["ETH_CONTRACT_ADDRESS"]:
        print("Error: ETH_CONTRACT_ADDRESS not set", file=sys.stderr)
        sys.exit(1)

    w3 = setup_web3(config)
    abi = load_contract_abi()
    contract = w3.eth.contract(
        address=config["ETH_CONTRACT_ADDRESS"],
        abi=abi,
    )

    prefix_b32 = prefix_to_bytes32(args.prefix)
    sn = args.sn

    # Query all SAIDs is not possible without knowing the SAID,
    # so we query isAnchored if --said is provided, otherwise
    # just print the prefix hash for reference
    if args.said:
        said_b32 = said_to_bytes32(args.said)
        result = contract.functions.isAnchored(prefix_b32, sn, said_b32).call()
        print(f"Prefix:     {args.prefix}")
        print(f"SN:         {sn}")
        print(f"SAID:       {args.said}")
        print(f"Anchored:   {result}")
    else:
        print(f"Prefix:     {args.prefix}")
        print(f"Prefix b32: 0x{prefix_b32.hex()}")
        print(f"SN:         {sn}")
        print("Provide --said to check if a specific event is anchored")


def main():
    """Entry point for the evm-backer CLI."""
    parser = argparse.ArgumentParser(
        prog="evm-backer",
        description="EVM Ledger Registrar Backer for KERI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # evm-backer start
    start_parser = subparsers.add_parser(
        "start", help="Start the backer service"
    )
    start_parser.set_defaults(func=cmd_start)

    # evm-backer info
    info_parser = subparsers.add_parser(
        "info", help="Show backer AID and configuration"
    )
    info_parser.set_defaults(func=cmd_info)

    # evm-backer query
    query_parser = subparsers.add_parser(
        "query", help="Query on-chain anchor state"
    )
    query_parser.add_argument(
        "--prefix", required=True, help="Controller AID prefix (qb64)"
    )
    query_parser.add_argument(
        "--sn", required=True, type=int, help="Event sequence number"
    )
    query_parser.add_argument(
        "--said", help="Event SAID (qb64) to check anchoring"
    )
    query_parser.set_defaults(func=cmd_query)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
