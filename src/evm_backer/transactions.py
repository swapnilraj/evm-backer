# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.transactions module

Ethereum transaction construction and submission for the KERIBacker contract.

The contract uses Ed25519 signature verification for access control (C1 fix).
Each batch is signed with the backer's Ed25519 key and the signature is passed
alongside the anchors in the anchorBatch call.

Reference:
  - evm-backer-spec.md section 3 (Smart Contract)
  - evm-backer-spec.md section 5.6 (Transaction Submission)
"""

import logging

from nacl.signing import SigningKey
from web3 import Web3

logger = logging.getLogger(__name__)

FALLBACK_GAS_LIMIT = 1_500_000  # Ed25519 on-chain verification is gas-intensive
GAS_ESTIMATE_BUFFER = 1.2  # 20% safety margin on gas estimates
PRIORITY_FEE_FLOOR_WEI = 1_000_000_000  # 1 gwei minimum priority fee


def prefix_to_bytes32(qb64: str) -> bytes:
    """Convert qb64 AID prefix to bytes32 using keccak256 (M1 fix).

    keccak256 is collision-resistant and handles arbitrary-length prefixes
    without the truncation and padding ambiguity of base64url slicing.
    External contracts calling isAnchored() compute keccak256 on-chain.
    """
    return Web3.keccak(text=qb64)


def said_to_bytes32(qb64: str) -> bytes:
    """Convert qb64 SAID to bytes32 using keccak256 (M1 fix).

    SAIDs are short fixed-length strings; keccak256 is safe and unambiguous.
    """
    return Web3.keccak(text=qb64)


def estimate_eip1559_fees(w3):
    """Estimate EIP-1559 fee parameters from the current chain state.

    Returns:
        A dict with 'maxFeePerGas' and 'maxPriorityFeePerGas', or None
        if estimation fails (caller should fall back to legacy gas).
    """
    try:
        latest = w3.eth.get_block("latest")
        base_fee = latest["baseFeePerGas"]
    except Exception:
        return None

    try:
        priority_fee = w3.eth.max_priority_fee
    except Exception:
        priority_fee = PRIORITY_FEE_FLOOR_WEI

    priority_fee = max(priority_fee, PRIORITY_FEE_FLOOR_WEI)
    max_fee = base_fee * 2 + priority_fee

    return {
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": priority_fee,
    }


def ed25519_sign(signing_key, message):
    """Sign a message with an Ed25519 key.

    Args:
        signing_key: Either a nacl.signing.SigningKey, or any callable that
                     accepts bytes and returns a 64-byte signature. The
                     callable form is used in production to delegate signing
                     to the backer's keripy key manager.
        message: bytes to sign.

    Returns:
        64-byte Ed25519 signature (r || s).
    """
    if hasattr(signing_key, "sign"):
        return signing_key.sign(message).signature
    return signing_key(message)


def build_anchor_tx(w3, contract, backer_account, anchors, signing_key=None):
    """Build an anchorBatch transaction for a list of anchor tuples.

    Each anchor is a tuple of (prefix_bytes32, sn, said_bytes32).

    Uses EIP-1559 (type-2) fee estimation when the chain supports it,
    with a fallback to a fixed gas limit if estimation fails.

    The contract requires an Ed25519 signature over keccak256(abi.encode(anchors)).
    If signing_key is provided, the signature is computed and included.

    Args:
        w3: Web3 instance connected to an Ethereum node.
        contract: web3.py Contract instance for KERIBacker.
        backer_account: eth_account.Account for the gas payer (secp256k1 signer).
        anchors: list of (bytes32, int, bytes32) tuples.
        signing_key: nacl.signing.SigningKey for Ed25519 signing.

    Returns:
        A signed transaction ready for submission.
    """
    # Compute Ed25519 signature over the batch hash
    if signing_key is not None:
        # ABI-encode the anchors array the same way Solidity does
        encoded = w3.codec.encode(
            ["(bytes32,uint64,bytes32)[]"],
            [anchors],
        )
        msg_hash = Web3.keccak(encoded)
        sig = ed25519_sign(signing_key, msg_hash)
    else:
        sig = b""

    tx_params = {
        "from": backer_account.address,
        "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
        "chainId": w3.eth.chain_id,
    }

    # EIP-1559 fee estimation
    fee_params = estimate_eip1559_fees(w3)
    if fee_params is not None:
        tx_params.update(fee_params)
    else:
        logger.warning("EIP-1559 fee estimation failed, using legacy gas limit")

    # Dynamic gas estimation with buffer, fallback to hardcoded limit
    try:
        gas_estimate = contract.functions.anchorBatch(anchors, sig).estimate_gas(
            {"from": backer_account.address}
        )
        tx_params["gas"] = int(gas_estimate * GAS_ESTIMATE_BUFFER)
    except Exception:
        logger.warning(
            "Gas estimation failed, using fallback gas limit %d", FALLBACK_GAS_LIMIT
        )
        tx_params["gas"] = FALLBACK_GAS_LIMIT

    tx = contract.functions.anchorBatch(anchors, sig).build_transaction(tx_params)
    signed = backer_account.sign_transaction(tx)
    return signed


def build_anchor_tx_with_sp1_proof(w3, contract, backer_account, anchors, public_values, proof_bytes):
    """Build an anchorBatchWithZKProof transaction using SP1 ZK proof verification.

    The proof and public values come from generate_sp1_proof() (production) or
    make_mock_sp1_proof() (tests with SP1MockVerifier).

    Uses the same EIP-1559 fee estimation as build_anchor_tx. The SP1 verifier
    costs ~275k gas vs ~692k for on-chain Ed25519, so the fallback limit is kept
    at 1_500_000 for safety.

    Args:
        w3: Web3 instance connected to an Ethereum node.
        contract: web3.py Contract instance for KERIBacker.
        backer_account: eth_account.Account for the gas payer (secp256k1 signer).
        anchors: list of (bytes32, int, bytes32) tuples.
        public_values: bytes — 64-byte SP1 public output (abi.encode(pubkey, msgHash)).
        proof_bytes: bytes — SP1 proof (b"" when using SP1MockVerifier).

    Returns:
        A signed transaction ready for submission.
    """
    tx_params = {
        "from": backer_account.address,
        "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
        "chainId": w3.eth.chain_id,
    }

    fee_params = estimate_eip1559_fees(w3)
    if fee_params is not None:
        tx_params.update(fee_params)
    else:
        logger.warning("EIP-1559 fee estimation failed, using legacy gas limit")

    try:
        gas_estimate = contract.functions.anchorBatchWithZKProof(
            anchors, public_values, proof_bytes
        ).estimate_gas({"from": backer_account.address})
        tx_params["gas"] = int(gas_estimate * GAS_ESTIMATE_BUFFER)
    except Exception:
        logger.warning(
            "Gas estimation failed, using fallback gas limit %d", FALLBACK_GAS_LIMIT
        )
        tx_params["gas"] = FALLBACK_GAS_LIMIT

    tx = contract.functions.anchorBatchWithZKProof(
        anchors, public_values, proof_bytes
    ).build_transaction(tx_params)
    signed = backer_account.sign_transaction(tx)
    return signed


def submit_anchor_tx(w3, signed_tx):
    """Broadcast a signed transaction and return the tx hash.

    Args:
        w3: Web3 instance connected to an Ethereum node.
        signed_tx: A signed transaction object from build_anchor_tx.

    Returns:
        The transaction hash as a hex string.
    """
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    return "0x" + tx_hash.hex()
