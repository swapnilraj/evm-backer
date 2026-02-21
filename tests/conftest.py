# -*- encoding: utf-8 -*-
"""
EVM Backer Test Configuration

Shared pytest fixtures for the EVM backer test suite.

Every fixture uses real infrastructure:
- anvil: real local EVM node (subprocess, session-scoped)
- forge: real Solidity contract compilation and deployment
- keripy: real Habery with in-memory keystore
- web3.py: real JSON-RPC connection to anvil
- pynacl: real Ed25519 signing for contract auth

No mocks, no stubs, no monkeypatching.
"""

import json
import os
import signal
import subprocess
import time

import pytest
from nacl.signing import SigningKey
from web3 import Web3

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ANVIL_HOST = "127.0.0.1"
ANVIL_PORT = 8545
ANVIL_RPC_URL = f"http://{ANVIL_HOST}:{ANVIL_PORT}"

# anvil's deterministic account #0 (default deployer)
# Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ANVIL_DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_DEPLOYER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# anvil's deterministic account #1 (used for gas payment)
ANVIL_BACKER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ANVIL_BACKER_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

# Ed25519 test key pair (RFC 8032 test vector 3 seed)
# This is the Ed25519 key used for contract access control.
# The secp256k1 key (ANVIL_BACKER_KEY) is only for gas payment.
ED25519_SEED_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
ED25519_SIGNING_KEY = SigningKey(bytes.fromhex(ED25519_SEED_HEX))
ED25519_PUBKEY_HEX = ED25519_SIGNING_KEY.verify_key.encode().hex()
# "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"

# Known salts from keripy test fixtures — used for deterministic golden tests.
# These produce repeatable KERI AIDs so tests can assert exact prefix values.
BACKER_SALT_RAW = b"0123456789abcdef"
CONTROLLER_SALT_RAW = b"abcdef0123456789"

# Golden seeds from keripy test suite — shared across test files.
SEED_0 = (
    b'\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa '
    b'\xc4\x1bG\x11\xc4\xaeSAR\xc9\xbd\x04\x9d\x85)~\x93'
)
SEED_1 = (
    b'\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf'
    b'\xacQ\xb5\xd6Y^\xa2E\xfa\x015\x98Y\xdd\xe8'
)
SEED_2 = (
    b'\xbe\x96\x02\xa9\x88\xce\xf9O\x1e\x0fo\xc0\xff\x98\xb6\xfa'
    b'\x1e\xa2y\xf2e\xf9AL\x1aeK\xafj\xa1pB'
)

# Paths relative to project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRACTS_DIR = os.path.join(PROJECT_ROOT, "contracts")
CONTRACT_SRC = os.path.join(CONTRACTS_DIR, "src", "KERIBacker.sol")


# ---------------------------------------------------------------------------
# anvil process fixture (session-scoped)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def anvil_process():
    """Start a real anvil node as a subprocess.

    anvil is Foundry's local EVM node. It starts with 10 deterministic
    accounts, each funded with 10000 ETH. We use account #0 for deployment
    and account #1 as the backer's Ethereum address.

    The fixture kills anvil on teardown. If anvil fails to start within
    5 seconds (e.g. port already in use), the test session fails immediately.
    """
    proc = subprocess.Popen(
        [
            "anvil",
            "--host", ANVIL_HOST,
            "--port", str(ANVIL_PORT),
            "--accounts", "10",
            "--balance", "10000",
            "--block-time", "1",  # 1-second block time for confirmation tests
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for anvil to be ready by polling the RPC endpoint
    w3 = Web3(Web3.HTTPProvider(ANVIL_RPC_URL))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if w3.is_connected():
                break
        except Exception:
            pass
        time.sleep(0.2)
    else:
        proc.kill()
        proc.wait()
        pytest.fail(
            f"anvil did not start within 10 seconds on {ANVIL_RPC_URL}. "
            f"stderr: {proc.stderr.read().decode()}"
        )

    yield proc

    # Teardown: kill anvil
    os.kill(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------------------
# web3 connection fixture (session-scoped)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def w3(anvil_process):
    """Provide a web3.py connection to the running anvil node.

    Depends on anvil_process to ensure the node is running before
    any test tries to connect.
    """
    w3 = Web3(Web3.HTTPProvider(ANVIL_RPC_URL))
    assert w3.is_connected(), f"web3 cannot connect to anvil at {ANVIL_RPC_URL}"
    return w3


# ---------------------------------------------------------------------------
# Contract deployment fixture (session-scoped)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def deployed_contract(w3):
    """Compile and deploy KERIBacker.sol to anvil using forge.

    Uses `forge create` to compile the contract from source and deploy it
    in a single step. The backer address (anvil account #1) is passed as
    the constructor argument.

    Returns a dict with:
        - address: the deployed contract address
        - abi: the contract ABI (parsed from forge output)
        - contract: a web3.py Contract instance bound to the address
    """
    # Compile the contract to get the ABI
    compile_result = subprocess.run(
        [
            "forge", "build",
            "--root", CONTRACTS_DIR,
        ],
        capture_output=True,
        text=True,
    )
    if compile_result.returncode != 0:
        pytest.fail(
            f"forge build failed:\nstdout: {compile_result.stdout}\n"
            f"stderr: {compile_result.stderr}"
        )

    # Deploy using forge create — constructor takes bytes32 Ed25519 pubkey
    pubkey_arg = "0x" + ED25519_PUBKEY_HEX
    deploy_result = subprocess.run(
        [
            "forge", "create",
            "--root", CONTRACTS_DIR,
            "--rpc-url", ANVIL_RPC_URL,
            "--private-key", ANVIL_DEPLOYER_KEY,
            "--broadcast",
            "src/KERIBacker.sol:KERIBacker",
            "--constructor-args", pubkey_arg,
        ],
        capture_output=True,
        text=True,
    )
    if deploy_result.returncode != 0:
        pytest.fail(
            f"forge create failed:\nstdout: {deploy_result.stdout}\n"
            f"stderr: {deploy_result.stderr}"
        )

    # Parse the deployed address from forge create output
    # forge create outputs: "Deployed to: 0x..."
    contract_address = None
    for line in deploy_result.stdout.splitlines():
        if "Deployed to:" in line:
            contract_address = line.split("Deployed to:")[-1].strip()
            break

    if contract_address is None:
        pytest.fail(
            f"Could not parse contract address from forge create output:\n"
            f"{deploy_result.stdout}"
        )

    # Load the ABI from forge's output artifacts
    abi_path = os.path.join(
        CONTRACTS_DIR, "out", "KERIBacker.sol", "KERIBacker.json"
    )
    with open(abi_path) as f:
        artifact = json.load(f)

    abi = artifact["abi"]
    contract = w3.eth.contract(address=contract_address, abi=abi)

    return {
        "address": contract_address,
        "abi": abi,
        "contract": contract,
    }


# ---------------------------------------------------------------------------
# keripy Habery fixture (session-scoped)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def keri_habery():
    """Create a real keripy Habery with an in-memory (temp) keystore.

    Uses keripy's built-in temp mode which stores everything in memory
    and cleans up on close. No disk I/O, no leftover state between runs.

    A known salt (from keripy test fixtures) is used so that derived
    identities are deterministic across test runs. This enables golden
    tests that assert exact prefix values.

    The Habery is the root object in keripy that manages identifiers,
    keystores, and databases.
    """
    from keri.app import habbing
    from keri.core.signing import Salter

    salt = Salter(raw=BACKER_SALT_RAW).qb64
    hby = habbing.Habery(name="test-evm-backer", temp=True, salt=salt)
    yield hby
    hby.close()


@pytest.fixture(scope="session")
def backer_hab(keri_habery):
    """Create a real backer Hab (non-transferable, as spec requires).

    This mirrors the production code path exactly:
        hab = hby.makeHab(name=alias, transferable=False)

    The resulting inception event has:
        - t: "icp"
        - n: [] (empty — no rotation possible)
        - b: [] (empty — backers cannot have backers)
        - kt: "1", k: [<Ed25519 pubkey>]

    This fixture is session-scoped because the backer identity is stable
    across all tests.
    """
    hab = keri_habery.makeHab(name="test-backer", transferable=False)
    return hab


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

def _send_anchor_tx(w3, contract, backer_account, prefix_b32, sn, said_b32):
    """Submit an anchorEvent transaction signed by the backer.

    The contract requires an Ed25519 signature over
    keccak256(abi.encode(prefix, sn, eventSAID)).
    """
    # Compute the message hash the same way the contract does
    encoded = w3.codec.encode(
        ["bytes32", "uint64", "bytes32"],
        [prefix_b32, sn, said_b32],
    )
    msg_hash = Web3.keccak(encoded)
    sig = ED25519_SIGNING_KEY.sign(msg_hash).signature

    tx = contract.functions.anchorEvent(
        prefix_b32, sn, said_b32, sig
    ).build_transaction({
        "from": backer_account.address,
        "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
        "chainId": w3.eth.chain_id,
        "gas": 1_500_000,  # Ed25519 on-chain verification is gas-intensive
    })
    signed = backer_account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


# ---------------------------------------------------------------------------
# Convenience fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def contract_address(deployed_contract):
    """Shortcut to get just the deployed contract address."""
    return deployed_contract["address"]


@pytest.fixture(scope="session")
def contract(deployed_contract):
    """Shortcut to get the web3.py Contract instance."""
    return deployed_contract["contract"]


@pytest.fixture(scope="session")
def backer_account(w3):
    """Return the backer's Ethereum account for gas payment (secp256k1).

    Uses anvil's deterministic account #1. This key is only used to pay
    gas — contract access control uses Ed25519 signatures instead.
    """
    from eth_account import Account

    account = Account.from_key(ANVIL_BACKER_KEY)
    return account


@pytest.fixture(scope="session")
def backer_signing_key():
    """Return the backer's Ed25519 signing key for contract auth."""
    return ED25519_SIGNING_KEY


@pytest.fixture(scope="session")
def deployer_account(w3):
    """Return the deployer's Ethereum account (anvil account #0).

    Used only for contract deployment. Not the backer.
    """
    from eth_account import Account

    account = Account.from_key(ANVIL_DEPLOYER_KEY)
    return account


# ---------------------------------------------------------------------------
# SP1 ZK fixtures (session-scoped)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def mock_sp1_verifier(w3, anvil_process):
    """Deploy SP1MockVerifier to anvil and return its address.

    SP1MockVerifier accepts any verifyProof() call where proofBytes.length == 0.
    This allows ZK path tests to run without the real SP1 toolchain.
    """
    # Build must have already run via deployed_contract; run again for safety.
    compile_result = subprocess.run(
        ["forge", "build", "--root", CONTRACTS_DIR],
        capture_output=True,
        text=True,
    )
    if compile_result.returncode != 0:
        pytest.fail(
            f"forge build failed:\nstdout: {compile_result.stdout}\n"
            f"stderr: {compile_result.stderr}"
        )

    deploy_result = subprocess.run(
        [
            "forge", "create",
            "--root", CONTRACTS_DIR,
            "--rpc-url", ANVIL_RPC_URL,
            "--private-key", ANVIL_DEPLOYER_KEY,
            "--broadcast",
            "lib/sp1-contracts/contracts/src/SP1MockVerifier.sol:SP1MockVerifier",
        ],
        capture_output=True,
        text=True,
    )
    if deploy_result.returncode != 0:
        pytest.fail(
            f"forge create SP1MockVerifier failed:\nstdout: {deploy_result.stdout}\n"
            f"stderr: {deploy_result.stderr}"
        )

    mock_address = None
    for line in deploy_result.stdout.splitlines():
        if "Deployed to:" in line:
            mock_address = line.split("Deployed to:")[-1].strip()
            break

    if mock_address is None:
        pytest.fail(
            f"Could not parse SP1MockVerifier address from:\n{deploy_result.stdout}"
        )

    return mock_address


@pytest.fixture(scope="session")
def contract_with_zk(w3, mock_sp1_verifier):
    """Deploy a fresh KERIBacker and configure the SP1 ZK verifier.

    Calls setZKVerifier(mockAddr, bytes32(0), sig, nonce=42) so that
    anchorEventWithZKProof and anchorBatchWithZKProof can be tested
    without the real SP1 prover.

    Returns a dict with 'address', 'abi', 'contract', 'mock_sp1_address'.
    """
    from eth_account import Account

    # Deploy fresh KERIBacker for ZK tests (separate from the one in deployed_contract)
    pubkey_arg = "0x" + ED25519_PUBKEY_HEX
    deploy_result = subprocess.run(
        [
            "forge", "create",
            "--root", CONTRACTS_DIR,
            "--rpc-url", ANVIL_RPC_URL,
            "--private-key", ANVIL_DEPLOYER_KEY,
            "--broadcast",
            "src/KERIBacker.sol:KERIBacker",
            "--constructor-args", pubkey_arg,
        ],
        capture_output=True,
        text=True,
    )
    if deploy_result.returncode != 0:
        pytest.fail(
            f"forge create KERIBacker (ZK) failed:\nstdout: {deploy_result.stdout}\n"
            f"stderr: {deploy_result.stderr}"
        )

    contract_address = None
    for line in deploy_result.stdout.splitlines():
        if "Deployed to:" in line:
            contract_address = line.split("Deployed to:")[-1].strip()
            break

    if contract_address is None:
        pytest.fail(
            f"Could not parse KERIBacker address from:\n{deploy_result.stdout}"
        )

    abi_path = os.path.join(CONTRACTS_DIR, "out", "KERIBacker.sol", "KERIBacker.json")
    with open(abi_path) as f:
        artifact = json.load(f)

    abi = artifact["abi"]
    contract = w3.eth.contract(address=contract_address, abi=abi)

    # Configure ZK verifier: setZKVerifier(mockAddr, bytes32(0), sig, nonce=42)
    # Message: keccak256(abi.encodePacked(address mockAddr, bytes32 vkey, uint256 nonce))
    zk_nonce = 42
    sp1_vkey = b'\x00' * 32  # bytes32(0)
    mock_addr_bytes = bytes.fromhex(mock_sp1_verifier.lstrip("0x").zfill(40))

    # abi.encodePacked(address, bytes32, uint256) = 20 + 32 + 32 = 84 bytes
    packed = mock_addr_bytes + sp1_vkey + zk_nonce.to_bytes(32, "big")
    msg_hash = Web3.keccak(packed)
    sig = ED25519_SIGNING_KEY.sign(msg_hash).signature

    backer_acc = Account.from_key(ANVIL_BACKER_KEY)
    tx = contract.functions.setZKVerifier(
        mock_sp1_verifier, sp1_vkey, sig, zk_nonce
    ).build_transaction({
        "from": backer_acc.address,
        "nonce": w3.eth.get_transaction_count(backer_acc.address, "pending"),
        "chainId": w3.eth.chain_id,
        "gas": 1_500_000,  # Ed25519.verify costs ~692k gas
    })
    signed_tx = backer_acc.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1, (
        f"setZKVerifier failed (status=0) for contract at {contract_address}. "
        f"Gas used: {receipt.gasUsed}"
    )

    return {
        "address": contract_address,
        "abi": abi,
        "contract": contract,
        "mock_sp1_address": mock_sp1_verifier,
    }
