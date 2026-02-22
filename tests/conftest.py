# -*- encoding: utf-8 -*-
"""
EVM Backer Test Configuration

Shared pytest fixtures for the EVM backer test suite.

Every fixture uses real infrastructure:
- anvil: real local EVM node (subprocess, session-scoped)
- forge: real Solidity contract compilation and deployment
- keripy: real Habery with in-memory keystore
- web3.py: real JSON-RPC connection to anvil

No mocks, no stubs, no monkeypatching.
"""

import json
import os
import signal
import subprocess
import time

import pytest
from eth_abi import encode as abi_encode
from web3 import Web3

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ANVIL_HOST = "127.0.0.1"
ANVIL_PORT = 8545
ANVIL_RPC_URL = f"http://{ANVIL_HOST}:{ANVIL_PORT}"

# anvil's deterministic account #0 (default deployer, also acts as contract owner)
# Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ANVIL_DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_DEPLOYER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# anvil's deterministic account #1 (used for gas payment)
ANVIL_BACKER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ANVIL_BACKER_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

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
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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
            f"Is anvil installed and port {ANVIL_PORT} free?"
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
# Deployment helper
# ---------------------------------------------------------------------------

def _forge_create(contract_path, *constructor_args):
    """Deploy a contract via forge create and return the deployed address."""
    cmd = [
        "forge", "create",
        "--root", CONTRACTS_DIR,
        "--rpc-url", ANVIL_RPC_URL,
        "--private-key", ANVIL_DEPLOYER_KEY,
        "--broadcast",
        contract_path,
    ]
    if constructor_args:
        cmd += ["--constructor-args"] + list(constructor_args)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(
            f"forge create {contract_path} failed:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    for line in result.stdout.splitlines():
        if "Deployed to:" in line:
            return line.split("Deployed to:")[-1].strip()

    pytest.fail(f"Could not parse address from forge create output:\n{result.stdout}")


def _load_abi(contract_name):
    """Load a contract ABI from forge artifacts."""
    abi_path = os.path.join(CONTRACTS_DIR, "out", f"{contract_name}.sol", f"{contract_name}.json")
    with open(abi_path) as f:
        return json.load(f)["abi"]


def _call_contract(w3, address, abi, fn_name, *args):
    """Send a state-changing transaction from the deployer account."""
    from eth_account import Account

    deployer = Account.from_key(ANVIL_DEPLOYER_KEY)
    contract = w3.eth.contract(address=address, abi=abi)
    fn = getattr(contract.functions, fn_name)(*args)
    tx = fn.build_transaction({
        "from": deployer.address,
        "nonce": w3.eth.get_transaction_count(deployer.address, "pending"),
        "chainId": w3.eth.chain_id,
        "gas": 1_500_000,
    })
    signed = deployer.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1, f"{fn_name} failed (status=0)"
    return receipt


# ---------------------------------------------------------------------------
# Contract deployment fixture (session-scoped)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def deployed_contract(w3):
    """Compile and deploy KERIBacker to anvil.

    Deployment order:
      1. forge build (compile all contracts)
      2. Deploy KERIBacker(deployer_address)

    No verifier is pre-approved. ZK tests use their own contract_with_zk
    fixture which deploys SP1MockVerifier + SP1KERIVerifier + KERIBacker.

    Returns a dict with:
        - address: the deployed KERIBacker address
        - abi: the KERIBacker ABI
        - contract: a web3.py Contract instance for KERIBacker
    """
    # Compile all contracts
    compile_result = subprocess.run(
        ["forge", "build", "--root", CONTRACTS_DIR],
        capture_output=True, text=True,
    )
    if compile_result.returncode != 0:
        pytest.fail(
            f"forge build failed:\nstdout: {compile_result.stdout}\n"
            f"stderr: {compile_result.stderr}"
        )

    # Deploy KERIBacker with deployer as owner
    kb_address = _forge_create(
        "src/KERIBacker.sol:KERIBacker",
        ANVIL_DEPLOYER_ADDRESS,
    )

    kb_abi = _load_abi("KERIBacker")
    contract = w3.eth.contract(address=kb_address, abi=kb_abi)

    return {
        "address": kb_address,
        "abi": kb_abi,
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

def _send_anchor_tx_zk(w3, contract, backer_account, prefix_b32, sn, said_b32, verifier_address):
    """Submit an anchorEvent transaction using a mock SP1 ZK proof.

    The contract requires an approved verifier and a matching proof.
    For the SP1 ZK path: proof = abi.encode(publicValues, proofBytes)
    where publicValues = abi.encode(messageHash) and proofBytes = b""
    (for SP1MockVerifier).
    """
    from evm_backer.proofs import make_mock_sp1_proof

    # Compute the message hash the same way the contract does
    encoded = w3.codec.encode(
        ["bytes32", "uint64", "bytes32"],
        [prefix_b32, sn, said_b32],
    )
    msg_hash = Web3.keccak(encoded)
    contract_proof, _ = make_mock_sp1_proof(msg_hash)

    tx = contract.functions.anchorEvent(
        prefix_b32, sn, said_b32, verifier_address, contract_proof
    ).build_transaction({
        "from": backer_account.address,
        "nonce": w3.eth.get_transaction_count(backer_account.address, "pending"),
        "chainId": w3.eth.chain_id,
        "gas": 500_000,
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
    gas — contract access control uses ZK proofs for verification.
    """
    from eth_account import Account

    account = Account.from_key(ANVIL_BACKER_KEY)
    return account


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
def mock_sp1_verifier(w3, deployed_contract):
    """Deploy SP1MockVerifier to anvil and return its address.

    SP1MockVerifier accepts any verifyProof() call where proofBytes.length == 0.
    This allows ZK path tests to run without the real SP1 toolchain.

    Depends on deployed_contract to ensure forge build has already run.
    """
    mock_address = _forge_create(
        "lib/sp1-contracts/contracts/src/SP1MockVerifier.sol:SP1MockVerifier",
    )
    return mock_address


@pytest.fixture(scope="session")
def contract_with_zk(w3, mock_sp1_verifier):
    """Deploy SP1KERIVerifier + a fresh KERIBacker for ZK path tests.

    Deployment order:
      1. Deploy SP1KERIVerifier(mock_sp1_addr, bytes32(0)) — permissionless
      2. Deploy fresh KERIBacker(deployer_addr)
      3. approveVerifier(sp1_keri_verifier_addr) on KERIBacker

    Returns a dict with 'address', 'abi', 'contract', 'sp1_keri_verifier_address'.
    """
    # Deploy permissionless SP1KERIVerifier (2 args: sp1Verifier, vkey)
    sp1_keri_verifier_address = _forge_create(
        "src/SP1KERIVerifier.sol:SP1KERIVerifier",
        mock_sp1_verifier,
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    )

    # Deploy fresh KERIBacker for ZK tests (separate from the one in deployed_contract)
    kb_address = _forge_create(
        "src/KERIBacker.sol:KERIBacker",
        ANVIL_DEPLOYER_ADDRESS,
    )

    # Approve the SP1KERIVerifier
    kb_abi = _load_abi("KERIBacker")
    _call_contract(w3, kb_address, kb_abi, "approveVerifier", sp1_keri_verifier_address)

    contract = w3.eth.contract(address=kb_address, abi=kb_abi)

    return {
        "address": kb_address,
        "abi": kb_abi,
        "contract": contract,
        "sp1_keri_verifier_address": sp1_keri_verifier_address,
    }


@pytest.fixture(scope="class")
def tel_contracts(w3, deployed_contract):
    """Deploy SP1TELVerifier + fresh KERIBacker for TEL path tests.

    Depends on deployed_contract to ensure forge build has already run.

    Deployment order:
      1. SP1MockVerifier
      2. SP1KERIVerifier (for KEL anchoring, vkey=0)
      3. Fresh KERIBacker
      4. approveVerifier(sp1_keri_verifier)
      5. SP1TELVerifier (for TEL anchoring, vkey=0, points to KERIBacker)
      6. approveVerifier(sp1_tel_verifier)

    Returns dict with 'kb', 'kb_address', 'kel_verifier_addr', 'tel_verifier_addr'.
    """
    mock_sp1 = _forge_create(
        "lib/sp1-contracts/contracts/src/SP1MockVerifier.sol:SP1MockVerifier"
    )

    # Deploy fresh KERIBacker for TEL tests.
    kb_address = _forge_create(
        "src/KERIBacker.sol:KERIBacker",
        ANVIL_DEPLOYER_ADDRESS,
    )
    kb_abi = _load_abi("KERIBacker")

    # Deploy SP1KERIVerifier (KEL ZK path).
    kel_verifier_addr = _forge_create(
        "src/SP1KERIVerifier.sol:SP1KERIVerifier",
        mock_sp1,
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    )
    _call_contract(w3, kb_address, kb_abi, "approveVerifier", kel_verifier_addr)

    # Deploy SP1TELVerifier (TEL ZK path).
    tel_verifier_addr = _forge_create(
        "src/SP1TELVerifier.sol:SP1TELVerifier",
        mock_sp1,
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        kb_address,
    )
    _call_contract(w3, kb_address, kb_abi, "approveVerifier", tel_verifier_addr)

    kb = w3.eth.contract(address=kb_address, abi=kb_abi)

    return {
        "kb": kb,
        "kb_address": kb_address,
        "kel_verifier_addr": kel_verifier_addr,
        "tel_verifier_addr": tel_verifier_addr,
    }
