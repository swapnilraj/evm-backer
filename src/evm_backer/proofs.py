# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.proofs module

SP1 ZK proof generation for Ed25519 verification.

Two modes:
- generate_sp1_proof(): calls the sp1-prover binary (requires SP1 toolchain)
- make_mock_sp1_proof(): returns empty proof bytes for use with SP1MockVerifier in tests

Reference:
  - evm-backer-spec.md section 3.3 (ZK Proof Integration)
"""

import json
import os
import subprocess
from pathlib import Path

from eth_abi import encode

# Path to the compiled sp1-prover binary (built with `cargo build --release`).
# The binary lives in the workspace root target/ directory, not sp1-prover/target/.
_PROJECT_ROOT = Path(__file__).parent.parent.parent
PROVER_BIN = _PROJECT_ROOT / "target" / "release" / "sp1-prover"


def generate_sp1_proof(
    signing_key, message_hash: bytes, pubkey_bytes: bytes
) -> tuple[bytes, bytes, str]:
    """Generate an SP1 ZK proof of Ed25519 signature verification.

    Calls the sp1-prover binary, which runs the SP1 guest program (sp1-guest)
    that verifies the Ed25519 signature inside the zkVM and commits to
    (backerPubKey, messageHash) as public outputs.

    The prover generates a Groth16 proof suitable for on-chain verification
    via the SP1VerifierGroth16 contract.

    Requires:
      - SP1 toolchain installed (sp1up)
      - sp1-prover binary compiled (cargo build --release in sp1-prover/)

    Args:
        signing_key: nacl.signing.SigningKey — used to produce the Ed25519 sig.
        message_hash: 32-byte message hash to prove knowledge of signing.
        pubkey_bytes: 32-byte Ed25519 public key (backer's verify key).

    Returns:
        (proof_bytes, public_values, vkey) where:
          - proof_bytes: the SP1 Groth16 proof (variable length)
          - public_values: 64 bytes = pubkey (32) || msg_hash (32)
          - vkey: the SP1 program verification key as a 0x-prefixed hex string
    """
    sig = signing_key.sign(message_hash).signature  # 64 bytes

    # SP1_PROVER controls the proving mode: "local" (real Groth16, default),
    # "mock" (instant, guest executes but proof is empty), "network" (Succinct's
    # remote network). The subprocess inherits the caller's environment; we only
    # set a default if SP1_PROVER is not already present.
    env = os.environ.copy()
    env.setdefault("SP1_PROVER", "cpu")

    result = subprocess.run(
        [
            str(PROVER_BIN),
            pubkey_bytes.hex(),
            message_hash.hex(),
            sig.hex(),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=600,  # Groth16 proving can take several minutes
        env=env,
    )

    # The prover writes progress messages to stdout before the final JSON line.
    # Find the last line that is valid JSON.
    json_line = next(
        line for line in reversed(result.stdout.splitlines()) if line.strip().startswith("{")
    )
    data = json.loads(json_line)
    return (
        bytes.fromhex(data["proof"]),
        bytes.fromhex(data["publicValues"]),
        data["vkey"],
    )


def make_mock_sp1_proof(backer_pubkey: bytes, message_hash: bytes) -> tuple[bytes, bytes]:
    """Build mock SP1 proof inputs for testing with SP1MockVerifier.

    SP1MockVerifier (from sp1-contracts) accepts any call where
    proofBytes.length == 0. It does NOT verify the proof — it only
    checks the public values format.

    Args:
        backer_pubkey: 32-byte Ed25519 public key (bytes32).
        message_hash: 32-byte message hash (bytes32).

    Returns:
        (proof_bytes, public_values) where:
          - proof_bytes: b"" (empty — required by SP1MockVerifier)
          - public_values: 64 bytes = abi.encode(bytes32, bytes32)
    """
    public_values = encode(["bytes32", "bytes32"], [backer_pubkey, message_hash])
    return b"", public_values
