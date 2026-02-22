# -*- encoding: utf-8 -*-
"""
EVM Backer
evm_backer.proofs module

SP1 ZK proof generation for KERI Key Event Log (KEL) and TEL verification.

Two modes:
- generate_sp1_proof(kel_input): calls the sp1-prover binary (KEL)
- generate_tel_proof(tel_input): calls the sp1-tel-prover binary (TEL)
- make_mock_sp1_proof(message_hash): builds encoded proof for SP1MockVerifier (KEL)
- make_mock_tel_proof(...): builds encoded proof for SP1MockVerifier (TEL)

Helpers:
- build_kel_input(kel_store, prefix_qb64, target_sn): converts keripy serder
  objects and raw signature bytes into the KelInput JSON dict.
- build_tel_input(kel_store, tel_serder, registry_prefix_qb64, controller_prefix_qb64, tel_sn):
  converts TEL event data into TelInput JSON dict.

Reference:
  - evm-backer-spec.md section 3.3 (ZK Proof Integration)
  - sp1-guest/src/lib.rs (KelInput / KeriEvent struct definitions)
  - sp1-tel-guest/src/lib.rs (TelInput struct definition)
"""

import json
import os
import subprocess
from pathlib import Path

from eth_abi import encode
from keri.core.coring import Diger

# Path to the compiled sp1-prover binaries (built with `cargo build --release`).
_PROJECT_ROOT = Path(__file__).parent.parent.parent
PROVER_BIN = _PROJECT_ROOT / "target" / "release" / "sp1-prover"
TEL_PROVER_BIN = _PROJECT_ROOT / "target" / "release" / "sp1-tel-prover"


def _parse_prover_output(result) -> tuple[bytes, bytes, str]:
    """Parse JSON output from sp1-prover or sp1-tel-prover.

    Both CLIs write progress logs to stdout before a final JSON line:
        {"proof": "0x...", "publicValues": "0x...", "vkey": "0x..."}

    Returns:
        (contract_proof, public_values, vkey) where:
          - contract_proof: abi.encode(publicValues, proofBytes)
          - public_values: raw proof public output bytes
          - vkey: SP1 program verification key as 0x-prefixed hex string
    """
    json_line = next(
        line for line in reversed(result.stdout.splitlines()) if line.strip().startswith("{")
    )
    data = json.loads(json_line)
    proof_bytes = bytes.fromhex(data["proof"])
    public_values = bytes.fromhex(data["publicValues"])
    contract_proof = encode(["bytes", "bytes"], [public_values, proof_bytes])
    return (contract_proof, public_values, data["vkey"])


def generate_sp1_proof(kel_input: dict) -> tuple[bytes, bytes, str]:
    """Generate an SP1 ZK proof of KERI KEL validity.

    Args:
        kel_input: dict matching the KelInput struct in sp1-guest/src/lib.rs.
                   Build with build_kel_input().

    Returns:
        (contract_proof, public_values, vkey) where:
          - contract_proof: abi.encode(publicValues, proofBytes) for SP1KERIVerifier
          - public_values: 32 bytes = abi.encode(bytes32 messageHash)
          - vkey: SP1 program verification key as 0x-prefixed hex string
    """
    json_bytes = json.dumps(kel_input).encode()
    hex_arg = json_bytes.hex()

    env = os.environ.copy()
    env.setdefault("SP1_PROVER", "cpu")

    result = subprocess.run(
        [str(PROVER_BIN), hex_arg],
        capture_output=True,
        text=True,
        check=True,
        timeout=600,
        env=env,
    )
    return _parse_prover_output(result)


def generate_tel_proof(tel_input: dict) -> tuple[bytes, bytes, str]:
    """Generate an SP1 ZK proof of KERI TEL event validity.

    Calls the sp1-tel-prover binary, which runs the SP1 TEL guest program.

    The public output is 192 bytes: abi.encode(
        bytes32 registryPrefixB32, uint64 telSn, bytes32 telSaidB32,
        bytes32 controllerPrefixB32, uint64 anchorSn, bytes32 anchorSaidB32
    ).

    Args:
        tel_input: dict matching the TelInput struct in sp1-tel-guest/src/lib.rs.
                   Build with build_tel_input().

    Returns:
        (contract_proof, public_values, vkey) where:
          - contract_proof: abi.encode(publicValues, proofBytes) for SP1TELVerifier
          - public_values: 192 bytes
          - vkey: SP1 program verification key as 0x-prefixed hex string
    """
    json_bytes = json.dumps(tel_input).encode()
    hex_arg = json_bytes.hex()

    env = os.environ.copy()
    env.setdefault("SP1_PROVER", "cpu")

    result = subprocess.run(
        [str(TEL_PROVER_BIN), hex_arg],
        capture_output=True,
        text=True,
        check=True,
        timeout=600,
        env=env,
    )
    return _parse_prover_output(result)


def make_mock_sp1_proof(message_hash: bytes) -> tuple[bytes, bytes]:
    """Build mock SP1 proof inputs for testing with SP1MockVerifier (KEL path).

    Args:
        message_hash: 32-byte message hash (bytes32).

    Returns:
        (contract_proof, public_values) where:
          - contract_proof: abi.encode(publicValues, b"") for anchorEvent/anchorBatch
          - public_values: 32 bytes = abi.encode(bytes32 messageHash)
    """
    public_values = encode(["bytes32"], [message_hash])
    contract_proof = encode(["bytes", "bytes"], [public_values, b""])
    return contract_proof, public_values


def make_mock_tel_proof(
    registry_prefix_b32: bytes,
    tel_sn: int,
    tel_said_b32: bytes,
    controller_prefix_b32: bytes,
    anchor_sn: int,
    anchor_said_b32: bytes,
) -> tuple[bytes, bytes]:
    """Build mock TEL proof inputs for testing with SP1MockVerifier (TEL path).

    SP1MockVerifier accepts any call where proofBytes.length == 0.

    The TEL guest's public output is 192 bytes:
    abi.encode(bytes32, uint64, bytes32, bytes32, uint64, bytes32).

    Args:
        registry_prefix_b32: keccak256(registry_prefix_qb64) as bytes32.
        tel_sn: TEL event sequence number.
        tel_said_b32: keccak256(tel_said_qb64) as bytes32.
        controller_prefix_b32: keccak256(controller_prefix_qb64) as bytes32.
        anchor_sn: sequence number of the controller KEL anchor event.
        anchor_said_b32: keccak256(anchor_said_qb64) as bytes32.

    Returns:
        (contract_proof, public_values) where:
          - contract_proof: abi.encode(publicValues, b"") for anchorEvent
          - public_values: 192 bytes
    """
    public_values = encode(
        ["bytes32", "uint64", "bytes32", "bytes32", "uint64", "bytes32"],
        [registry_prefix_b32, tel_sn, tel_said_b32,
         controller_prefix_b32, anchor_sn, anchor_said_b32],
    )
    contract_proof = encode(["bytes", "bytes"], [public_values, b""])
    return contract_proof, public_values


def build_kel_input(kel_store: dict, prefix_qb64: str, target_sn: int) -> dict:
    """Build a KelInput dict for the sp1-prover from stored KEL data.

    Supports icp (0), ixn (1), rot (2), dip (3), drt (4) event types.
    For delegated AIDs (dip/drt), automatically finds the delegation_event_idx
    and builds the delegating_kel recursively.

    Args:
        kel_store: dict mapping (prefix_qb64: str, sn: int) →
                   {"serder": Serder, "sigs": [(signer_idx: int, sig_bytes: bytes(64)), ...]}.
                   Single-sig convenience: "sigs": [(0, sig_bytes)].
        prefix_qb64: The controller's KERI prefix (e.g. "EAKCxMOu...").
        target_sn: The sequence number of the last event to include (inclusive).

    Returns:
        A dict matching the KelInput struct in sp1-guest/src/lib.rs.
    """
    if target_sn < 0:
        raise ValueError(f"target_sn must be >= 0, got {target_sn}")

    # Extract all initial signing keys from the genesis event (icp or dip).
    genesis_entry = kel_store.get((prefix_qb64, 0))
    if genesis_entry is None:
        raise KeyError(f"kel_store missing genesis event for prefix {prefix_qb64!r}")
    genesis_ked = genesis_entry["serder"].ked
    if not genesis_ked.get("k"):
        raise ValueError("Genesis event has no k field")
    initial_keys_qb64: list[str] = genesis_ked["k"]

    # Detect delegation: scan for dip/drt events to find delegating prefix.
    delegating_pre = None
    for sn in range(target_sn + 1):
        entry = kel_store.get((prefix_qb64, sn))
        if entry and entry["serder"].ked.get("t") in ("dip", "drt"):
            delegating_pre = entry["serder"].ked.get("di")
            break

    # For delegated AIDs: find delegation_event_idx per dip/drt event.
    delegation_event_idxes: dict[int, int] = {}
    max_del_sn = 0

    if delegating_pre:
        for sn in range(target_sn + 1):
            entry = kel_store.get((prefix_qb64, sn))
            if not entry:
                continue
            etype = entry["serder"].ked.get("t")
            if etype not in ("dip", "drt"):
                continue

            delegated_said = entry["serder"].said
            # Scan delegating AID's events for the approval seal.
            del_sn = 0
            found_idx = None
            while True:
                del_entry = kel_store.get((delegating_pre, del_sn))
                if del_entry is None:
                    break
                del_ked = del_entry["serder"].ked
                a_field = del_ked.get("a", [])
                for seal in a_field:
                    if (seal.get("i") == prefix_qb64
                            and seal.get("s") == str(sn)
                            and seal.get("d") == delegated_said):
                        found_idx = del_sn
                        break
                if found_idx is not None:
                    break
                del_sn += 1

            if found_idx is None:
                raise ValueError(
                    f"No delegation seal found for {etype} at sn={sn} "
                    f"(delegatee={prefix_qb64!r}, delegating={delegating_pre!r})"
                )
            delegation_event_idxes[sn] = found_idx
            max_del_sn = max(max_del_sn, found_idx)

    # Build the delegating KEL if needed (up to max delegation event index).
    delegating_kel = None
    if delegating_pre and delegation_event_idxes:
        delegating_kel = build_kel_input(kel_store, delegating_pre, max_del_sn)

    # Build the events list.
    events = []
    for sn in range(target_sn + 1):
        entry = kel_store.get((prefix_qb64, sn))
        if entry is None:
            raise KeyError(f"kel_store missing event ({prefix_qb64!r}, sn={sn})")

        serder = entry["serder"]
        sigs_raw = entry["sigs"]  # [(signer_idx: int, bytes(64)), ...]
        ked = serder.ked

        # Preimage: replace all occurrences of SAID qb64 with "#"*44.
        said_qb64: str = serder.said
        preimage_bytes = serder.raw.replace(
            said_qb64.encode("ascii"), b"#" * 44
        )

        # expected_said: raw 32 bytes from the SAID qb64 (Blake3_256 code 'E').
        diger = Diger(qb64=said_qb64)
        expected_said = list(diger.raw)

        # prev_said: raw bytes from the p field (None for sn==0).
        if sn == 0:
            prev_said = None
        else:
            prev_diger = Diger(qb64=ked["p"])
            prev_said = list(prev_diger.raw)

        # event_type: 0=icp, 1=ixn, 2=rot, 3=dip, 4=drt.
        etype = ked["t"]
        if etype == "icp":
            event_type = 0
        elif etype == "ixn":
            event_type = 1
        elif etype == "rot":
            event_type = 2
        elif etype == "dip":
            event_type = 3
        elif etype == "drt":
            event_type = 4
        else:
            raise ValueError(f"Unsupported event type at sn={sn}: {etype!r}")

        # signatures: all provided sigs with their signer indices.
        signatures = [
            {"signer_idx": idx, "sig_r": list(raw[:32]), "sig_s": list(raw[32:])}
            for idx, raw in sigs_raw
        ]
        kt = int(ked.get("kt", 1))

        # new_key_qb64s: full list of new signing keys (rot and drt only).
        new_key_qb64s: list[str] = []
        if etype in ("rot", "drt"):
            k_field = ked.get("k", [])
            if not k_field:
                raise ValueError(f"Rotation at sn={sn} has empty k field")
            new_key_qb64s = k_field

        # next_key_digests: raw blake3 bytes from each entry in the n field.
        n_field = ked.get("n", [])
        next_key_digests = [list(Diger(qb64=d).raw) for d in n_field]
        nt = int(ked.get("nt", 0))

        # delegation_event_idx: index into delegating_kel.events (dip/drt only).
        delegation_event_idx = delegation_event_idxes.get(sn)

        events.append({
            "preimage_bytes": list(preimage_bytes),
            "expected_said": expected_said,
            "prev_said": prev_said,
            "signatures": signatures,
            "kt": kt,
            "event_type": event_type,
            "new_key_qb64s": new_key_qb64s,
            "next_key_digests": next_key_digests,
            "nt": nt,
            "delegation_event_idx": delegation_event_idx,
        })

    return {
        "prefix_qb64": prefix_qb64,
        "initial_keys_qb64": initial_keys_qb64,
        "events": events,
        "delegating_kel": delegating_kel,
    }


def build_tel_input(
    kel_store: dict,
    tel_serder,
    registry_prefix_qb64: str,
    controller_prefix_qb64: str,
    tel_sn: int,
) -> dict:
    """Build a TelInput dict for the sp1-tel-prover from keripy objects.

    Scans the kel_store for a controller event whose ked["a"] contains:
    {"i": registry_prefix_qb64, "s": str(tel_sn), "d": tel_event_said}.

    Args:
        kel_store: dict mapping (prefix_qb64: str, sn: int) → {"serder", "sigs"}.
                   Must contain the controller's events (with anchor seal).
        tel_serder: keripy Serder (or equivalent) for the TEL event.
        registry_prefix_qb64: TEL registry prefix qb64.
        controller_prefix_qb64: Controller AID prefix qb64.
        tel_sn: TEL event sequence number.

    Returns:
        A dict matching the TelInput struct in sp1-tel-guest/src/lib.rs.
    """
    # Build TEL event preimage.
    tel_said_qb64: str = tel_serder.said
    tel_preimage = tel_serder.raw.replace(
        tel_said_qb64.encode("ascii"), b"#" * 44
    )
    tel_diger = Diger(qb64=tel_said_qb64)
    tel_expected_said = list(tel_diger.raw)

    # Scan controller KEL events for the one with matching anchor seal.
    anchor_sn = None
    anchor_serder = None
    scan_sn = 0
    while True:
        entry = kel_store.get((controller_prefix_qb64, scan_sn))
        if entry is None:
            break
        ctrl_ked = entry["serder"].ked
        a_field = ctrl_ked.get("a", [])
        for seal in a_field:
            if (seal.get("i") == registry_prefix_qb64
                    and seal.get("s") == str(tel_sn)
                    and seal.get("d") == tel_said_qb64):
                anchor_sn = scan_sn
                anchor_serder = entry["serder"]
                break
        if anchor_sn is not None:
            break
        scan_sn += 1

    if anchor_sn is None:
        raise ValueError(
            f"No controller KEL anchor event found for TEL "
            f"registry={registry_prefix_qb64!r} sn={tel_sn}"
        )

    # Build anchor event preimage.
    anchor_said_qb64: str = anchor_serder.said
    anchor_preimage = anchor_serder.raw.replace(
        anchor_said_qb64.encode("ascii"), b"#" * 44
    )
    anchor_diger = Diger(qb64=anchor_said_qb64)
    anchor_expected_said = list(anchor_diger.raw)

    return {
        "registry_prefix_qb64": registry_prefix_qb64,
        "controller_prefix_qb64": controller_prefix_qb64,
        "tel_sn": tel_sn,
        "tel_event": {
            "preimage_bytes": list(tel_preimage),
            "expected_said": tel_expected_said,
        },
        "anchor_sn": anchor_sn,
        "anchor_event": {
            "preimage_bytes": list(anchor_preimage),
            "expected_said": anchor_expected_said,
        },
    }
