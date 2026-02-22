//! SP1 TEL prover CLI: generate a ZK proof that a KERI TEL event is valid.
//!
//! Usage: sp1-tel-prover <tel_input_hex>
//!
//!   <tel_input_hex>  hex-encoded JSON of a TelInput struct.
//!                    Build this with evm_backer.proofs.build_tel_input() in Python.
//!
//! Outputs JSON to stdout:
//!   {
//!     "proof": "<hex>",
//!     "publicValues": "<hex>",
//!     "vkey": "<hex>"
//!   }

use sp1_tel_guest::TelInput;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};

const GUEST_ELF: Elf = include_elf!("sp1-tel-guest-bin");

fn main() {
    sp1_sdk::utils::setup_logger();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: sp1-tel-prover <tel_input_hex>");
        eprintln!("  <tel_input_hex>  hex-encoded JSON of a TelInput struct");
        std::process::exit(1);
    }

    let json_bytes = hex::decode(&args[1]).expect("invalid hex argument");
    let tel_input: TelInput = serde_json::from_slice(&json_bytes).expect("invalid JSON TelInput");

    let mut stdin = SP1Stdin::new();
    stdin.write(&tel_input);

    let client = ProverClient::from_env();
    let pk = client.setup(GUEST_ELF).expect("failed to setup ELF");
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("proving failed");

    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.as_slice();
    let vkey_bytes = pk.verifying_key().bytes32();

    println!(
        "{}",
        serde_json::json!({
            "proof": hex::encode(proof_bytes),
            "publicValues": hex::encode(public_values),
            "vkey": vkey_bytes,
        })
    );
}
