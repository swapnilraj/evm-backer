//! SP1 prover CLI: generate a ZK proof that an Ed25519 signature is valid.
//!
//! Usage: sp1-prover <pubkey_hex> <msg_hex> <sig_hex>
//!
//! Outputs JSON to stdout:
//!   {
//!     "proof": "<hex>",
//!     "publicValues": "<hex>",
//!     "vkey": "<hex>"
//!   }
//!
//! Environment variables:
//!   SP1_PROVER=local   — real local STARK proving (default, 1-5 min)
//!   SP1_PROVER=mock    — mock proving (instant, for getting vkey quickly)
//!   SP1_PROVER=network — Succinct's remote proving network

use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};

/// The ELF binary of the sp1-guest program, embedded at compile time.
const GUEST_ELF: Elf = include_elf!("sp1-guest");

fn main() {
    sp1_sdk::utils::setup_logger();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: sp1-prover <pubkey_hex> <msg_hex> <sig_hex>");
        std::process::exit(1);
    }

    let pubkey_bytes: [u8; 32] = hex::decode(&args[1])
        .expect("invalid pubkey hex")
        .try_into()
        .expect("pubkey must be 32 bytes");
    let msg_bytes: [u8; 32] = hex::decode(&args[2])
        .expect("invalid msg hex")
        .try_into()
        .expect("msg must be 32 bytes");
    let sig_bytes: [u8; 64] = hex::decode(&args[3])
        .expect("invalid sig hex")
        .try_into()
        .expect("sig must be 64 bytes");

    // Write signature as two [u8; 32] halves to match guest's read pattern
    // (serde doesn't support [u8; 64] deserialization).
    let sig_r: [u8; 32] = sig_bytes[..32].try_into().unwrap();
    let sig_s: [u8; 32] = sig_bytes[32..].try_into().unwrap();

    let mut stdin = SP1Stdin::new();
    stdin.write(&pubkey_bytes);
    stdin.write(&msg_bytes);
    stdin.write(&sig_r);
    stdin.write(&sig_s);

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
