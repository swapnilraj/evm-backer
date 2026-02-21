//! SP1 guest program: verify an Ed25519 signature and commit to (pubkey, messageHash).
//!
//! Private inputs (via sp1_zkvm::io::read):
//!   - backer_pubkey: [u8; 32]  — Ed25519 verifying key bytes
//!   - message_hash:  [u8; 32]  — the 32-byte keccak256 message hash
//!   - signature:     [u8; 64]  — Ed25519 signature (r || s)
//!
//! Public outputs (committed via sp1_zkvm::io::commit_slice):
//!   64 bytes = backer_pubkey (32) || message_hash (32)
//!   Matches abi.encode(bytes32 backerPubKey, bytes32 messageHash) in Solidity.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_dalek::{Signature, VerifyingKey};

pub fn main() {
    let pubkey_bytes: [u8; 32] = sp1_zkvm::io::read();
    let message: [u8; 32] = sp1_zkvm::io::read();
    // Read signature as two [u8; 32] halves because serde doesn't support [u8; 64].
    let sig_r: [u8; 32] = sp1_zkvm::io::read();
    let sig_s: [u8; 32] = sp1_zkvm::io::read();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig_r);
    sig_bytes[32..].copy_from_slice(&sig_s);

    let vk = VerifyingKey::from_bytes(&pubkey_bytes).expect("invalid pubkey");
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&message, &sig).expect("invalid signature");

    sp1_zkvm::io::commit_slice(&pubkey_bytes);
    sp1_zkvm::io::commit_slice(&message);
}
