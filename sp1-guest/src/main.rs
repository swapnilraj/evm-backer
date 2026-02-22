//! SP1 guest program: verify a full KERI Key Event Log (KEL) and commit to
//! the 32-byte messageHash of the final event.
//!
//! Private input: KelInput (bincode-serialized, written by sp1-prover via stdin.write)
//! Public output: 32 bytes = keccak256(abi.encode(prefix_b32, sn, said_b32))
//!
//! The verification logic lives in lib.rs (run_kel_verification) so it can be
//! unit-tested natively.  Only the zkVM I/O lives here.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_guest::{run_kel_verification, KelInput};

pub fn main() {
    let input: KelInput = sp1_zkvm::io::read();
    let message_hash = run_kel_verification(&input);
    sp1_zkvm::io::commit_slice(&message_hash);
}
