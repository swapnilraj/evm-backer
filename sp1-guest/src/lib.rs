//! KERI KEL (Key Event Log) verification logic for the SP1 zkVM guest.
//!
//! This library crate is separated from main.rs so that the verification
//! algorithm can be unit-tested natively on the host (without the zkVM).
//!
//! The [[bin]] target (main.rs) reads inputs via sp1_zkvm::io and calls
//! run_kel_verification from this library.

pub use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

// ---------------------------------------------------------------------------
// Input types (must match sp1-prover/src/main.rs)
// ---------------------------------------------------------------------------

/// One Ed25519 signature in a multi-sig event.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct KeriSig {
    /// Index into current_keys[] that produced this signature.
    pub signer_idx: u8,
    /// First 32 bytes of the Ed25519 signature.
    pub sig_r: [u8; 32],
    /// Last 32 bytes of the Ed25519 signature.
    pub sig_s: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct KeriEvent {
    /// Event JSON with the d (and optionally i for self-addressing icp) field set to "#"*44.
    pub preimage_bytes: Vec<u8>,
    /// Raw 32-byte blake3 output (the SAID, decoded from the d-field qb64).
    pub expected_said: [u8; 32],
    /// Raw blake3 from the p field; None for the genesis event (sn=0).
    pub prev_said: Option<[u8; 32]>,
    /// All provided signatures; verified_count must reach kt.
    pub signatures: Vec<KeriSig>,
    /// Key signing threshold (M in M-of-N); verified_count must be >= kt.
    pub kt: u8,
    /// 0 = icp, 1 = ixn, 2 = rot, 3 = dip, 4 = drt
    pub event_type: u8,
    /// rot/drt only: full 44-char KERI qb64 of each new signing key.
    /// blake3(qb64_bytes) must appear in the previous event's next_key_digests.
    pub new_key_qb64s: Vec<String>,
    /// icp + rot + dip + drt: raw 32-byte blake3 of each next key's qb64 bytes (n field).
    pub next_key_digests: Vec<[u8; 32]>,
    /// Next key threshold (M for the following rotation).
    pub nt: u8,
    /// dip/drt only: index into delegating_kel.events that contains the approval seal.
    pub delegation_event_idx: Option<usize>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct KelInput {
    /// Controller's KERI prefix qb64 (e.g. "EAKCxMOu..." self-addressing, or "BFs8..." basic).
    pub prefix_qb64: String,
    /// Full 44-char KERI qb64 of all signing keys for sn=0 (from the icp/dip k field).
    pub initial_keys_qb64: Vec<String>,
    /// Events sn=0..N inclusive.
    pub events: Vec<KeriEvent>,
    /// dip/drt only: the delegating AID's KEL (None for non-delegated).
    pub delegating_kel: Option<Box<KelInput>>,
}

// ---------------------------------------------------------------------------
// Core helpers
// ---------------------------------------------------------------------------

/// Compute keccak256 of the given bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Compute blake3 of the given bytes, returning raw 32 bytes.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Decode a 44-char KERI qb64 key string (any 1-char code: 'B', 'D', …) to raw 32 bytes.
///
/// KERI qb64 for a 32-byte matter with a 1-char code:
///   - Prepend 1 zero lead byte to the raw value → 33 bytes
///   - base64url-no-pad encode → 44 chars
///   - Replace the first char ('A' from lead byte) with the code char
///
/// Decoding: replace the code char with 'A', decode → 33 bytes, skip lead byte.
pub fn decode_qb64_key(qb64: &str) -> [u8; 32] {
    assert_eq!(qb64.len(), 44, "KERI key qb64 must be 44 chars, got {}", qb64.len());
    let mut b64 = String::with_capacity(44);
    b64.push('A'); // reinstate the 'A' that the lead byte encodes to
    b64.push_str(&qb64[1..]);
    let decoded = URL_SAFE_NO_PAD
        .decode(&b64)
        .expect("KERI key qb64: invalid base64");
    assert_eq!(decoded.len(), 33, "decoded qb64 key must be 33 bytes");
    decoded[1..33].try_into().unwrap()
}

/// Encode raw 32-byte blake3 digest to a 44-char KERI qb64 string (code 'E').
pub fn digest_to_qb64(raw: &[u8; 32]) -> String {
    let mut padded = [0u8; 33];
    padded[1..].copy_from_slice(raw);
    let b64 = URL_SAFE_NO_PAD.encode(padded); // 44 chars, starts with 'A'
    let mut result = String::with_capacity(44);
    result.push('E');        // KERI Blake3_256 code
    result.push_str(&b64[1..]); // skip the 'A' lead-byte char
    result
}

/// Replace every contiguous run of 44 '#' bytes in `src` with `replacement`.
pub fn replace_placeholder(src: &[u8], replacement: &[u8]) -> Vec<u8> {
    const PLACEHOLDER: [u8; 44] = [b'#'; 44];
    let mut out = Vec::with_capacity(src.len());
    let mut pos = 0;
    while pos + 44 <= src.len() {
        if src[pos..pos + 44] == PLACEHOLDER {
            out.extend_from_slice(replacement);
            pos += 44;
        } else {
            out.push(src[pos]);
            pos += 1;
        }
    }
    out.extend_from_slice(&src[pos..]);
    out
}

// ---------------------------------------------------------------------------
// Delegation helpers
// ---------------------------------------------------------------------------

/// Verify that the delegating KEL contains an approval seal for the delegated event.
///
/// Searches `delegating_event.preimage_bytes` (after SAID substitution) for a JSON `a`
/// field containing `{"i": delegatee_prefix_qb64, "s": delegated_sn, "d": delegated_said_qb64}`.
fn verify_delegation_seal(
    delegating_kel: &KelInput,
    delegation_event_idx: usize,
    delegatee_prefix_qb64: &str,
    delegated_sn: u64,
    delegated_said_qb64: &str,
) {
    let delegating_event = &delegating_kel.events[delegation_event_idx];
    let said_qb64 = digest_to_qb64(&delegating_event.expected_said);
    let signing_bytes = replace_placeholder(&delegating_event.preimage_bytes, said_qb64.as_bytes());

    let event_json: serde_json::Value =
        serde_json::from_slice(&signing_bytes).expect("delegation event: invalid JSON");

    let a_field = event_json
        .get("a")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("delegation event: missing or non-array 'a' field"));

    let found = a_field.iter().any(|entry| {
        entry.get("i").and_then(|v| v.as_str()) == Some(delegatee_prefix_qb64)
            && entry.get("s").and_then(|v| v.as_str()) == Some(&delegated_sn.to_string())
            && entry.get("d").and_then(|v| v.as_str()) == Some(delegated_said_qb64)
    });

    assert!(
        found,
        "Delegation seal not found: expected {{\"i\":{delegatee_prefix_qb64:?}, \"s\":{delegated_sn}, \"d\":{delegated_said_qb64:?}}} in delegating event a field"
    );
}

// ---------------------------------------------------------------------------
// Main algorithm
// ---------------------------------------------------------------------------

/// Verify a KERI Key Event Log and return the 32-byte message hash to commit.
///
/// Verifies for each event:
///   (a) SAID: blake3(preimage_bytes) == expected_said
///   (b) Signing bytes: replace "#"*44 in preimage with SAID qb64
///   (c) Chain: prev_said == events[i-1].expected_said
///   (d) Multi-sig: verify each sig against current_keys[signer_idx], count >= kt
///   (e) Key state: for rot/drt, pre-rotation commitment; update current_keys
///
/// Returns keccak256(abi.encode(prefix_b32, sn, said_b32)) for the final event.
pub fn run_kel_verification(input: &KelInput) -> [u8; 32] {
    assert!(!input.events.is_empty(), "KEL must have at least one event");
    assert!(!input.initial_keys_qb64.is_empty(), "KEL must have at least one initial key");

    let mut current_keys: Vec<[u8; 32]> = input.initial_keys_qb64
        .iter().map(|q| decode_qb64_key(q)).collect();
    let mut pending_n_digests: Vec<[u8; 32]> = Vec::new();
    let mut pending_nt: u8 = 0;
    let mut prev_said: Option<[u8; 32]> = None;

    for (i, event) in input.events.iter().enumerate() {
        // (a) SAID verification.
        let computed_said = blake3_hash(&event.preimage_bytes);
        assert_eq!(
            computed_said, event.expected_said,
            "Event {i}: SAID mismatch — blake3(preimage) != expected_said"
        );

        // (b) Reconstruct signing bytes.
        let said_qb64 = digest_to_qb64(&event.expected_said);
        let signing_bytes = replace_placeholder(&event.preimage_bytes, said_qb64.as_bytes());

        // (c) Chain verification.
        if i == 0 {
            assert!(event.prev_said.is_none(), "Event 0: prev_said must be None");
        } else {
            let expected_prev = prev_said.expect("previous SAID must be set");
            let actual_prev = event.prev_said.expect("Event i > 0 must have prev_said");
            assert_eq!(
                actual_prev, expected_prev,
                "Event {i}: chain broken — prev_said != events[{}].expected_said", i - 1
            );
        }

        // (d) Multi-sig verification: verify each sig, count must reach kt.
        let mut verified_count: u8 = 0;
        for ksig in &event.signatures {
            let key_raw = &current_keys[ksig.signer_idx as usize];
            let vk = VerifyingKey::from_bytes(key_raw)
                .unwrap_or_else(|e| panic!("Event {i}: invalid pubkey at idx {}: {e}", ksig.signer_idx));
            let mut sig_bytes = [0u8; 64];
            sig_bytes[..32].copy_from_slice(&ksig.sig_r);
            sig_bytes[32..].copy_from_slice(&ksig.sig_s);
            let sig = Signature::from_bytes(&sig_bytes);
            vk.verify_strict(&signing_bytes, &sig)
                .unwrap_or_else(|e| panic!("Event {i}: sig[{}] failed: {e}", ksig.signer_idx));
            verified_count += 1;
        }
        assert!(
            verified_count >= event.kt,
            "Event {i}: threshold not met: got {verified_count}, need {}", event.kt
        );

        // (e) Key state transition.
        match event.event_type {
            0 => {
                // icp: record pre-rotation commitment.
                pending_n_digests = event.next_key_digests.clone();
                pending_nt = event.nt;
            }
            1 => {
                // ixn: no key change.
            }
            2 => {
                // rot: verify pre-rotation commitments, then rotate.
                assert!(!event.new_key_qb64s.is_empty(), "Event {i}: rot requires new_key_qb64s");
                assert!(
                    event.new_key_qb64s.len() >= pending_nt as usize,
                    "Event {i}: not enough new keys for threshold {pending_nt}"
                );
                for new_key_qb64 in &event.new_key_qb64s {
                    assert_eq!(new_key_qb64.len(), 44, "new_key_qb64 must be 44 chars");
                    let digest = blake3_hash(new_key_qb64.as_bytes());
                    assert!(
                        pending_n_digests.contains(&digest),
                        "Event {i}: rotation key not in pre-rotation commitment"
                    );
                }
                current_keys = event.new_key_qb64s.iter().map(|q| decode_qb64_key(q)).collect();
                pending_n_digests = event.next_key_digests.clone();
                pending_nt = event.nt;
            }
            3 => {
                // dip: delegated inception — like icp but verifies delegation seal.
                let delegating_kel = input.delegating_kel.as_deref()
                    .unwrap_or_else(|| panic!("Event {i}: dip requires delegating_kel"));

                // Verify the delegating AID is correct.
                let event_json: serde_json::Value =
                    serde_json::from_slice(&signing_bytes).expect("dip event: invalid JSON");
                let di = event_json.get("di").and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("Event {i}: dip missing 'di' field"));
                assert_eq!(
                    di, delegating_kel.prefix_qb64,
                    "Event {i}: dip di field mismatch"
                );

                // Verify the delegating KEL itself.
                run_kel_verification(delegating_kel);

                // Verify the delegation approval seal.
                let delegation_event_idx = event.delegation_event_idx
                    .unwrap_or_else(|| panic!("Event {i}: dip requires delegation_event_idx"));
                let delegated_said_qb64 = digest_to_qb64(&event.expected_said);
                verify_delegation_seal(
                    delegating_kel,
                    delegation_event_idx,
                    &input.prefix_qb64,
                    i as u64,
                    &delegated_said_qb64,
                );

                // Record pre-rotation commitment (same as icp).
                pending_n_digests = event.next_key_digests.clone();
                pending_nt = event.nt;
            }
            4 => {
                // drt: delegated rotation — like rot but verifies delegation seal.
                // Note: unlike dip, drt events do NOT include a 'di' field per the KERI spec.
                // The delegation relationship was established by the dip event; subsequent drt
                // events are tied to the delegating AID only through the approval seal.
                let delegating_kel = input.delegating_kel.as_deref()
                    .unwrap_or_else(|| panic!("Event {i}: drt requires delegating_kel"));

                // Verify the delegating KEL itself.
                run_kel_verification(delegating_kel);

                // Verify the delegation approval seal.
                let delegation_event_idx = event.delegation_event_idx
                    .unwrap_or_else(|| panic!("Event {i}: drt requires delegation_event_idx"));
                let delegated_said_qb64 = digest_to_qb64(&event.expected_said);
                verify_delegation_seal(
                    delegating_kel,
                    delegation_event_idx,
                    &input.prefix_qb64,
                    i as u64,
                    &delegated_said_qb64,
                );

                // Rotate key (same as rot).
                assert!(!event.new_key_qb64s.is_empty(), "Event {i}: drt requires new_key_qb64s");
                assert!(
                    event.new_key_qb64s.len() >= pending_nt as usize,
                    "Event {i}: not enough new keys for threshold {pending_nt}"
                );
                for new_key_qb64 in &event.new_key_qb64s {
                    assert_eq!(new_key_qb64.len(), 44, "new_key_qb64 must be 44 chars");
                    let digest = blake3_hash(new_key_qb64.as_bytes());
                    assert!(
                        pending_n_digests.contains(&digest),
                        "Event {i}: rotation key not in pre-rotation commitment (drt)"
                    );
                }
                current_keys = event.new_key_qb64s.iter().map(|q| decode_qb64_key(q)).collect();
                pending_n_digests = event.next_key_digests.clone();
                pending_nt = event.nt;
            }
            t => panic!("Event {i}: unknown event_type {t}"),
        }

        prev_said = Some(event.expected_said);
    }

    // Compute and return message_hash = keccak256(abi.encode(prefix_b32, sn, said_b32)).
    let final_said = input.events.last().unwrap().expected_said;
    let sn = (input.events.len() as u64) - 1;

    let prefix_b32 = keccak256(input.prefix_qb64.as_bytes());
    let final_said_qb64 = digest_to_qb64(&final_said);
    let said_b32 = keccak256(final_said_qb64.as_bytes());

    // abi.encode(bytes32 prefix, uint64 sn, bytes32 said) = 96 bytes:
    //   prefix_b32 (0-31) | zeros (32-55) | sn.to_be_bytes() (56-63) | said_b32 (64-95)
    let mut abi_encoded = [0u8; 96];
    abi_encoded[..32].copy_from_slice(&prefix_b32);
    abi_encoded[56..64].copy_from_slice(&sn.to_be_bytes());
    abi_encoded[64..].copy_from_slice(&said_b32);

    keccak256(&abi_encoded)
}

// ---------------------------------------------------------------------------
// Unit tests — run natively with `cargo test -p sp1-guest`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // -----------------------------------------------------------------------
    // Helper function test vectors
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_qb64_key_roundtrip_b_code() {
        let raw: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        let mut padded = [0u8; 33];
        padded[1..].copy_from_slice(&raw);
        let b64 = URL_SAFE_NO_PAD.encode(padded);
        let mut qb64 = String::with_capacity(44);
        qb64.push('B');
        qb64.push_str(&b64[1..]);
        assert_eq!(qb64.len(), 44);
        assert_eq!(decode_qb64_key(&qb64), raw);
    }

    #[test]
    fn test_decode_qb64_key_d_code() {
        let raw = [0xaau8; 32];
        let mut padded = [0u8; 33];
        padded[1..].copy_from_slice(&raw);
        let b64 = URL_SAFE_NO_PAD.encode(padded);
        let mut qb64 = String::with_capacity(44);
        qb64.push('D');
        qb64.push_str(&b64[1..]);
        assert_eq!(decode_qb64_key(&qb64), raw);
    }

    #[test]
    fn test_digest_to_qb64_starts_with_e_and_44_chars() {
        let raw = [0u8; 32];
        let qb64 = digest_to_qb64(&raw);
        assert_eq!(qb64.len(), 44);
        assert!(qb64.starts_with('E'));
    }

    #[test]
    fn test_digest_to_qb64_roundtrip() {
        let raw: [u8; 32] = [0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7,
                              8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                              20, 21, 22, 23, 24, 25, 26, 27];
        let qb64 = digest_to_qb64(&raw);
        // Decode: replace 'E' with 'A', decode 44 chars → 33 bytes, skip lead byte.
        let mut b64 = String::with_capacity(44);
        b64.push('A');
        b64.push_str(&qb64[1..]);
        let decoded = URL_SAFE_NO_PAD.decode(&b64).unwrap();
        assert_eq!(decoded.len(), 33);
        assert_eq!(decoded[0], 0x00);
        let recovered: [u8; 32] = decoded[1..33].try_into().unwrap();
        assert_eq!(recovered, raw);
    }

    #[test]
    fn test_replace_placeholder_single() {
        let mut src = b"prefix:".to_vec();
        src.extend_from_slice(&[b'#'; 44]);
        src.extend_from_slice(b":suffix");
        let replacement: Vec<u8> = (0u8..44u8).collect();
        let result = replace_placeholder(&src, &replacement);
        assert_eq!(&result[..7], b"prefix:");
        assert_eq!(&result[7..51], replacement.as_slice());
        assert_eq!(&result[51..], b":suffix");
    }

    #[test]
    fn test_replace_placeholder_double() {
        let placeholder = [b'#'; 44];
        let replacement: Vec<u8> = (0u8..44u8).collect();
        let mut src = placeholder.to_vec();
        src.extend_from_slice(b"|");
        src.extend_from_slice(&placeholder);
        let result = replace_placeholder(&src, &replacement);
        assert_eq!(&result[..44], replacement.as_slice());
        assert_eq!(&result[44..45], b"|");
        assert_eq!(&result[45..], replacement.as_slice());
    }

    #[test]
    fn test_keccak256_empty() {
        let h = keccak256(b"");
        let expected = hex_to_32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(h, expected);
    }

    #[test]
    fn test_blake3_empty() {
        let h = blake3_hash(b"");
        let expected = hex_to_32("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        assert_eq!(h, expected);
    }

    // -----------------------------------------------------------------------
    // Full algorithm tests
    // -----------------------------------------------------------------------

    fn make_key_qb64(raw: &[u8; 32], code: char) -> String {
        let mut padded = [0u8; 33];
        padded[1..].copy_from_slice(raw);
        let b64 = URL_SAFE_NO_PAD.encode(padded);
        let mut q = String::with_capacity(44);
        q.push(code);
        q.push_str(&b64[1..]);
        q
    }

    fn make_signing_key(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(seed)
    }

    /// Build a KeriEvent signed by `signers` (one KeriSig per signer, in order).
    fn build_event_and_sign(
        preimage: Vec<u8>,
        signers: &[&ed25519_dalek::SigningKey],
        kt: u8,
        prev_said_raw: Option<[u8; 32]>,
        event_type: u8,
        new_key_qb64s: Vec<String>,
        next_key_digests: Vec<[u8; 32]>,
        nt: u8,
    ) -> KeriEvent {
        use ed25519_dalek::Signer;
        let expected_said = blake3_hash(&preimage);
        let said_qb64 = digest_to_qb64(&expected_said);
        let signing_bytes = replace_placeholder(&preimage, said_qb64.as_bytes());
        let signatures = signers.iter().enumerate().map(|(idx, sk)| {
            let sig = sk.sign(&signing_bytes).to_bytes();
            KeriSig {
                signer_idx: idx as u8,
                sig_r: sig[..32].try_into().unwrap(),
                sig_s: sig[32..].try_into().unwrap(),
            }
        }).collect();
        KeriEvent {
            preimage_bytes: preimage,
            expected_said,
            prev_said: prev_said_raw,
            signatures,
            kt,
            event_type,
            new_key_qb64s,
            next_key_digests,
            nt,
            delegation_event_idx: None,
        }
    }

    #[test]
    fn test_full_icp_only_synthetic() {
        let seed0: [u8; 32] = [0x9f, 0x7b, 0xa8, 0xa7, 0xa8, 0x43, 0x39, 0x96,
                               0x26, 0xfa, 0xb1, 0x99, 0xeb, 0xaa, 0x20, 0xc4,
                               0x1b, 0x47, 0x11, 0xc4, 0xae, 0x53, 0x41, 0x52,
                               0xc9, 0xbd, 0x04, 0x9d, 0x85, 0x29, 0x7e, 0x93];
        let sk0 = make_signing_key(&seed0);
        let raw0 = sk0.verifying_key().to_bytes();
        let qb64_0 = make_key_qb64(&raw0, 'D');

        let icp_preimage = format!("{{\"t\":\"icp\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();

        let icp_event = build_event_and_sign(icp_preimage, &[&sk0], 1, None, 0, vec![], vec![], 0);

        let kel_input = KelInput {
            prefix_qb64: qb64_0.clone(),
            initial_keys_qb64: vec![qb64_0],
            events: vec![icp_event],
            delegating_kel: None,
        };

        let msg_hash = run_kel_verification(&kel_input);
        // Verify it's non-zero and deterministic.
        assert_ne!(msg_hash, [0u8; 32]);
        // Run again — must produce same result.
        assert_eq!(run_kel_verification(&kel_input), msg_hash);
    }

    #[test]
    fn test_full_icp_ixn_rot_synthetic() {
        let seed0: [u8; 32] = [0x9f, 0x7b, 0xa8, 0xa7, 0xa8, 0x43, 0x39, 0x96,
                               0x26, 0xfa, 0xb1, 0x99, 0xeb, 0xaa, 0x20, 0xc4,
                               0x1b, 0x47, 0x11, 0xc4, 0xae, 0x53, 0x41, 0x52,
                               0xc9, 0xbd, 0x04, 0x9d, 0x85, 0x29, 0x7e, 0x93];
        let seed1: [u8; 32] = [0x83, 0x42, 0x7e, 0x04, 0x94, 0xe3, 0xce, 0x55,
                               0x51, 0x79, 0x11, 0x66, 0x0c, 0x93, 0x5d, 0x1e,
                               0xbf, 0xac, 0x51, 0xb5, 0xd6, 0x59, 0x5e, 0xa2,
                               0x45, 0xfa, 0x01, 0x35, 0x98, 0x59, 0xdd, 0xe8];

        let sk0 = make_signing_key(&seed0);
        let sk1 = make_signing_key(&seed1);
        let raw0 = sk0.verifying_key().to_bytes();
        let raw1 = sk1.verifying_key().to_bytes();
        let qb64_0 = make_key_qb64(&raw0, 'D');
        let qb64_1 = make_key_qb64(&raw1, 'D');

        // Pre-rotation commitment: blake3(key1_qb64_bytes)
        let n_field_raw = blake3_hash(qb64_1.as_bytes());

        // icp: committed to rotating to key1
        let icp_preimage = format!("{{\"t\":\"icp\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        let icp_event = build_event_and_sign(
            icp_preimage, &[&sk0], 1, None, 0, vec![], vec![n_field_raw], 1
        );
        let icp_said = icp_event.expected_said;

        // ixn: no key change; references icp SAID
        let ixn_preimage = format!("{{\"t\":\"ixn\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        let ixn_event = build_event_and_sign(
            ixn_preimage, &[&sk0], 1, Some(icp_said), 1, vec![], vec![], 0
        );
        let ixn_said = ixn_event.expected_said;

        // rot: rotate to key1 (signed with OLD key0)
        let rot_preimage = format!("{{\"t\":\"rot\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        let rot_event = build_event_and_sign(
            rot_preimage, &[&sk0], 1, Some(ixn_said), 2, vec![qb64_1], vec![], 0
        );

        let kel_input = KelInput {
            prefix_qb64: "ETestPrefix0000000000000000000000000000000000".to_string(),
            initial_keys_qb64: vec![qb64_0],
            events: vec![icp_event, ixn_event, rot_event],
            delegating_kel: None,
        };

        let msg_hash = run_kel_verification(&kel_input);
        assert_ne!(msg_hash, [0u8; 32]);
    }

    #[test]
    #[should_panic(expected = "SAID mismatch")]
    fn test_tampered_preimage_fails_said_check() {
        let seed0: [u8; 32] = [1u8; 32];
        let sk0 = make_signing_key(&seed0);
        let raw0 = sk0.verifying_key().to_bytes();
        let qb64_0 = make_key_qb64(&raw0, 'D');

        let icp_preimage = format!("{{\"t\":\"icp\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        let mut event = build_event_and_sign(icp_preimage.clone(), &[&sk0], 1, None, 0, vec![], vec![], 0);

        // Tamper with the preimage — SAID check must fail.
        event.preimage_bytes[0] ^= 0xff;

        let kel_input = KelInput {
            prefix_qb64: qb64_0.clone(),
            initial_keys_qb64: vec![qb64_0],
            events: vec![event],
            delegating_kel: None,
        };
        run_kel_verification(&kel_input);
    }

    #[test]
    #[should_panic(expected = "sig[0] failed")]
    fn test_wrong_signature_fails() {
        let seed0: [u8; 32] = [1u8; 32];
        let seed1: [u8; 32] = [2u8; 32];
        let sk0 = make_signing_key(&seed0);
        let sk1 = make_signing_key(&seed1); // wrong key
        let raw0 = sk0.verifying_key().to_bytes();
        let qb64_0 = make_key_qb64(&raw0, 'D');

        let icp_preimage = format!("{{\"t\":\"icp\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        // Sign with WRONG key (sk1) but claim signer_idx=0 (key0).
        let event = build_event_and_sign(icp_preimage, &[&sk1], 1, None, 0, vec![], vec![], 0);

        let kel_input = KelInput {
            prefix_qb64: qb64_0.clone(),
            initial_keys_qb64: vec![qb64_0],
            events: vec![event],
            delegating_kel: None,
        };
        run_kel_verification(&kel_input);
    }

    #[test]
    #[should_panic(expected = "rotation key not in pre-rotation commitment")]
    fn test_wrong_pre_rotation_key_fails() {
        let seed0: [u8; 32] = [1u8; 32];
        let seed1: [u8; 32] = [2u8; 32];
        let seed_wrong: [u8; 32] = [3u8; 32];

        let sk0 = make_signing_key(&seed0);
        let sk1 = make_signing_key(&seed1);
        let sk_wrong = make_signing_key(&seed_wrong);

        let raw0 = sk0.verifying_key().to_bytes();
        let raw1 = sk1.verifying_key().to_bytes();
        let raw_wrong = sk_wrong.verifying_key().to_bytes();
        let qb64_0 = make_key_qb64(&raw0, 'D');
        let qb64_1 = make_key_qb64(&raw1, 'D');
        let qb64_wrong = make_key_qb64(&raw_wrong, 'D');

        // icp commits to key1 as next key.
        let n_field_raw = blake3_hash(qb64_1.as_bytes());
        let icp_preimage = format!("{{\"t\":\"icp\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        let icp_event = build_event_and_sign(icp_preimage, &[&sk0], 1, None, 0, vec![], vec![n_field_raw], 1);
        let icp_said = icp_event.expected_said;

        // rot presents a WRONG new key — commitment check must fail.
        let rot_preimage = format!("{{\"t\":\"rot\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        let rot_event = build_event_and_sign(
            rot_preimage, &[&sk0], 1, Some(icp_said), 2, vec![qb64_wrong], vec![], 0
        );

        let kel_input = KelInput {
            prefix_qb64: qb64_0.clone(),
            initial_keys_qb64: vec![qb64_0],
            events: vec![icp_event, rot_event],
            delegating_kel: None,
        };
        run_kel_verification(&kel_input);
    }

    // -----------------------------------------------------------------------
    // Multi-sig tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_multisig_2of3_icp() {
        // 3 keys, kt=2, signed by key0 and key1 → passes.
        let sk0 = make_signing_key(&[0x01u8; 32]);
        let sk1 = make_signing_key(&[0x02u8; 32]);
        let sk2 = make_signing_key(&[0x03u8; 32]);
        let qb64_0 = make_key_qb64(&sk0.verifying_key().to_bytes(), 'D');
        let qb64_1 = make_key_qb64(&sk1.verifying_key().to_bytes(), 'D');
        let qb64_2 = make_key_qb64(&sk2.verifying_key().to_bytes(), 'D');

        let icp_preimage = format!("{{\"t\":\"icp\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        // Sign with key0 and key1 (2-of-3).
        let icp_event = build_event_and_sign(
            icp_preimage, &[&sk0, &sk1], 2, None, 0, vec![], vec![], 0
        );

        let kel_input = KelInput {
            prefix_qb64: "EMultiSigPrefix000000000000000000000000000000".to_string(),
            initial_keys_qb64: vec![qb64_0, qb64_1, qb64_2],
            events: vec![icp_event],
            delegating_kel: None,
        };

        let msg_hash = run_kel_verification(&kel_input);
        assert_ne!(msg_hash, [0u8; 32]);
        // Deterministic.
        assert_eq!(run_kel_verification(&kel_input), msg_hash);
    }

    #[test]
    #[should_panic(expected = "threshold not met")]
    fn test_multisig_threshold_not_met() {
        // 3 keys, kt=2, only 1 sig → threshold not met.
        let sk0 = make_signing_key(&[0x01u8; 32]);
        let sk1 = make_signing_key(&[0x02u8; 32]);
        let sk2 = make_signing_key(&[0x03u8; 32]);
        let qb64_0 = make_key_qb64(&sk0.verifying_key().to_bytes(), 'D');
        let qb64_1 = make_key_qb64(&sk1.verifying_key().to_bytes(), 'D');
        let qb64_2 = make_key_qb64(&sk2.verifying_key().to_bytes(), 'D');

        let icp_preimage = format!("{{\"t\":\"icp\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        // Sign with only key0 (1-of-3), but kt=2.
        let icp_event = build_event_and_sign(
            icp_preimage, &[&sk0], 2, None, 0, vec![], vec![], 0
        );

        let kel_input = KelInput {
            prefix_qb64: "EMultiSigPrefix000000000000000000000000000000".to_string(),
            initial_keys_qb64: vec![qb64_0, qb64_1, qb64_2],
            events: vec![icp_event],
            delegating_kel: None,
        };
        run_kel_verification(&kel_input);
    }

    #[test]
    fn test_multisig_rotation() {
        // icp: 3 keys (k0,k1,k2), kt=2, pre-commits to next 3 keys (k3,k4,k5), nt=2.
        // rot: new keys = [k3,k4,k5], kt=2, signed by current k0 and k1.
        let sk0 = make_signing_key(&[0x01u8; 32]);
        let sk1 = make_signing_key(&[0x02u8; 32]);
        let sk2 = make_signing_key(&[0x03u8; 32]);
        let sk3 = make_signing_key(&[0x04u8; 32]);
        let sk4 = make_signing_key(&[0x05u8; 32]);
        let sk5 = make_signing_key(&[0x06u8; 32]);

        let qb64_0 = make_key_qb64(&sk0.verifying_key().to_bytes(), 'D');
        let qb64_1 = make_key_qb64(&sk1.verifying_key().to_bytes(), 'D');
        let qb64_2 = make_key_qb64(&sk2.verifying_key().to_bytes(), 'D');
        let qb64_3 = make_key_qb64(&sk3.verifying_key().to_bytes(), 'D');
        let qb64_4 = make_key_qb64(&sk4.verifying_key().to_bytes(), 'D');
        let qb64_5 = make_key_qb64(&sk5.verifying_key().to_bytes(), 'D');

        // Pre-rotation commitments for the next 3 keys.
        let n3 = blake3_hash(qb64_3.as_bytes());
        let n4 = blake3_hash(qb64_4.as_bytes());
        let n5 = blake3_hash(qb64_5.as_bytes());

        // icp: signed by k0 + k1 (2-of-3), commits to next keys [k3,k4,k5] with nt=2.
        let icp_preimage = format!("{{\"t\":\"icp\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        let icp_event = build_event_and_sign(
            icp_preimage, &[&sk0, &sk1], 2, None, 0,
            vec![],
            vec![n3, n4, n5],
            2,
        );
        let icp_said = icp_event.expected_said;

        // rot: signed by current k0 + k1, rotates to [k3,k4,k5].
        let rot_preimage = format!("{{\"t\":\"rot\",\"d\":\"{}\"}}", "#".repeat(44)).into_bytes();
        let rot_event = build_event_and_sign(
            rot_preimage, &[&sk0, &sk1], 2, Some(icp_said), 2,
            vec![qb64_3.clone(), qb64_4.clone(), qb64_5.clone()],
            vec![],
            0,
        );

        let kel_input = KelInput {
            prefix_qb64: "EMultiSigRotPrefix00000000000000000000000000".to_string(),
            initial_keys_qb64: vec![qb64_0, qb64_1, qb64_2],
            events: vec![icp_event, rot_event],
            delegating_kel: None,
        };

        let msg_hash = run_kel_verification(&kel_input);
        assert_ne!(msg_hash, [0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // Hex helper.
    // -----------------------------------------------------------------------
    fn hex_to_32(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    // -----------------------------------------------------------------------
    // Delegation tests (dip/drt)
    // -----------------------------------------------------------------------

    /// Build a minimal delegating KEL (icp only) and a delegatee dip event.
    /// The delegating icp has an `a` field with the approval seal.
    fn make_delegating_kel_and_dip(
        delegating_seed: &[u8; 32],
        delegatee_seed: &[u8; 32],
    ) -> (KelInput, KelInput) {
        // Delegating: simple icp with no pre-rotation.
        let delegating_sk = make_signing_key(delegating_seed);
        let delegating_raw = delegating_sk.verifying_key().to_bytes();
        let delegating_qb64 = make_key_qb64(&delegating_raw, 'D');

        // Delegatee: dip — we need the delegating prefix.
        let delegatee_sk = make_signing_key(delegatee_seed);
        let delegatee_raw = delegatee_sk.verifying_key().to_bytes();
        let delegatee_qb64 = make_key_qb64(&delegatee_raw, 'D');

        // Build delegatee dip first (to get its SAID for the seal).
        let dip_preimage = format!(
            "{{\"t\":\"dip\",\"d\":\"{}\",\"di\":\"{}\"}}",
            "#".repeat(44),
            delegating_qb64
        )
        .into_bytes();
        let dip_said = blake3_hash(&dip_preimage);
        let dip_said_qb64 = digest_to_qb64(&dip_said);

        // Build delegating icp with the approval seal in `a`.
        // The delegatee prefix is the dip SAID itself (self-addressing).
        let delegating_icp_preimage = format!(
            "{{\"t\":\"icp\",\"d\":\"{}\",\"a\":[{{\"i\":\"{}\",\"s\":\"0\",\"d\":\"{}\"}}]}}",
            "#".repeat(44),
            dip_said_qb64, // delegatee prefix = dip SAID (self-addressing)
            dip_said_qb64,
        )
        .into_bytes();
        let delegating_icp_event =
            build_event_and_sign(delegating_icp_preimage, &[&delegating_sk], 1, None, 0, vec![], vec![], 0);

        let delegating_kel = KelInput {
            prefix_qb64: delegating_qb64.clone(),
            initial_keys_qb64: vec![delegating_qb64.clone()],
            events: vec![delegating_icp_event],
            delegating_kel: None,
        };

        // Now build the dip event for the delegatee.
        let dip_event = build_event_and_sign(
            dip_preimage,
            &[&delegatee_sk],
            1,
            None,
            3, // dip
            vec![],
            vec![],
            0,
        );
        // Set delegation_event_idx = 0 (the delegating icp event has the seal).
        let mut dip_event = dip_event;
        dip_event.delegation_event_idx = Some(0);

        let delegatee_kel = KelInput {
            prefix_qb64: dip_said_qb64.clone(), // self-addressing prefix
            initial_keys_qb64: vec![delegatee_qb64],
            events: vec![dip_event],
            delegating_kel: Some(Box::new(delegating_kel)),
        };

        (delegatee_kel, KelInput {
            prefix_qb64: delegating_qb64.clone(),
            initial_keys_qb64: vec![delegating_qb64],
            events: vec![],
            delegating_kel: None,
        })
    }

    #[test]
    fn test_dip_basic() {
        let delegating_seed: [u8; 32] = [0xaa; 32];
        let delegatee_seed: [u8; 32] = [0xbb; 32];
        let (delegatee_kel, _) = make_delegating_kel_and_dip(&delegating_seed, &delegatee_seed);
        let msg_hash = run_kel_verification(&delegatee_kel);
        assert_ne!(msg_hash, [0u8; 32]);
        // Deterministic
        assert_eq!(run_kel_verification(&delegatee_kel), msg_hash);
    }

    #[test]
    #[should_panic(expected = "Delegation seal not found")]
    fn test_dip_wrong_seal_panics() {
        let delegating_seed: [u8; 32] = [0xaa; 32];
        let delegatee_seed: [u8; 32] = [0xbb; 32];
        let (mut delegatee_kel, _) = make_delegating_kel_and_dip(&delegating_seed, &delegatee_seed);

        // Replace the delegating KEL's icp with a version that has a WRONG seal
        // (wrong delegatee prefix in `i` field).
        let delegating_sk = make_signing_key(&delegating_seed);

        let bad_icp_preimage = format!(
            "{{\"t\":\"icp\",\"d\":\"{}\",\"a\":[{{\"i\":\"Ewrongprefix0000000000000000000000000000000\",\"s\":\"0\",\"d\":\"Ewrongprefix0000000000000000000000000000000\"}}]}}",
            "#".repeat(44),
        ).into_bytes();
        let bad_delegating_event =
            build_event_and_sign(bad_icp_preimage, &[&delegating_sk], 1, None, 0, vec![], vec![], 0);

        let mut bad_delegating_kel = delegatee_kel.delegating_kel.as_deref().unwrap().clone();
        bad_delegating_kel.events = vec![bad_delegating_event];
        delegatee_kel.delegating_kel = Some(Box::new(bad_delegating_kel));

        run_kel_verification(&delegatee_kel);
    }

    #[test]
    fn test_dip_drt_pipeline() {
        // Build delegating KEL: icp (seals dip), ixn (seals drt).
        let delegating_seed: [u8; 32] = [0xcc; 32];
        let delegatee_seed: [u8; 32] = [0xdd; 32];
        let delegatee_seed2: [u8; 32] = [0xee; 32];

        let delegating_sk = make_signing_key(&delegating_seed);
        let delegating_raw = delegating_sk.verifying_key().to_bytes();
        let delegating_qb64 = make_key_qb64(&delegating_raw, 'D');

        let delegatee_sk = make_signing_key(&delegatee_seed);
        let delegatee_raw = delegatee_sk.verifying_key().to_bytes();
        let delegatee_qb64 = make_key_qb64(&delegatee_raw, 'D');

        let delegatee_sk2 = make_signing_key(&delegatee_seed2);
        let delegatee_raw2 = delegatee_sk2.verifying_key().to_bytes();
        let delegatee_qb642 = make_key_qb64(&delegatee_raw2, 'D');

        // Build dip event first to get delegatee prefix (= dip SAID).
        let n_next = blake3_hash(delegatee_qb642.as_bytes());
        let dip_preimage = format!(
            "{{\"t\":\"dip\",\"d\":\"{}\",\"di\":\"{}\"}}",
            "#".repeat(44),
            delegating_qb64
        )
        .into_bytes();
        let dip_said = blake3_hash(&dip_preimage);
        let dip_said_qb64 = digest_to_qb64(&dip_said);

        // Build drt event. drt events do not include a 'di' field (unlike dip).
        let drt_preimage = format!(
            "{{\"t\":\"drt\",\"d\":\"{}\"}}",
            "#".repeat(44),
        )
        .into_bytes();
        let drt_said = blake3_hash(&drt_preimage);
        let drt_said_qb64 = digest_to_qb64(&drt_said);

        // Delegating: icp seals dip, then ixn seals drt.
        let delegating_icp_preimage = format!(
            "{{\"t\":\"icp\",\"d\":\"{}\",\"a\":[{{\"i\":\"{}\",\"s\":\"0\",\"d\":\"{}\"}}]}}",
            "#".repeat(44),
            dip_said_qb64,
            dip_said_qb64,
        ).into_bytes();
        let delegating_icp_event = build_event_and_sign(
            delegating_icp_preimage, &[&delegating_sk], 1, None, 0, vec![], vec![], 0
        );
        let del_icp_said = delegating_icp_event.expected_said;

        let delegating_ixn_preimage = format!(
            "{{\"t\":\"ixn\",\"d\":\"{}\",\"a\":[{{\"i\":\"{}\",\"s\":\"1\",\"d\":\"{}\"}}]}}",
            "#".repeat(44),
            dip_said_qb64,
            drt_said_qb64,
        ).into_bytes();
        let delegating_ixn_event = build_event_and_sign(
            delegating_ixn_preimage, &[&delegating_sk], 1, Some(del_icp_said), 1, vec![], vec![], 0
        );

        let delegating_kel = KelInput {
            prefix_qb64: delegating_qb64.clone(),
            initial_keys_qb64: vec![delegating_qb64.clone()],
            events: vec![delegating_icp_event, delegating_ixn_event],
            delegating_kel: None,
        };

        // Build dip event (sn=0, signed by delegatee key0, no prev).
        let mut dip_event = build_event_and_sign(
            dip_preimage, &[&delegatee_sk], 1, None, 3, vec![], vec![n_next], 1
        );
        dip_event.delegation_event_idx = Some(0); // delegating icp (sn=0) has the dip seal.

        // Build drt event (sn=1, signed by delegatee key0, approved by delegating ixn sn=1).
        let mut drt_event = build_event_and_sign(
            drt_preimage, &[&delegatee_sk], 1, Some(dip_said), 4,
            vec![delegatee_qb642.clone()], vec![], 0
        );
        drt_event.delegation_event_idx = Some(1); // delegating ixn (sn=1) has the drt seal.

        let delegatee_kel = KelInput {
            prefix_qb64: dip_said_qb64.clone(),
            initial_keys_qb64: vec![delegatee_qb64],
            events: vec![dip_event, drt_event],
            delegating_kel: Some(Box::new(delegating_kel)),
        };

        let msg_hash = run_kel_verification(&delegatee_kel);
        assert_ne!(msg_hash, [0u8; 32]);
    }
}
