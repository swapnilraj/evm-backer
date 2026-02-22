//! KERI TEL (Transaction Event Log) verification logic for the SP1 zkVM guest.
//!
//! The guest proves:
//! 1. The TEL event's SAID is correct (blake3).
//! 2. The controller's KEL anchor event contains a seal `{"i": registry_prefix, "s": tel_sn, "d": tel_said}`.
//!
//! Note: the controller's KEL anchor event being ON-CHAIN is verified by SP1TELVerifier
//! calling KERIBacker.isAnchored() at proof-verify time (not inside the zkVM).
//!
//! Public values: 192 bytes = abi.encode(
//!   bytes32 registry_prefix_b32,
//!   uint64  tel_sn,
//!   bytes32 tel_said_b32,
//!   bytes32 controller_prefix_b32,
//!   uint64  anchor_sn,
//!   bytes32 anchor_said_b32,
//! )

pub use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tiny_keccak::{Hasher, Keccak};

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct TelEvent {
    /// TEL event JSON with the d field set to "#"*44.
    pub preimage_bytes: Vec<u8>,
    /// Raw 32-byte blake3 output (the SAID).
    pub expected_said: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct AnchorEvent {
    /// Controller's KEL event JSON with the d field set to "#"*44.
    pub preimage_bytes: Vec<u8>,
    /// Raw 32-byte blake3 output (the SAID).
    pub expected_said: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct TelInput {
    /// TEL registry prefix qb64 (e.g. "E...").
    pub registry_prefix_qb64: String,
    /// Controller AID prefix qb64.
    pub controller_prefix_qb64: String,
    /// TEL event sequence number.
    pub tel_sn: u64,
    /// The TEL event to prove.
    pub tel_event: TelEvent,
    /// Sequence number of the controller KEL event containing the anchor seal.
    pub anchor_sn: u64,
    /// The controller KEL anchor event (contains seal in `a` field).
    pub anchor_event: AnchorEvent,
}

// ---------------------------------------------------------------------------
// Core helpers
// ---------------------------------------------------------------------------

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Encode raw 32-byte blake3 digest to a 44-char KERI qb64 string (code 'E').
pub fn digest_to_qb64(raw: &[u8; 32]) -> String {
    let mut padded = [0u8; 33];
    padded[1..].copy_from_slice(raw);
    let b64 = URL_SAFE_NO_PAD.encode(padded);
    let mut result = String::with_capacity(44);
    result.push('E');
    result.push_str(&b64[1..]);
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
// Main algorithm
// ---------------------------------------------------------------------------

/// Verify a KERI TEL event and commit public values.
///
/// Algorithm:
/// 1. Verify TEL SAID: blake3(tel_event.preimage_bytes) == tel_event.expected_said
/// 2. Verify anchor SAID: blake3(anchor_event.preimage_bytes) == anchor_event.expected_said
/// 3. Reconstruct anchor signing bytes (replace "#"*44 with SAID qb64)
/// 4. Parse anchor JSON; find seal {"i": registry_prefix, "s": tel_sn, "d": tel_said}
/// 5. Commit 192-byte public values via sp1_zkvm::io::commit_slice
#[cfg(not(test))]
pub fn run_tel_verification(input: &TelInput) {
    let public_values = compute_tel_public_values(input);
    sp1_zkvm::io::commit_slice(&public_values);
}

/// Test-visible version that returns public values instead of committing.
pub fn compute_tel_public_values(input: &TelInput) -> Vec<u8> {
    // Step 1: TEL SAID verification.
    let computed_tel_said = blake3_hash(&input.tel_event.preimage_bytes);
    assert_eq!(
        computed_tel_said, input.tel_event.expected_said,
        "TEL event SAID mismatch"
    );
    let tel_said_qb64 = digest_to_qb64(&input.tel_event.expected_said);

    // Step 2: Anchor SAID verification.
    let computed_anchor_said = blake3_hash(&input.anchor_event.preimage_bytes);
    assert_eq!(
        computed_anchor_said, input.anchor_event.expected_said,
        "Anchor event SAID mismatch"
    );

    // Step 3: Reconstruct anchor signing bytes.
    let anchor_said_qb64 = digest_to_qb64(&input.anchor_event.expected_said);
    let anchor_signing_bytes = replace_placeholder(
        &input.anchor_event.preimage_bytes,
        anchor_said_qb64.as_bytes(),
    );

    // Step 4: Parse anchor JSON and verify the seal.
    let anchor_json: serde_json::Value =
        serde_json::from_slice(&anchor_signing_bytes).expect("anchor event: invalid JSON");

    let a_field = anchor_json
        .get("a")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("anchor event: missing or non-array 'a' field"));

    let expected_s = input.tel_sn.to_string();
    let found = a_field.iter().any(|entry| {
        entry.get("i").and_then(|v| v.as_str()) == Some(&input.registry_prefix_qb64)
            && entry.get("s").and_then(|v| v.as_str()) == Some(&expected_s)
            && entry.get("d").and_then(|v| v.as_str()) == Some(&tel_said_qb64)
    });

    assert!(
        found,
        "TEL anchor seal not found: expected {{\"i\":{:?}, \"s\":{}, \"d\":{:?}}}",
        input.registry_prefix_qb64, input.tel_sn, tel_said_qb64
    );

    // Step 5: Compute 192-byte public values:
    // abi.encode(bytes32, uint64, bytes32, bytes32, uint64, bytes32)
    // = 32 + 32 + 32 + 32 + 32 + 32 = 192 bytes
    // but uint64 only occupies last 8 bytes of its 32-byte slot.
    let registry_prefix_b32 = keccak256(input.registry_prefix_qb64.as_bytes());
    let tel_said_b32 = keccak256(tel_said_qb64.as_bytes());
    let controller_prefix_b32 = keccak256(input.controller_prefix_qb64.as_bytes());
    let anchor_said_b32 = keccak256(anchor_said_qb64.as_bytes());

    // abi.encode layout (192 bytes total):
    // [0..32]   registry_prefix_b32
    // [32..64]  tel_sn as uint64 (left-padded: [32..56]=0, [56..64]=sn.to_be_bytes())
    // [64..96]  tel_said_b32
    // [96..128] controller_prefix_b32
    // [128..160] anchor_sn as uint64 (left-padded)
    // [160..192] anchor_said_b32
    let mut pv = vec![0u8; 192];
    pv[0..32].copy_from_slice(&registry_prefix_b32);
    pv[56..64].copy_from_slice(&input.tel_sn.to_be_bytes());
    pv[64..96].copy_from_slice(&tel_said_b32);
    pv[96..128].copy_from_slice(&controller_prefix_b32);
    pv[152..160].copy_from_slice(&input.anchor_sn.to_be_bytes());
    pv[160..192].copy_from_slice(&anchor_said_b32);
    pv
}

// In test mode, provide a no-op run_tel_verification that calls compute_tel_public_values.
#[cfg(test)]
pub fn run_tel_verification(input: &TelInput) {
    compute_tel_public_values(input);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tel_event(registry_prefix: &str, tel_sn: u64) -> TelEvent {
        let preimage = format!(
            "{{\"t\":\"iss\",\"d\":\"{}\",\"ri\":\"{}\",\"s\":\"{}\"}}",
            "#".repeat(44),
            registry_prefix,
            tel_sn,
        )
        .into_bytes();
        let expected_said = blake3_hash(&preimage);
        TelEvent {
            preimage_bytes: preimage,
            expected_said,
        }
    }

    fn make_anchor_event(registry_prefix: &str, tel_sn: u64, tel_said_qb64: &str) -> AnchorEvent {
        let preimage = format!(
            "{{\"t\":\"ixn\",\"d\":\"{}\",\"a\":[{{\"i\":\"{}\",\"s\":\"{}\",\"d\":\"{}\"}}]}}",
            "#".repeat(44),
            registry_prefix,
            tel_sn,
            tel_said_qb64,
        )
        .into_bytes();
        let expected_said = blake3_hash(&preimage);
        AnchorEvent {
            preimage_bytes: preimage,
            expected_said,
        }
    }

    #[test]
    fn test_tel_said_verification() {
        let registry_prefix = "ETestRegistry0000000000000000000000000000000";
        let tel_event = make_tel_event(registry_prefix, 0);
        // Should not panic — SAID is correct.
        let computed = blake3_hash(&tel_event.preimage_bytes);
        assert_eq!(computed, tel_event.expected_said);
    }

    #[test]
    fn test_anchor_seal_verification() {
        let registry_prefix = "ETestRegistry0000000000000000000000000000000";
        let tel_event = make_tel_event(registry_prefix, 0);
        let tel_said_qb64 = digest_to_qb64(&tel_event.expected_said);
        let anchor_event = make_anchor_event(registry_prefix, 0, &tel_said_qb64);

        let input = TelInput {
            registry_prefix_qb64: registry_prefix.to_string(),
            controller_prefix_qb64: "BTestController000000000000000000000000000000".to_string(),
            tel_sn: 0,
            tel_event,
            anchor_sn: 1,
            anchor_event,
        };
        // Should not panic.
        compute_tel_public_values(&input);
    }

    #[test]
    #[should_panic(expected = "TEL anchor seal not found")]
    fn test_wrong_seal_panics() {
        let registry_prefix = "ETestRegistry0000000000000000000000000000000";
        let tel_event = make_tel_event(registry_prefix, 0);
        // Build anchor with WRONG seal (different registry prefix).
        let tel_said_qb64 = digest_to_qb64(&tel_event.expected_said);
        let wrong_anchor = make_anchor_event("EWrongRegistry00000000000000000000000000000", 0, &tel_said_qb64);

        let input = TelInput {
            registry_prefix_qb64: registry_prefix.to_string(),
            controller_prefix_qb64: "BTestController000000000000000000000000000000".to_string(),
            tel_sn: 0,
            tel_event,
            anchor_sn: 1,
            anchor_event: wrong_anchor,
        };
        compute_tel_public_values(&input);
    }

    #[test]
    fn test_full_tel_pipeline() {
        let registry_prefix = "ETestRegistry0000000000000000000000000000000";
        let controller_prefix = "BTestController000000000000000000000000000000";
        let tel_sn: u64 = 0;

        let tel_event = make_tel_event(registry_prefix, tel_sn);
        let tel_said_qb64 = digest_to_qb64(&tel_event.expected_said);
        let anchor_event = make_anchor_event(registry_prefix, tel_sn, &tel_said_qb64);

        let input = TelInput {
            registry_prefix_qb64: registry_prefix.to_string(),
            controller_prefix_qb64: controller_prefix.to_string(),
            tel_sn,
            tel_event,
            anchor_sn: 5,
            anchor_event,
        };

        let pv = compute_tel_public_values(&input);
        // Public values must be 192 bytes.
        assert_eq!(pv.len(), 192, "TEL public values must be 192 bytes");

        // Spot-check: registry_prefix_b32 is keccak256 of the registry prefix.
        let expected_reg_b32 = keccak256(registry_prefix.as_bytes());
        assert_eq!(&pv[0..32], &expected_reg_b32);

        // tel_sn field: bytes 56-63.
        let tel_sn_bytes: [u8; 8] = pv[56..64].try_into().unwrap();
        assert_eq!(u64::from_be_bytes(tel_sn_bytes), tel_sn);

        // anchor_sn field: bytes 152-159.
        let anchor_sn_bytes: [u8; 8] = pv[152..160].try_into().unwrap();
        assert_eq!(u64::from_be_bytes(anchor_sn_bytes), 5u64);
    }
}
