# SP1 Blake3 Precompile — Implementation Specification

## 1. Context and Motivation

### What this is

This document specifies the implementation of a Blake3 hash precompile for the
[SP1 zkVM](https://github.com/succinctlabs/sp1) (version 6.x). The goal is to
upstream this as a contribution to `succinctlabs/sp1`.

### Why Blake3

[KERI](https://keri.one) (Key Event Receipt Infrastructure) uses Blake3_256 as
its default hash algorithm for computing SAIDs (Self-Addressing IDentifiers).
The SAID is the canonical identifier for a KERI event — it is `blake3(event_bytes)`
encoded as base64url. Every event in a KEL (Key Event Log) references the prior
event's SAID in its `p` (prior) field, forming an unforgeable hash chain.

The `evm-backer` project (in this repo) anchors KERI events on Ethereum. The
long-term goal is to verify the full KERI event chain inside the SP1 zkVM,
producing a Groth16 proof that the chain is cryptographically valid. This
eliminates the need for trusted attestors entirely.

Without a Blake3 precompile, every SAID verification inside the guest runs as
plain RISC-V software (~200k–500k cycles per event). With a precompile it drops
to ~1k–5k cycles — the same order as the existing Ed25519 precompile — making
full-chain verification fast for typical KEL lengths (5–50 events).

Blake3 is also used by Solana, IPFS, OpenZFS, Bazel, and many other systems, so
this precompile is broadly useful beyond KERI.

### Scope of this document

1. Implement the Blake3 compression function as an SP1 AIR chip
2. Wire it as a syscall (guest-side stub + executor handler + chip registration)
3. Publish a patched `blake3` crate in the `sp1-patches` style
4. Write unit tests and integration tests
5. Open a PR to `succinctlabs/sp1`

This document does NOT cover the higher-level KERI chain verification guest
program that will use this precompile — that is a separate project.

---

## 2. SP1 Architecture Overview

### The two-sided precompile model

Every SP1 precompile has exactly two sides:

**Guest side** — the RISC-V program (your SP1 guest) calls a syscall via
`ecall`. The SP1 toolchain compiles the guest to RISC-V ELF. When running inside
the zkVM, the hot path of the cryptographic library is replaced with a syscall
stub that writes inputs to memory and reads outputs from memory.

**Prover side** — the SP1 prover has a "chip" (an AIR table with constraints)
that proves the syscall was executed correctly. The chip reads the same memory
regions the guest wrote, applies constraints that enforce the Blake3 computation,
and produces the correct output. The RISC-V code for the operation is NOT
re-executed in the prover — only the constraints run.

This means: the guest runs fast (one `ecall` instruction), and the prover proves
correctness via polynomial constraints rather than re-simulation.

### SP1 proof stack

```
Guest RISC-V program
  └─ ecall (Blake3 syscall number, input ptr, output ptr)

SP1 Executor (interpretation layer)
  └─ SyscallHandler for Blake3
       reads memory → runs native Blake3 → writes memory back
       records the (input, output) as a "precompile event"

SP1 STARK prover (constraint layer)
  └─ Blake3CompressChip: AIR constraints prove output = Blake3(input)
  └─ MemoryChip: proves the memory reads/writes are consistent

SP1 Groth16 wrapper
  └─ Wraps the STARK proof into a ~256-byte Groth16 proof

SP1VerifierGroth16.sol
  └─ Verifies the Groth16 proof on-chain (~275k gas)
```

### SP1 field

SP1 uses the **BabyBear** prime field: `p = 2^31 - 2^27 + 1 = 2013265921`.
This is a 31-bit prime. **Important**: 32-bit unsigned integers (like Blake3's
state words) do NOT fit in one field element. Every 32-bit operation must be
decomposed into bytes or handled with carry arithmetic. This is the central
challenge of implementing a 32-bit hash in SP1.

### Plonky3 AIR interface

SP1 chips implement the `Air<AB: AirBuilder>` trait from
[Plonky3](https://github.com/Plonky3/Plonky3). The trait requires implementing
`eval(&self, builder: &mut AB)` which asserts polynomial constraints. Each row
of the AIR table represents one step of the computation. Constraints can assert:

- `builder.assert_zero(expr)` — expr must be zero on every row
- `builder.assert_bool(expr)` — expr must be 0 or 1
- Interactions with other chips (lookup arguments) via `builder.send(...)` /
  `builder.receive(...)`

---

## 3. SP1 Codebase Navigation

The implementation will touch the `succinctlabs/sp1` repository. Clone it:

```bash
git clone https://github.com/succinctlabs/sp1
cd sp1
git checkout dev   # or the latest stable tag, e.g. v6.4.0
```

### Key directories

```
sp1/
  crates/
    core/
      machine/src/chips/precompiles/   ← ADD blake3/ HERE (the AIR chip)
        sha256/                        ← PRIMARY REFERENCE — study this
          compress.rs                  ← SHA-256 compress AIR (~1200 lines)
          extend.rs                    ← SHA-256 message schedule AIR
          mod.rs
        keccak256/                     ← also study for lookup table patterns
        ed25519/                       ← also study for field arithmetic
        mod.rs                         ← REGISTER new chip here
      executor/src/syscalls/precompiles/ ← ADD blake3.rs HERE (executor handler)
        sha256/
          compress.rs                  ← reference for syscall handler pattern
        mod.rs                         ← REGISTER new syscall here
    zkvm/
      precompiles/src/                 ← ADD blake3.rs HERE (guest-side stub)
        lib.rs                         ← REGISTER syscall number here
  # Separate repo for crate patch:
  # github.com/sp1-patches/BLAKE3
```

### Primary reference: SHA-256 compress chip

Read `crates/core/machine/src/chips/precompiles/sha256/compress.rs` in full
before writing any Blake3 code. It demonstrates:

- How to represent a u32 as `Word<F>` (4 bytes)
- How to do 32-bit addition with carry in BabyBear
- How to use the XOR lookup table (`ShrCarryChip` / `XorChip`)
- How to interact with the memory chip for reads and writes
- How to structure AIR columns as a `#[derive(AlignedBorrow)]` struct

### Secondary reference: SHA-256 syscall handler

Read `crates/core/executor/src/syscalls/precompiles/sha256/compress.rs`. It shows:

- How to implement `SyscallHandler`
- How to read memory from the RISC-V address space
- How to run the native computation (for witness generation)
- How to write the result back to memory
- How to record a `PrecompileEvent` for the prover

---

## 4. Blake3 Algorithm Reference

### Constants

```rust
// Initialization vector (same as SHA-256's IV — first 8 primes, fractional parts)
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// Message word permutation applied each round
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const BLOCK_LEN: u32 = 64;    // bytes per block
const CHUNK_LEN: u32 = 1024;  // bytes per chunk (not relevant for single-block path)

// Flags
const CHUNK_START: u32 = 1;
const CHUNK_END:   u32 = 2;
const ROOT:        u32 = 8;
```

### The G mixing function

The core operation. Applied 56 times per compression (7 rounds × 8 G calls):

```rust
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}
```

Operations per G call: 4 wrapping additions, 4 XORs, 4 rotations.

### One round

```rust
fn round(state: &mut [u32; 16], msg: &[u32; 16]) {
    // Column step
    g(state,  0, 4,  8, 12, msg[0],  msg[1]);
    g(state,  1, 5,  9, 13, msg[2],  msg[3]);
    g(state,  2, 6, 10, 14, msg[4],  msg[5]);
    g(state,  3, 7, 11, 15, msg[6],  msg[7]);
    // Diagonal step
    g(state,  0, 5, 10, 15, msg[8],  msg[9]);
    g(state,  1, 6, 11, 12, msg[10], msg[11]);
    g(state,  2, 7,  8, 13, msg[12], msg[13]);
    g(state,  3, 4,  9, 14, msg[14], msg[15]);
}
```

### Full compression function

```rust
fn compress(
    chaining_value: &[u32; 8],  // current chaining value (cv)
    block_words: &[u32; 16],    // 16 message words (64 bytes, little-endian)
    counter: u64,               // chunk counter
    block_len: u32,             // number of input bytes in this block (≤ 64)
    flags: u32,                 // CHUNK_START | CHUNK_END | ROOT etc.
) -> [u32; 16] {
    let mut state: [u32; 16] = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0], IV[1], IV[2], IV[3],
        counter as u32, (counter >> 32) as u32,
        block_len, flags,
    ];

    // Apply permutation to get message words for each round
    let mut msg = *block_words;
    for _ in 0..7 {
        round(&mut state, &msg);
        // Permute message words for next round
        let mut permuted = [0u32; 16];
        for i in 0..16 { permuted[i] = msg[MSG_PERMUTATION[i]]; }
        msg = permuted;
    }

    // XOR upper half into lower half (output chaining value)
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }

    state
}
```

### Blake3 hash of a short message (≤ 1024 bytes, the KERI case)

For KERI event bytes (typically 100–500 bytes), the message fits in one chunk.
Each 64-byte block is compressed in sequence. The final output is the first 32
bytes of the last compression's output, in little-endian.

```rust
fn blake3_hash(input: &[u8]) -> [u8; 32] {
    assert!(input.len() <= 1024, "single-chunk path only");

    let mut cv = IV;  // start with IV as chaining value
    let mut offset = 0;
    let num_full_blocks = input.len() / 64;

    for block_idx in 0..num_full_blocks {
        let mut flags = 0u32;
        if block_idx == 0 { flags |= CHUNK_START; }
        if block_idx == num_full_blocks && input.len() % 64 == 0 { flags |= CHUNK_END | ROOT; }

        let mut block_words = [0u32; 16];
        for i in 0..16 {
            block_words[i] = u32::from_le_bytes(input[offset + i*4..offset + i*4 + 4].try_into().unwrap());
        }
        let out = compress(&cv, &block_words, 0, BLOCK_LEN, flags);
        cv.copy_from_slice(&out[..8]);
        offset += 64;
    }

    // Final (possibly partial) block
    let mut last_block = [0u8; 64];
    let remaining = &input[offset..];
    last_block[..remaining.len()].copy_from_slice(remaining);
    let mut block_words = [0u32; 16];
    for i in 0..16 {
        block_words[i] = u32::from_le_bytes(last_block[i*4..i*4+4].try_into().unwrap());
    }
    let mut flags = CHUNK_END | ROOT;
    if offset == 0 { flags |= CHUNK_START; }
    let out = compress(&cv, &block_words, 0, remaining.len() as u32, flags);

    // Output: first 8 words as little-endian bytes
    let mut hash = [0u8; 32];
    for i in 0..8 {
        hash[i*4..(i+1)*4].copy_from_slice(&out[i].to_le_bytes());
    }
    hash
}
```

### Rotation amounts

The four rotations used in G: **right by 16, 12, 8, 7 bits**.

For the AIR, each rotation is encoded by byte-reordering + bit shifting:
- `rotr16(x)`: swap the two 16-bit halves — pure byte reorder, no bit shifting
- `rotr8(x)`: rotate bytes by 1 — pure byte reorder, no bit shifting
- `rotr12(x)`: 4-bit shift after byte manipulation
- `rotr7(x)`: 1-bit shift after byte manipulation

`rotr16` and `rotr8` are free (just column reordering in the AIR). `rotr12` and
`rotr7` require a small bit decomposition.

---

## 5. Syscall Design

### Syscall number

Add a new constant to `crates/zkvm/precompiles/src/lib.rs`:

```rust
pub const BLAKE3_COMPRESS_INNER: SyscallCode = SyscallCode::BLAKE3_COMPRESS_INNER; // pick next available number
```

Look at the existing `SyscallCode` enum to find the next unused value (currently
likely in the 0x00_00_01_xx range). Name it `BLAKE3_COMPRESS_INNER` to match
the function name in the blake3 crate internals.

### Memory layout

The syscall takes two pointer arguments (passed in RISC-V registers `a0`, `a1`):

```
a0: *mut [u32; 16]   — the full 16-word compression state (input + output)
    Words 0..7   = chaining value (cv) — INPUT, overwritten with new cv on exit
    Words 8..11  = IV (hardcoded constants, written by guest before syscall)
    Words 12..13 = counter_low, counter_high
    Words 14     = block_len
    Words 15     = flags

a1: *const [u32; 16] — the 16 message words (block_words) — read-only input
```

After the syscall:
- `a0[0..8]` = new chaining value (XOR'd output as per compress() final step)
- `a0[8..16]` = upper half of compression output (for ROOT nodes that need full output)
- `a1[0..16]` = unchanged

This matches how the blake3 crate's `compress_in_place` function works internally.

### Why this layout

The SP1 SHA-256 compress syscall uses a similar pattern: a pointer to the state
(8 u32s) and a pointer to the message schedule (64 u32s). Modelling Blake3
after this makes the implementation consistent and easier to review.

---

## 6. Implementation Plan

Implement in this exact order. Each step is independently testable.

### Step 0: Read the SHA-256 chip in full

Before writing any code, read these files completely:
- `crates/core/machine/src/chips/precompiles/sha256/compress.rs`
- `crates/core/executor/src/syscalls/precompiles/sha256/compress.rs`
- `crates/zkvm/precompiles/src/lib.rs` (look at how SHA256_COMPRESS is defined)

Understand:
- The `Word<F>` type and how bytes map to field elements
- How `builder.send_byte_pair(...)` interacts with the XOR lookup table
- The `MemoryReadCols` and `MemoryWriteCols` column types
- How `eval_memory_access` hooks into the memory chip

### Step 1: Guest-side syscall stub

**File**: `crates/zkvm/precompiles/src/blake3.rs` (new file)

```rust
cfg_if::cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use crate::SyscallCode;

        /// Blake3 compress inner syscall.
        ///
        /// # Safety
        /// `state` must point to 16 u32s (64 bytes). `msg` must point to 16 u32s (64 bytes).
        /// On return, state[0..8] contains the new chaining value.
        pub unsafe fn syscall_blake3_compress_inner(state: *mut u32, msg: *const u32) {
            core::arch::asm!(
                "ecall",
                in("a0") state,
                in("a1") msg,
                in("t0") SyscallCode::BLAKE3_COMPRESS_INNER as u32,
                options(nostack),
            );
        }
    } else {
        pub unsafe fn syscall_blake3_compress_inner(state: *mut u32, msg: *const u32) {
            // No-op outside zkvm — the patched crate handles the fallback
            unimplemented!("only callable inside SP1 zkVM");
        }
    }
}
```

Register in `crates/zkvm/precompiles/src/lib.rs`:
```rust
pub mod blake3;
pub use blake3::syscall_blake3_compress_inner;
```

### Step 2: Executor syscall handler

**File**: `crates/core/executor/src/syscalls/precompiles/blake3.rs` (new file)

```rust
use crate::syscalls::SyscallContext;
use sp1_primitives::consts::bytes_to_words_le;

/// Syscall handler for BLAKE3_COMPRESS_INNER.
///
/// Reads the 16-word state and 16-word message from the guest's address space,
/// runs native Blake3 compression (via the blake3 crate), writes the result
/// back, and records a PrecompileEvent for the prover chip.
pub fn syscall_blake3_compress_inner(ctx: &mut SyscallContext, state_ptr: u32, msg_ptr: u32) -> Option<u64> {
    // Read state words [0..16] from guest memory
    let state_words = ctx.mr_slice(state_ptr, 16);  // 16 u32s
    let msg_words   = ctx.mr_slice(msg_ptr,   16);  // 16 u32s

    // Convert to blake3 internal types and run the compression
    let mut state: [u32; 16] = state_words.try_into().unwrap();
    let msg: [u32; 16] = msg_words.try_into().unwrap();

    // Run the reference Blake3 compression (used for witness generation)
    blake3_compress_inner_reference(&mut state, &msg);

    // Write the result back into guest memory
    ctx.mw_slice(state_ptr, &state);

    // Record the precompile event for the prover chip
    ctx.record_mut().blake3_compress_events.push(Blake3CompressEvent {
        clk: ctx.clk(),
        state_ptr,
        msg_ptr,
        input_state: state_words.try_into().unwrap(),
        input_msg:   msg.try_into().unwrap(),
        output_state: state,
    });

    None  // no return value in register
}

fn blake3_compress_inner_reference(state: &mut [u32; 16], msg: &[u32; 16]) {
    // Implement the 7-round Blake3 compression matching the AIR exactly.
    // This MUST be bit-for-bit identical to what the AIR proves.
    // Use the algorithm from Section 4 of this document.
    let mut m = *msg;
    for _ in 0..7 {
        round(state, &m);
        let mut permuted = [0u32; 16];
        for i in 0..16 { permuted[i] = m[MSG_PERMUTATION[i]]; }
        m = permuted;
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= state[i]; // original cv, captured before the loop
    }
}
```

Register in `crates/core/executor/src/syscalls/mod.rs`:
```rust
SyscallCode::BLAKE3_COMPRESS_INNER => {
    Box::new(blake3::syscall_blake3_compress_inner)
}
```

### Step 3: AIR chip — column layout

**File**: `crates/core/machine/src/chips/precompiles/blake3/compress.rs` (new file)

Define the witness columns. Each row of the AIR represents one G function
application (56 rows per compression call, spread across 7 rounds × 8 G calls).

```rust
use sp1_derive::AlignedBorrow;

/// Columns for one Blake3 compress invocation.
/// One row = one G function application.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake3CompressCols<T: Copy> {
    // === Control ===
    pub is_real:   T,       // 1 if this row is a real G application
    pub round:     T,       // round index 0..6
    pub g_index:   T,       // G index within round 0..7

    // === Memory access (first and last row of each compress call) ===
    pub state_ptr: T,       // pointer to state in guest memory
    pub msg_ptr:   T,       // pointer to message in guest memory
    pub state_read:  [MemoryReadCols<T>; 16],   // read state words
    pub msg_read:    [MemoryReadCols<T>; 16],   // read message words
    pub state_write: [MemoryWriteCols<T>; 16],  // write output state

    // === G function inputs ===
    // Four state indices a, b, c, d for this G call
    pub a_in:  Word<T>,     // state[a] before G
    pub b_in:  Word<T>,     // state[b] before G
    pub c_in:  Word<T>,     // state[c] before G
    pub d_in:  Word<T>,     // state[d] before G
    pub mx:    Word<T>,     // message word mx
    pub my:    Word<T>,     // message word my

    // === G function intermediate values ===
    // Line 1: a' = a + b + mx
    pub a1:       Word<T>,
    pub a1_carry: T,

    // Line 2: d' = (d XOR a') >>> 16
    pub d1_xor:   Word<T>,  // d XOR a' (before rotation)
    pub d1:       Word<T>,  // after rotr16

    // Line 3: c' = c + d'
    pub c1:       Word<T>,
    pub c1_carry: T,

    // Line 4: b' = (b XOR c') >>> 12
    pub b1_xor:   Word<T>,  // b XOR c' (before rotation)
    pub b1:       Word<T>,  // after rotr12
    pub b1_bits:  [T; 32],  // bit decomposition for rotr12

    // Line 5: a'' = a' + b' + my
    pub a2:       Word<T>,
    pub a2_carry: T,

    // Line 6: d'' = (d' XOR a'') >>> 8
    pub d2_xor:   Word<T>,  // d' XOR a'' (before rotation)
    pub d2:       Word<T>,  // after rotr8

    // Line 7: c'' = c' + d''
    pub c2:       Word<T>,
    pub c2_carry: T,

    // Line 8: b'' = (b' XOR c'') >>> 7
    pub b2_xor:   Word<T>,  // b' XOR c'' (before rotation)
    pub b2:       Word<T>,  // after rotr7
    pub b2_bits:  [T; 32],  // bit decomposition for rotr7

    // === G function outputs ===
    pub a_out:  Word<T>,
    pub b_out:  Word<T>,
    pub c_out:  Word<T>,
    pub d_out:  Word<T>,
}
```

Note: `Word<T>` is `[T; 4]` — a u32 represented as 4 bytes (field elements 0..255).

### Step 4: AIR chip — constraints

**In the same file**, implement `Air<AB>`:

```rust
impl<AB: SP1AirBuilder> Air<AB> for Blake3CompressChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Blake3CompressCols<AB::Var> = (*local).borrow();

        // === 32-bit addition constraints ===
        // For a1 = a_in + b_in + mx:
        // Represent each Word as 4 bytes. The sum of bytes at each position
        // plus carry-in must equal the output byte plus 256 * carry-out.
        eval_add3_u32(builder, local.a_in, local.b_in, local.mx, local.a1, local.a1_carry);

        // === XOR constraints via lookup table ===
        // d1_xor = d_in XOR a1
        // Use the XOR lookup table chip: send (d_in_byte, a1_byte, d1_xor_byte) for each byte pair
        for i in 0..4 {
            builder.send_xor(local.d_in[i], local.a1[i], local.d1_xor[i], local.is_real);
        }

        // === Rotation constraints ===
        // rotr16: just byte reordering — no bits needed
        // d1[0] = d1_xor[2], d1[1] = d1_xor[3], d1[2] = d1_xor[0], d1[3] = d1_xor[1]
        builder.assert_eq(local.d1[0], local.d1_xor[2]);
        builder.assert_eq(local.d1[1], local.d1_xor[3]);
        builder.assert_eq(local.d1[2], local.d1_xor[0]);
        builder.assert_eq(local.d1[3], local.d1_xor[1]);

        // rotr12: split each 32-bit word into bits, then reconstruct
        // Use bit decomposition columns b1_bits[0..31]
        eval_rotr_u32(builder, local.b1_xor, local.b1, local.b1_bits, 12);

        // rotr8: byte reordering only (same pattern as rotr16)
        builder.assert_eq(local.d2[0], local.d2_xor[1]);
        builder.assert_eq(local.d2[1], local.d2_xor[2]);
        builder.assert_eq(local.d2[2], local.d2_xor[3]);
        builder.assert_eq(local.d2[3], local.d2_xor[0]);

        // rotr7: bit decomposition
        eval_rotr_u32(builder, local.b2_xor, local.b2, local.b2_bits, 7);

        // === Output consistency ===
        // Verify a_out, b_out, c_out, d_out match the computed intermediates
        for i in 0..4 {
            builder.assert_eq(local.a_out[i], local.a2[i]);
            builder.assert_eq(local.b_out[i], local.b2[i]);
            builder.assert_eq(local.c_out[i], local.c2[i]);
            builder.assert_eq(local.d_out[i], local.d2[i]);
        }

        // === is_real must be boolean ===
        builder.assert_bool(local.is_real);

        // === Memory interactions (only on first/last row of each compress) ===
        // ... (follow SHA-256 chip pattern for memory chip interactions)
    }
}
```

**Helper functions to implement:**

```rust
/// Constrain out = a + b + c (mod 2^32) with carry.
/// Each of a, b, c, out is Word<AB::Var> (4 bytes).
/// carry is AB::Var, constrained to {0, 1, 2, 3} (can carry up to 3).
fn eval_add3_u32<AB: SP1AirBuilder>(
    builder: &mut AB,
    a: Word<AB::Var>, b: Word<AB::Var>, c: Word<AB::Var>,
    out: Word<AB::Var>, carry: AB::Var,
) { /* ... */ }

/// Constrain out = in.rotate_right(n) using bit decomposition.
/// bits must be a 32-element array of boolean witnesses.
fn eval_rotr_u32<AB: SP1AirBuilder>(
    builder: &mut AB,
    input: Word<AB::Var>,
    output: Word<AB::Var>,
    bits: [AB::Var; 32],
    n: usize,
) {
    // 1. Constrain bits[i] ∈ {0,1} for all i
    for b in bits { builder.assert_bool(b); }

    // 2. Reconstruct input from bits (byte by byte):
    //    bits[0..7]   = input[0] bits (LSB first)
    //    bits[8..15]  = input[1] bits
    //    bits[16..23] = input[2] bits
    //    bits[24..31] = input[3] bits
    for byte_idx in 0..4 {
        let mut reconstructed = AB::Expr::zero();
        for bit_idx in 0..8 {
            reconstructed += bits[byte_idx * 8 + bit_idx] * AB::Expr::from_canonical_u32(1 << bit_idx);
        }
        builder.assert_eq(input[byte_idx], reconstructed);
    }

    // 3. Reconstruct output from rotated bits:
    //    output bit i = bits[(i + n) % 32]
    // Group back into bytes for output
    for byte_idx in 0..4 {
        let mut reconstructed = AB::Expr::zero();
        for bit_idx in 0..8 {
            let src_bit = (byte_idx * 8 + bit_idx + n) % 32;
            reconstructed += bits[src_bit] * AB::Expr::from_canonical_u32(1 << bit_idx);
        }
        builder.assert_eq(output[byte_idx], reconstructed);
    }
}
```

### Step 5: Register the chip

In `crates/core/machine/src/chips/precompiles/mod.rs`, add:
```rust
pub mod blake3;
```

In the `RiscvAir` enum (find this in the machine crate — it lists all chips):
```rust
Blake3Compress(Blake3CompressChip),
```

In the chips vec constructor:
```rust
chips.push(RiscvAir::Blake3Compress(Blake3CompressChip::default()));
```

In the `SyscallCode` handler match:
```rust
SyscallCode::BLAKE3_COMPRESS_INNER => {
    let chip = self.blake3_compress_chip();
    // ... follow SHA256_COMPRESS pattern
}
```

### Step 6: Guest-side crate patch

Create a fork of the `blake3` crate in a new GitHub repo
`sp1-patches/BLAKE3` (unarchive the existing one or create fresh).
On a branch named `patched`:

**Patch target**: `blake3-1.5.x` (or latest stable). The key file is
`src/guts.rs` which contains `compress_in_place` and `compress_xof_in_place`.

```rust
// In blake3/src/guts.rs, replace the portable implementation:

#[cfg(target_os = "zkvm")]
pub fn compress_in_place(cv: &mut CVWords, block: &Block, block_len: u8, counter: u64, flags: u8) {
    unsafe {
        // Pack the full 16-word state that the syscall expects
        let mut state: [u32; 16] = [
            cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
            IV[0], IV[1], IV[2], IV[3],
            counter as u32, (counter >> 32) as u32,
            block_len as u32, flags as u32,
        ];
        // Convert block bytes to little-endian u32 words
        let mut msg = [0u32; 16];
        for i in 0..16 {
            msg[i] = u32::from_le_bytes(block[i*4..i*4+4].try_into().unwrap());
        }
        sp1_lib::syscall_blake3_compress_inner(state.as_mut_ptr(), msg.as_ptr());
        // Copy new cv back
        cv[0..8].copy_from_slice(&state[0..8]);
    }
}

#[cfg(not(target_os = "zkvm"))]
pub fn compress_in_place(cv: &mut CVWords, block: &Block, block_len: u8, counter: u64, flags: u8) {
    // original portable implementation unchanged
}
```

**Cargo.toml for the patched branch:**
```toml
[package]
name = "blake3"
version = "1.5.4"  # match upstream version

[dependencies]
sp1-lib = { version = "6.0.0", optional = true }

[features]
default = []
zkvm = ["sp1-lib"]
```

**Usage in sp1-guest Cargo.toml:**
```toml
[dependencies]
blake3 = { version = "1.5", features = ["zkvm"] }

[patch.crates-io]
blake3 = { git = "https://github.com/sp1-patches/BLAKE3", branch = "patched" }
```

---

## 7. Testing Plan

### Unit test 1: G function constraints

Test that the AIR constraints accept a valid G computation and reject a
corrupted one:

```rust
#[test]
fn test_g_function_constraints_valid() {
    // Run the G function natively to get witness values
    // Populate Blake3CompressCols with those values
    // Run the constraint checker — should produce no constraint failures
}

#[test]
fn test_g_function_constraints_reject_bad_xor() {
    // Same as above but flip one bit in d1_xor
    // Constraint checker should fail on the XOR lookup
}
```

### Unit test 2: Full compression round-trip

```rust
#[test]
fn test_compress_matches_reference() {
    use blake3::guts::{IV, CHUNK_START, CHUNK_END, ROOT};

    let cv = IV;
    let block = [0u8; 64];
    let mut block_words = [0u32; 16];
    for i in 0..16 { block_words[i] = u32::from_le_bytes(block[i*4..i*4+4].try_into().unwrap()); }

    // Reference (blake3 crate)
    let expected = blake3::hash(&block);

    // Our native reference implementation from the executor handler
    let out = blake3_compress_inner_reference(&cv, &block_words, 0, 64, CHUNK_START | CHUNK_END | ROOT);

    assert_eq!(&out[0..4], &expected.as_bytes()[0..4], "output mismatch");
}
```

### Unit test 3: Test vectors

Blake3 has official test vectors in the upstream repository
(`test_vectors/test_vectors.json`). Run all of them through the native
executor implementation to ensure correctness before proving:

```rust
#[test]
fn test_blake3_official_test_vectors() {
    let vectors = include_str!("../test_vectors/test_vectors.json");
    // ... parse and verify each vector
}
```

### Integration test: SP1 guest with Blake3

Write a minimal guest program that computes Blake3 inside the zkVM:

```rust
// sp1-blake3-test-guest/src/main.rs
#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: Vec<u8> = sp1_zkvm::io::read_vec();
    let hash = blake3::hash(&input);
    sp1_zkvm::io::commit_slice(hash.as_bytes());
}
```

Integration test:
```rust
#[test]
fn test_blake3_precompile_in_guest() {
    let input = b"hello world";
    let expected = blake3::hash(input);

    // Run with SP1_PROVER=mock (executes guest ELF, uses precompile if registered)
    std::env::set_var("SP1_PROVER", "mock");
    let client = ProverClient::from_env();
    // ... setup, prove, check public values == expected
}
```

### Performance test

After the precompile is working, measure cycles with and without it:

```
Without precompile (software Blake3, 10 events): ~3M cycles
With precompile (10 events):                      ~50k cycles
```

Run: `RUST_LOG=info cargo test test_performance -- --nocapture`

---

## 8. Key Pitfalls

### BabyBear overflow

BabyBear is a 31-bit prime. A u32 value of `2^31` or above is NOT representable
as a single field element. NEVER put a raw u32 into a single `AB::Var`. Always
decompose into bytes (0..255) or smaller chunks.

### The blake3 crate's internal API

The `compress_in_place` function is in `blake3::guts` which is a semipublic
module. The exact signature and module path may differ between blake3 versions.
**Always check the upstream blake3 source for the version you're patching.**

### rotr12 and rotr7 are the expensive ones

`rotr16` and `rotr8` are pure byte reordering — zero constraint overhead.
`rotr12` and `rotr7` require 32 boolean witness bits each plus reconstruction
constraints. Each G call contributes 64 boolean constraints from rotations.
Total per compression: 56 × 64 = 3584 boolean constraints just for rotations.
This is normal — SHA-256 has similar overhead.

### Message permutation must match exactly

The MSG_PERMUTATION array must be applied in the AIR exactly as in the reference
implementation. An off-by-one in the permutation produces wrong outputs that
pass constraint checks (since the AIR just proves internal consistency of the
columns, not correctness of the permutation index). Add explicit tests for this.

### Thread safety of the event recorder

The executor's `record_mut().blake3_compress_events.push(...)` must be safe
under the executor's locking model. Follow exactly how SHA-256 events are
recorded — do not introduce new locking patterns.

### Do not implement tree hashing initially

Blake3's tree-mode (for inputs > 1024 bytes) requires parent node chaining and
a different flags pattern. KERI events are ≤ 500 bytes — always single-chunk.
Implement tree mode as a follow-up, not in the initial PR.

---

## 9. SP1 Version Information

This implementation targets **SP1 6.x** (specifically tested with `sp1-sdk = "6.0.0"`
and `sp1-zkvm = "6.0.0"`).

The field is BabyBear: `p = 2^31 - 2^27 + 1`.

The Groth16 verifier version being used in the EVM backer project:
`lib/sp1-contracts/contracts/src/v6.0.0/SP1VerifierGroth16.sol`.

The vkey hash changes when the guest program changes (adding a new chip changes
the circuit). After implementing this precompile and updating the guest to use
it, the vkey must be recomputed and the `SP1KERIVerifier` contract redeployed
with the new vkey.

---

## 10. Contributing to succinctlabs/sp1

Once the implementation is complete and all tests pass:

1. Fork `succinctlabs/sp1` on GitHub
2. Create a branch: `feat/blake3-compress-precompile`
3. Open a PR with:
   - Title: `feat(precompiles): Blake3 compress inner precompile`
   - Reference the archived `sp1-patches/BLAKE3` repo as prior art
   - Note the use cases: KERI SAID verification, Solana, IPFS
   - Include benchmark numbers (cycles with vs. without precompile)
   - Tag SP1 team members who work on precompiles (check recent SHA-256 / keccak commits)
4. Separately, open a PR to `sp1-patches/BLAKE3` (unarchive it first or create
   a new repo) with the crate patch

---

## 11. References

- **Blake3 paper**: https://github.com/BLAKE3-team/BLAKE3/blob/master/blake3_specs.pdf
- **Blake3 Rust crate source**: https://github.com/BLAKE3-team/BLAKE3/tree/master/src
- **SP1 repository**: https://github.com/succinctlabs/sp1
- **SP1 SHA-256 chip** (primary reference): `crates/core/machine/src/chips/precompiles/sha256/`
- **SP1 precompiles docs**: https://docs.succinct.xyz/docs/sp1/writing-programs/precompiles
- **Plonky3** (SP1's backend): https://github.com/Plonky3/Plonky3
- **sp1-patches org**: https://github.com/sp1-patches
- **Archived Blake3 patch** (placeholder, no actual SP1 code): https://github.com/sp1-patches/BLAKE3
- **KERI SAID specification**: https://trustoverip.github.io/tswg-keri-specification/#said-fields
- **evm-backer project** (consumer of this precompile): the repo this document lives in

---

## 12. Acceptance Criteria

The implementation is complete when:

- [ ] `blake3::hash(b"hello world")` inside an SP1 guest produces the correct output
- [ ] All official Blake3 test vectors pass in the executor's native implementation
- [ ] The constraint system (AIR) produces no failures on valid witness values
- [ ] The constraint system rejects a witness with a corrupted XOR output
- [ ] The constraint system rejects a witness with a corrupted rotation output
- [ ] SP1 mock proving works end-to-end with the patched `blake3` crate
- [ ] SP1 CPU proving produces a Groth16 proof verifiable by `SP1VerifierGroth16.sol`
- [ ] Cycle count with precompile is ≥ 50× lower than without, for a 64-byte input
- [ ] The implementation passes SP1's existing test suite (`cargo test -p sp1-core-machine`)
- [ ] A PR is open on `succinctlabs/sp1` with the above evidence

---

*This document was written in the context of the `evm-backer` project
(an EVM Ledger Registrar Backer for KERI) but the Blake3 precompile is a
standalone contribution to the SP1 ecosystem.*
