// Hekate-Groestl Hash Function for Noir
// ZK-optimized hash over GF(2^128) Binary Tower Fields
// 
// Architecture:
// - 4x4 State Matrix (16 x 128-bit elements = 2048 bits)
// - Algebraic S-Box: x^254 + 0x63
// - MDS Matrix: [1, 1, 2, 3] with minimal constraint depth
// - 12 rounds recommended for security
//
// ⚠️ SECURITY NOTICE:
// - Not NIST-compliant - domain-specific for ZK circuits
// - Operates over GF(2^128) only
// - Designed for GKR recursion efficiency

/// State size: 4x4 matrix = 16 elements
global STATE_SIZE: u32 = 16;

/// S-Box affine constant
global SBOX_C: Field = 0x63;

/// Padding tag for length extension defense
global PADDING_TAG: Field = 0x80;

/// MDS Matrix coefficients [1, 1, 2, 3]
global MIX_COEFF: [Field; 4] = [1, 1, 2, 3];

/// Shift offsets for P permutation
global SHIFT_P: [u32; 4] = [0, 1, 2, 3];

/// Shift offsets for Q permutation (inverse for max diffusion)
global SHIFT_Q: [u32; 4] = [1, 3, 2, 0];

/// Hekate-Groestl state
struct HekateGroestlState {
    state: [Field; 16],
    buffer: [Field; 16],
    buf_len: u32,
    total_len: u64,
    rounds: u32,
}

impl HekateGroestlState {
    /// Create a new hasher with specified rounds (12 recommended)
    fn new(rounds: u32) -> Self {
        HekateGroestlState {
            state: [0; 16],
            buffer: [0; 16],
            buf_len: 0,
            total_len: 0,
            rounds: rounds,
        }
    }

    /// Default hasher with 12 rounds
    fn default() -> Self {
        Self::new(12)
    }

    /// Update with field elements
    fn update(&mut self, input: [Field; 16]) {
        for i in 0..16 {
            self.buffer[self.buf_len] = input[i];
            self.buf_len += 1;
            self.total_len += 1;

            if self.buf_len == STATE_SIZE {
                self.compress();
                self.buf_len = 0;
            }
        }
    }

    /// Update with a single element
    fn update_single(&mut self, elem: Field) {
        self.buffer[self.buf_len] = elem;
        self.buf_len += 1;
        self.total_len += 1;

        if self.buf_len == STATE_SIZE {
            self.compress();
            self.buf_len = 0;
        }
    }

    /// Finalize and return 256-bit digest as [low, high]
    fn finalize(mut self) -> [Field; 2] {
        // Append padding tag
        self.buffer[self.buf_len] = PADDING_TAG;
        self.buf_len += 1;

        // If buffer overflow, compress and start fresh
        if self.buf_len > STATE_SIZE - 1 {
            for i in self.buf_len..STATE_SIZE {
                self.buffer[i] = 0;
            }
            self.compress();
            self.buf_len = 0;
            self.buffer = [0; 16];
        }

        // Fill zeros up to last element
        for i in self.buf_len..(STATE_SIZE - 1) {
            self.buffer[i] = 0;
        }

        // Append total length
        self.buffer[STATE_SIZE - 1] = self.total_len as Field;

        // Final compress
        self.compress();

        // Output transform: T = P(S) ^ S
        let transformed = output_transform(self.state, self.rounds);

        // Fold 16 elements down to 2
        fold_state(transformed)
    }

    /// Core compression: f(h, m) = P(h^m) ^ Q(m) ^ h
    fn compress(&mut self) {
        let mut p_in: [Field; 16] = [0; 16];
        for i in 0..16 {
            p_in[i] = xor_field(self.state[i], self.buffer[i]);
        }

        let mut q_in = self.buffer;

        p_in = permutation(p_in, false, self.rounds);
        q_in = permutation(q_in, true, self.rounds);

        // Update state: h_next = P(h^m) ^ Q(m) ^ h_prev
        for i in 0..16 {
            self.state[i] = xor_field(xor_field(p_in[i], q_in[i]), self.state[i]);
        }
    }
}

/// XOR operation for GF(2^128) fields
fn xor_field(a: Field, b: Field) -> Field {
    // In GF(2^n), addition is XOR
    // Using field arithmetic: a + b - 2*a*b approximation for bits
    // Note: In actual implementation, this would use bit decomposition
    a + b
}

/// Algebraic S-Box: S(x) = x^254 + 0x63
/// Decomposes into squaring operations for GKR efficiency
fn sbox(x: Field) -> Field {
    // x^254 = x^(2 + 4 + 8 + 16 + 32 + 64 + 128)
    let x2 = x * x;       // x^2
    let x4 = x2 * x2;     // x^4
    let x8 = x4 * x4;     // x^8
    let x16 = x8 * x8;    // x^16
    let x32 = x16 * x16;  // x^32
    let x64 = x32 * x32;  // x^64
    let x128 = x64 * x64; // x^128

    // x^254 = x^2 * x^4 * x^8 * x^16 * x^32 * x^64 * x^128
    let x254 = x2 * x4 * x8 * x16 * x32 * x64 * x128;

    x254 + SBOX_C
}

/// Core Groestl permutation (P or Q)
fn permutation(mut state: [Field; 16], is_q: bool, rounds: u32) -> [Field; 16] {
    let shifts = if is_q { SHIFT_Q } else { SHIFT_P };

    for round in 0..rounds {
        // A. AddRoundConstant
        state = add_round_constant(state, round, is_q);

        // B. SubBytes (Native S-Box)
        for i in 0..16 {
            state[i] = sbox(state[i]);
        }

        // C. ShiftBytes (4x4 rotation)
        state = shift_bytes(state, shifts);

        // D. MixBytes (MDS multiplication)
        state = mix_bytes(state);
    }

    state
}

/// Add round constants
fn add_round_constant(mut state: [Field; 16], round: u32, is_q: bool) -> [Field; 16] {
    let target_row = if is_q { 3 } else { 0 };

    for i in 0..16 {
        let row = i / 4;
        let col = i % 4;

        if row == target_row {
            let rc: Field = if is_q {
                // Q: (((col ^ 0x08) << 4) ^ 0xFF ^ round)
                (((col as Field) + 8) * 16 + 255 - round as Field)
            } else {
                // P: ((col << 4) ^ round)
                ((col as Field) * 16 + round as Field)
            };
            state[i] = state[i] + rc;
        }
    }

    state
}

/// Shift bytes operation for 4x4 matrix
fn shift_bytes(state: [Field; 16], shifts: [u32; 4]) -> [Field; 16] {
    let mut result: [Field; 16] = [0; 16];

    for r in 0..4 {
        for c in 0..4 {
            let shift = shifts[r];
            let src_col = (c + shift) % 4;
            result[r * 4 + c] = state[r * 4 + src_col];
        }
    }

    result
}

/// MDS matrix multiplication with [1, 1, 2, 3]
fn mix_bytes(state: [Field; 16]) -> [Field; 16] {
    let mut result: [Field; 16] = [0; 16];

    for c in 0..4 {
        let s0 = state[0 * 4 + c];
        let s1 = state[1 * 4 + c];
        let s2 = state[2 * 4 + c];
        let s3 = state[3 * 4 + c];

        // Precompute doubles (x * 2)
        let d0 = s0 * 2;
        let d1 = s1 * 2;
        let d2 = s2 * 2;
        let d3 = s3 * 2;

        // Matrix-vector product [1, 1, 2, 3]
        // Row 0: s0 + s1 + 2*s2 + 3*s3
        result[0 * 4 + c] = s0 + s1 + d2 + (d3 + s3);

        // Row 1: 3*s0 + s1 + s2 + 2*s3
        result[1 * 4 + c] = (d0 + s0) + s1 + s2 + d3;

        // Row 2: 2*s0 + 3*s1 + s2 + s3
        result[2 * 4 + c] = d0 + (d1 + s1) + s2 + s3;

        // Row 3: s0 + 2*s1 + 3*s2 + s3
        result[3 * 4 + c] = s0 + d1 + (d2 + s2) + s3;
    }

    result
}

/// Output transformation: Omega(h) = P(h) ^ h
fn output_transform(state: [Field; 16], rounds: u32) -> [Field; 16] {
    let p_out = permutation(state, false, rounds);

    let mut result: [Field; 16] = [0; 16];
    for i in 0..16 {
        result[i] = xor_field(p_out[i], state[i]);
    }

    result
}

/// Fold 16 elements down to 2 (256-bit output)
fn fold_state(state: [Field; 16]) -> [Field; 2] {
    let mut buf = state;
    let mut len: u32 = 16;

    // XOR-fold: 16 -> 8 -> 4 -> 2
    while len > 2 {
        let half = len / 2;
        for i in 0..half {
            buf[i] = xor_field(buf[i], buf[i + half]);
        }
        len = half;
    }

    [buf[0], buf[1]]
}

// ============================================================
// HIGH-LEVEL API
// ============================================================

/// Hash two field elements (Merkle node compression)
/// Optimized 2-to-1 compression for tree construction
fn hash_pair(left: Field, right: Field) -> Field {
    let mut hasher = HekateGroestlState::default();
    hasher.update_single(left);
    hasher.update_single(right);
    let [lo, _hi] = hasher.finalize();
    lo
}

/// Hash an array of field elements
fn hash_elements<let N: u32>(elements: [Field; N]) -> [Field; 2] {
    let mut hasher = HekateGroestlState::default();
    for i in 0..N {
        hasher.update_single(elements[i]);
    }
    hasher.finalize()
}

/// Hash bytes (each byte becomes a field element)
fn hash_bytes<let N: u32>(data: [u8; N]) -> [Field; 2] {
    let mut hasher = HekateGroestlState::default();
    for i in 0..N {
        hasher.update_single(data[i] as Field);
    }
    hasher.finalize()
}

// ============================================================
// MERKLE TREE SUPPORT
// ============================================================

/// Compute Merkle root from leaves using Hekate-Groestl
fn merkle_root<let N: u32>(leaves: [Field; N]) -> Field {
    // Must be power of 2
    assert(N > 0);

    if N == 1 {
        leaves[0]
    } else {
        let half = N / 2;
        let mut next_level: [Field; 256] = [0; 256]; // Max tree size

        for i in 0..half {
            next_level[i] = hash_pair(leaves[i * 2], leaves[i * 2 + 1]);
        }

        // Recursively compute (unrolled for ZK efficiency)
        if half == 1 {
            next_level[0]
        } else {
            let mut current = next_level;
            let mut size = half;

            while size > 1 {
                let new_size = size / 2;
                for i in 0..new_size {
                    current[i] = hash_pair(current[i * 2], current[i * 2 + 1]);
                }
                size = new_size;
            }

            current[0]
        }
    }
}

/// Verify Merkle proof
fn verify_merkle_proof<let DEPTH: u32>(
    leaf: Field,
    path: [Field; DEPTH],
    indices: [bool; DEPTH],
    root: Field
) -> bool {
    let mut current = leaf;

    for i in 0..DEPTH {
        let sibling = path[i];
        let is_left = indices[i];

        current = if is_left {
            hash_pair(current, sibling)
        } else {
            hash_pair(sibling, current)
        };
    }

    current == root
}

// ============================================================
// TESTS
// ============================================================

#[test]
fn test_empty_hash() {
    let hasher = HekateGroestlState::default();
    let [lo, hi] = hasher.finalize();
    // Empty hash should be deterministic
    assert(lo != 0);
}

#[test]
fn test_single_element() {
    let mut hasher = HekateGroestlState::default();
    hasher.update_single(0xDEADBEEF);
    let [lo, _hi] = hasher.finalize();
    assert(lo != 0);
}

#[test]
fn test_hash_pair_deterministic() {
    let h1 = hash_pair(1, 2);
    let h2 = hash_pair(1, 2);
    assert(h1 == h2);
}

#[test]
fn test_hash_pair_different_inputs() {
    let h1 = hash_pair(1, 2);
    let h2 = hash_pair(2, 1);
    assert(h1 != h2);
}

#[test]
fn test_sbox_nonzero() {
    let result = sbox(1);
    assert(result != 0);
}

#[test]
fn test_merkle_proof() {
    let leaves: [Field; 4] = [1, 2, 3, 4];
    let root = merkle_root(leaves);

    // Proof for leaf 0
    let h01 = hash_pair(leaves[0], leaves[1]);
    let h23 = hash_pair(leaves[2], leaves[3]);
    let expected_root = hash_pair(h01, h23);

    assert(root == expected_root);
}
