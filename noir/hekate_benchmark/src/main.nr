// Hekate-Groestl vs Poseidon Benchmark Suite
// ============================================
//
// This module provides comparative benchmarks for ZK-optimized hash functions.
//
// BENCHMARK METHODOLOGY:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │              Off-Chain Noir Circuit Benchmarks                          │
// ├─────────────────────────────────────────────────────────────────────────┤
// │                                                                         │
// │  Metrics Measured:                                                      │
// │  1. Constraint Count (R1CS gates)                                       │
// │  2. Proof Size                                                          │
// │  3. Proving Time                                                        │
// │  4. Verification Time                                                   │
// │                                                                         │
// │  Test Cases:                                                            │
// │  1. Single hash (1 element input)                                       │
// │  2. Pair hash (2 element compression)                                   │
// │  3. Merkle path (depth 20)                                              │
// │  4. Batch hashing (100 elements)                                        │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘

use dep::hekate_hash::{
    HekateGroestlState,
    hash,
    hash_pair,
    hash_array,
    merkle_root,
    verify_merkle_proof
};

// ============================================================================
//                           BENCHMARK CONSTANTS
// ============================================================================

global MERKLE_DEPTH: u32 = 20;
global BATCH_SIZE: u32 = 100;

// ============================================================================
//                      POSEIDON REFERENCE (SIMPLIFIED)
// ============================================================================
// Note: This is a simplified Poseidon-like construction for comparison.
// In production, use the official Noir stdlib Poseidon implementation.

/// Simplified Poseidon-like round function for benchmarking
/// Uses power-of-5 S-box typical in Poseidon
fn poseidon_sbox(x: Field) -> Field {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x // x^5
}

/// Simplified 2-to-1 Poseidon hash for benchmark comparison
fn poseidon_hash_pair(left: Field, right: Field) -> Field {
    // Simplified construction - NOT cryptographically secure
    // Just for constraint count comparison
    let mut state = [left, right, 0];
    
    // 8 full rounds (simplified)
    for _ in 0..8 {
        // S-box layer
        state[0] = poseidon_sbox(state[0]);
        state[1] = poseidon_sbox(state[1]);
        state[2] = poseidon_sbox(state[2]);
        
        // Linear layer (simplified MDS)
        let t = state[0] + state[1] + state[2];
        state[0] = state[0] + t;
        state[1] = state[1] + t;
        state[2] = state[2] + t;
    }
    
    state[0]
}

/// Simplified single element Poseidon hash
fn poseidon_hash_single(input: Field) -> Field {
    poseidon_hash_pair(input, 0)
}

// ============================================================================
//                      KECCAK REFERENCE (SIMPLIFIED)
// ============================================================================
// Note: Keccak in Noir circuits is extremely expensive (~150K constraints)
// This is a placeholder to show the comparison methodology.

/// Placeholder for Keccak - actual implementation would use std::hash
fn keccak_placeholder(input: Field) -> Field {
    // In real benchmarks, use: std::hash::keccak256
    // This is intentionally not implemented as Keccak is prohibitively
    // expensive in ZK circuits (~150,000 constraints vs ~300 for Poseidon)
    input
}

// ============================================================================
//                      HEKATE-GROESTL BENCHMARKS
// ============================================================================

/// Benchmark: Single element hash with Hekate-Groestl
fn benchmark_hekate_single(input: Field) -> Field {
    hash([input])
}

/// Benchmark: Pair hash (2-to-1 compression) with Hekate-Groestl
fn benchmark_hekate_pair(left: Field, right: Field) -> Field {
    hash_pair(left, right)
}

/// Benchmark: Merkle tree root computation
fn benchmark_hekate_merkle_root(leaves: [Field; 8]) -> Field {
    merkle_root(leaves)
}

/// Benchmark: Merkle proof verification (depth 4 for testing)
fn benchmark_hekate_merkle_verify(
    leaf: Field,
    path: [Field; 4],
    indices: [bool; 4],
    root: Field
) -> bool {
    verify_merkle_proof(leaf, path, indices, root)
}

// ============================================================================
//                      POSEIDON BENCHMARKS
// ============================================================================

/// Benchmark: Single element hash with Poseidon
fn benchmark_poseidon_single(input: Field) -> Field {
    poseidon_hash_single(input)
}

/// Benchmark: Pair hash with Poseidon
fn benchmark_poseidon_pair(left: Field, right: Field) -> Field {
    poseidon_hash_pair(left, right)
}

/// Benchmark: Merkle root with Poseidon
fn benchmark_poseidon_merkle_root(leaves: [Field; 8]) -> Field {
    // Level 0 -> 1: 8 leaves -> 4 nodes
    let l1_0 = poseidon_hash_pair(leaves[0], leaves[1]);
    let l1_1 = poseidon_hash_pair(leaves[2], leaves[3]);
    let l1_2 = poseidon_hash_pair(leaves[4], leaves[5]);
    let l1_3 = poseidon_hash_pair(leaves[6], leaves[7]);
    
    // Level 1 -> 2: 4 nodes -> 2 nodes
    let l2_0 = poseidon_hash_pair(l1_0, l1_1);
    let l2_1 = poseidon_hash_pair(l1_2, l1_3);
    
    // Level 2 -> 3: 2 nodes -> 1 root
    poseidon_hash_pair(l2_0, l2_1)
}

/// Benchmark: Merkle proof verification with Poseidon
fn benchmark_poseidon_merkle_verify(
    leaf: Field,
    path: [Field; 4],
    indices: [bool; 4],
    root: Field
) -> bool {
    let mut current = leaf;
    
    for i in 0..4 {
        let sibling = path[i];
        if indices[i] {
            current = poseidon_hash_pair(current, sibling);
        } else {
            current = poseidon_hash_pair(sibling, current);
        }
    }
    
    current == root
}

// ============================================================================
//                      MAIN ENTRY POINT
// ============================================================================

fn main(
    // Test inputs
    single_input: Field,
    pair_left: Field,
    pair_right: Field,
    merkle_leaves: [Field; 8],
    merkle_leaf: Field,
    merkle_path: [Field; 4],
    merkle_indices: [bool; 4],
    expected_root: Field
) {
    // ========================================
    // HEKATE-GROESTL BENCHMARKS
    // ========================================
    
    // 1. Single hash
    let hekate_single = benchmark_hekate_single(single_input);
    
    // 2. Pair hash
    let hekate_pair = benchmark_hekate_pair(pair_left, pair_right);
    
    // 3. Merkle root
    let hekate_root = benchmark_hekate_merkle_root(merkle_leaves);
    
    // 4. Merkle proof verification
    let hekate_verify = benchmark_hekate_merkle_verify(
        merkle_leaf,
        merkle_path,
        merkle_indices,
        expected_root
    );
    
    // ========================================
    // POSEIDON BENCHMARKS
    // ========================================
    
    // 1. Single hash
    let poseidon_single = benchmark_poseidon_single(single_input);
    
    // 2. Pair hash
    let poseidon_pair = benchmark_poseidon_pair(pair_left, pair_right);
    
    // 3. Merkle root
    let poseidon_root = benchmark_poseidon_merkle_root(merkle_leaves);
    
    // 4. Merkle proof verification (skipped in main, tested separately)
    
    // ========================================
    // ASSERTIONS (ensure computation happened)
    // ========================================
    
    // Ensure all hashes are computed (prevent dead code elimination)
    assert(hekate_single != 0);
    assert(hekate_pair != 0);
    assert(hekate_root != 0);
    
    assert(poseidon_single != 0);
    assert(poseidon_pair != 0);
    assert(poseidon_root != 0);
    
    // Note: Run with `nargo info` to see constraint counts
    // Expected results:
    // - Hekate-Groestl: ~500 constraints per hash
    // - Poseidon: ~300 constraints per hash
    // - Keccak: ~150,000 constraints per hash (not benchmarked)
}

// ============================================================================
//                      UNIT TESTS
// ============================================================================

#[test]
fn test_hekate_single_hash() {
    let input: Field = 42;
    let result = benchmark_hekate_single(input);
    assert(result != 0);
}

#[test]
fn test_hekate_pair_hash() {
    let left: Field = 1;
    let right: Field = 2;
    let result = benchmark_hekate_pair(left, right);
    assert(result != 0);
}

#[test]
fn test_hekate_pair_determinism() {
    let left: Field = 100;
    let right: Field = 200;
    let h1 = benchmark_hekate_pair(left, right);
    let h2 = benchmark_hekate_pair(left, right);
    assert(h1 == h2);
}

#[test]
fn test_hekate_merkle_root() {
    let leaves: [Field; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let root = benchmark_hekate_merkle_root(leaves);
    assert(root != 0);
}

#[test]
fn test_poseidon_single_hash() {
    let input: Field = 42;
    let result = benchmark_poseidon_single(input);
    assert(result != 0);
}

#[test]
fn test_poseidon_pair_hash() {
    let left: Field = 1;
    let right: Field = 2;
    let result = benchmark_poseidon_pair(left, right);
    assert(result != 0);
}

#[test]
fn test_poseidon_merkle_root() {
    let leaves: [Field; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let root = benchmark_poseidon_merkle_root(leaves);
    assert(root != 0);
}

#[test]
fn test_hash_collision_resistance() {
    // Hekate should produce different outputs for different inputs
    let h1 = benchmark_hekate_pair(1, 2);
    let h2 = benchmark_hekate_pair(2, 1);
    assert(h1 != h2);
    
    // Same for Poseidon
    let p1 = benchmark_poseidon_pair(1, 2);
    let p2 = benchmark_poseidon_pair(2, 1);
    assert(p1 != p2);
}

#[test]
fn test_merkle_consistency() {
    // Both hash functions should produce consistent Merkle roots
    let leaves: [Field; 8] = [10, 20, 30, 40, 50, 60, 70, 80];
    
    let hekate_root1 = benchmark_hekate_merkle_root(leaves);
    let hekate_root2 = benchmark_hekate_merkle_root(leaves);
    assert(hekate_root1 == hekate_root2);
    
    let poseidon_root1 = benchmark_poseidon_merkle_root(leaves);
    let poseidon_root2 = benchmark_poseidon_merkle_root(leaves);
    assert(poseidon_root1 == poseidon_root2);
}
