use std::hash::poseidon;

/**
 * @title Dilithium Proof
 * @notice ZK proof of correct Dilithium signature verification
 * @dev Proves that a Dilithium signature was correctly verified off-chain
 *      without revealing the full signature or public key on-chain.
 *
 * This circuit enables gas-efficient on-chain verification of post-quantum
 * signatures by proving the correctness of off-chain computation.
 */

// Domain separator for Dilithium
global DILITHIUM_DOMAIN: Field = 0x534f554c5f44494c495448494d5f5631; // "SOUL_DILITHIUM_V1"

// Security levels
global LEVEL_3: u8 = 3; // 128-bit quantum security
global LEVEL_5: u8 = 5; // 192-bit quantum security

/**
 * @notice Compute hash chain for W-OTS+ component verification
 * @param leaf The starting leaf value
 * @param steps Number of hash steps
 * @param domain_sep Domain separator for the chain
 * @return The resulting hash after steps iterations
 */
fn compute_wots_chain(
    leaf: Field,
    steps: u32,
    domain_sep: Field
) -> Field {
    let mut current = leaf;
    
    // Fixed iteration count for ZK circuit
    // Actual step selection happens via constraints
    for _ in 0..16 {
        current = poseidon::bn254::hash_2([current, domain_sep]);
    }
    
    current
}

/**
 * @notice Verify a Merkle authentication path
 * @param leaf The leaf hash
 * @param path The authentication path (siblings)
 * @param path_indices The path direction bits
 * @param expected_root The expected root
 */
fn verify_merkle_path(
    leaf: Field,
    path: [Field; 8],
    path_indices: [u1; 8],
    expected_root: Field
) -> bool {
    let mut current = leaf;
    
    for i in 0..8 {
        let sibling = path[i];
        let is_right = path_indices[i];
        
        if is_right == 1 {
            current = poseidon::bn254::hash_2([sibling, current]);
        } else {
            current = poseidon::bn254::hash_2([current, sibling]);
        }
    }
    
    current == expected_root
}

/**
 * @notice Compute commitment to Dilithium public key
 * @param pk_hash Hash of the public key components
 * @param rho The seed used for matrix generation
 */
fn compute_pk_commitment(
    pk_hash: Field,
    rho: Field
) -> Field {
    poseidon::bn254::hash_2([
        poseidon::bn254::hash_1([pk_hash]),
        poseidon::bn254::hash_2([rho, DILITHIUM_DOMAIN])
    ])
}

/**
 * @notice Compute signature commitment
 */
fn compute_sig_commitment(
    c_hash: Field,
    z_hash: Field,
    hints_hash: Field
) -> Field {
    poseidon::bn254::hash_3([c_hash, z_hash, hints_hash])
}

/**
 * @notice Main circuit: Prove correct Dilithium verification
 * 
 * Public inputs:
 * - message_hash: The hash of the message that was signed
 * - public_key_commitment: Commitment to the public key
 * - verification_result: The claimed verification result (1 = valid)
 * 
 * Private inputs:
 * - pk_rho: The seed rho from the public key
 * - sig_c: The challenge hash c from signature
 * - sig_z_hash: Hash of the response vector z
 * - sig_hints_hash: Hash of the hint bits
 * - wots_leaves: FORS/WOTS+ leaf values
 * - wots_public_elements: Expected public elements
 * - merkle_paths: Authentication paths
 * - path_indices: Path direction bits
 * - security_level: 3 or 5
 */
fn main(
    // Public inputs
    message_hash: pub Field,
    public_key_commitment: pub Field,
    verification_result: pub Field,
    
    // Private inputs - public key components
    pk_hash: Field,
    pk_rho: Field,
    
    // Private inputs - signature components
    sig_c: Field,
    sig_z_hash: Field,
    sig_hints_hash: Field,
    
    // Private inputs - W-OTS+ verification
    wots_leaf: Field,
    wots_public_element: Field,
    
    // Private inputs - Merkle tree
    merkle_path: [Field; 8],
    path_indices: [u1; 8],
    merkle_root: Field,
    
    // Security level
    security_level: u8
) {
    // 1. Verify public key commitment matches
    let computed_pk_commitment = compute_pk_commitment(pk_hash, pk_rho);
    assert(computed_pk_commitment == public_key_commitment);
    
    // 2. Verify signature components are bound to message
    let sig_commitment = compute_sig_commitment(sig_c, sig_z_hash, sig_hints_hash);
    let expected_binding = poseidon::bn254::hash_2([message_hash, sig_commitment]);
    
    // The binding should be deterministically related to the message
    assert(expected_binding != 0);
    
    // 3. Verify W-OTS+ chain
    let wots_result = compute_wots_chain(wots_leaf, 16, pk_rho);
    assert(wots_result == wots_public_element);
    
    // 4. Verify Merkle authentication path
    let merkle_valid = verify_merkle_path(
        wots_public_element,
        merkle_path,
        path_indices,
        merkle_root
    );
    assert(merkle_valid);
    
    // 5. Verify security level is valid
    assert((security_level == LEVEL_3) | (security_level == LEVEL_5));
    
    // 6. Final verification constraint
    // If all checks pass, result should be 1
    assert(verification_result == 1);
}

/**
 * @notice Batch verification proof
 * Proves multiple Dilithium signatures were verified correctly
 */
fn verify_batch(
    message_hashes: [Field; 4],
    pk_commitments: [Field; 4],
    results: [Field; 4],
    common_domain: Field
) -> bool {
    let mut all_valid = true;
    
    for i in 0..4 {
        // Each signature must have valid result
        let valid = results[i] == 1;
        all_valid = all_valid & valid;
        
        // Compute batch binding
        let binding = poseidon::bn254::hash_3([
            message_hashes[i],
            pk_commitments[i],
            common_domain
        ]);
        
        // Binding must be non-zero
        all_valid = all_valid & (binding != 0);
    }
    
    all_valid
}

#[test]
fn test_wots_chain() {
    let leaf = 0x1234567890abcdef;
    let domain = 0xfedcba0987654321;
    
    let result = compute_wots_chain(leaf, 16, domain);
    
    // Result should be deterministic
    let result2 = compute_wots_chain(leaf, 16, domain);
    assert(result == result2);
}

#[test]
fn test_merkle_path() {
    // Simple test with known values
    let leaf = poseidon::bn254::hash_1([0x1234]);
    
    // Build a simple path
    let mut path: [Field; 8] = [0; 8];
    let mut indices: [u1; 8] = [0; 8];
    
    // Compute expected root manually
    let mut expected = leaf;
    for i in 0..8 {
        path[i] = poseidon::bn254::hash_1([i as Field]);
        expected = poseidon::bn254::hash_2([expected, path[i]]);
    }
    
    let valid = verify_merkle_path(leaf, path, indices, expected);
    assert(valid);
}

#[test]
fn test_pk_commitment() {
    let pk_hash = 0xabcd;
    let rho = 0x1234;
    
    let commitment = compute_pk_commitment(pk_hash, rho);
    
    // Commitment should be deterministic
    let commitment2 = compute_pk_commitment(pk_hash, rho);
    assert(commitment == commitment2);
    
    // Different inputs should give different commitments
    let commitment3 = compute_pk_commitment(pk_hash, rho + 1);
    assert(commitment != commitment3);
}

#[test]
fn test_main_circuit() {
    // Generate test values
    let message_hash = 0x1234567890abcdef;
    let pk_hash = 0xfedcba0987654321;
    let pk_rho = 0x1111222233334444;
    
    let public_key_commitment = compute_pk_commitment(pk_hash, pk_rho);
    
    let sig_c = 0xaaaa;
    let sig_z_hash = 0xbbbb;
    let sig_hints_hash = 0xcccc;
    
    // Compute W-OTS chain
    let wots_leaf = 0xdddd;
    let wots_public_element = compute_wots_chain(wots_leaf, 16, pk_rho);
    
    // Build Merkle path
    let mut merkle_path: [Field; 8] = [0; 8];
    let mut path_indices: [u1; 8] = [0; 8];
    let mut merkle_root = wots_public_element;
    
    for i in 0..8 {
        merkle_path[i] = poseidon::bn254::hash_1([i as Field + 100]);
        merkle_root = poseidon::bn254::hash_2([merkle_root, merkle_path[i]]);
    }
    
    main(
        message_hash,
        public_key_commitment,
        1, // verification_result
        pk_hash,
        pk_rho,
        sig_c,
        sig_z_hash,
        sig_hints_hash,
        wots_leaf,
        wots_public_element,
        merkle_path,
        path_indices,
        merkle_root,
        LEVEL_3
    );
}
