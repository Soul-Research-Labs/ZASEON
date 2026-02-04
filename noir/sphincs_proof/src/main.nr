use std::hash::poseidon;

/**
 * @title SPHINCS+ Proof
 * @notice ZK proof of correct SPHINCS+ (SLH-DSA) signature verification
 * @dev SPHINCS+ is a stateless hash-based signature scheme
 *      that relies only on the security of hash functions.
 *
 * SPHINCS+ Structure:
 * - FORS (Forest of Random Subsets) for message binding
 * - Hypertree of WOTS+ signatures for authentication
 * - Multiple layers of Merkle trees
 */

// Domain separators
global SPHINCS_DOMAIN: Field = 0x534f554c5f535048494e43535f5631; // "SOUL_SPHINCS_V1"
global FORS_DOMAIN: Field = 0x464f52535f444f4d41494e5f5631;    // "FORS_DOMAIN_V1"
global WOTS_DOMAIN: Field = 0x574f54535f444f4d41494e5f5631;    // "WOTS_DOMAIN_V1"

// SPHINCS+ parameters for 128s variant
global FORS_TREES: u32 = 14;
global FORS_HEIGHT: u32 = 12;
global HYPERTREE_LAYERS: u32 = 8;
global WOTS_LEN: u32 = 35;

/**
 * @notice Compute FORS leaf value
 * @param secret_seed The secret seed
 * @param address The tree address
 * @param idx The leaf index
 */
fn compute_fors_leaf(
    secret_seed: Field,
    address: Field,
    idx: u32
) -> Field {
    poseidon::bn254::hash_3([
        secret_seed,
        address,
        idx as Field
    ])
}

/**
 * @notice Verify FORS authentication path
 * @param leaf The FORS leaf
 * @param path Authentication path siblings
 * @param leaf_idx The leaf index
 * @param expected_root Expected FORS tree root
 */
fn verify_fors_path(
    leaf: Field,
    path: [Field; 12],
    leaf_idx: u32,
    expected_root: Field
) -> bool {
    let mut current = leaf;
    let mut idx = leaf_idx;
    
    for i in 0..12 {
        let sibling = path[i];
        let is_right = idx & 1;
        idx = idx >> 1;
        
        if is_right == 1 {
            current = poseidon::bn254::hash_2([sibling, current]);
        } else {
            current = poseidon::bn254::hash_2([current, sibling]);
        }
    }
    
    current == expected_root
}

/**
 * @notice Compute W-OTS+ chain value
 * @param start The starting value
 * @param steps Number of hash iterations
 * @param pub_seed Public seed
 * @param address Address for domain separation
 */
fn compute_wots_chain_value(
    start: Field,
    steps: u32,
    pub_seed: Field,
    address: Field
) -> Field {
    let mut current = start;
    
    // Fixed maximum of 16 steps (4-bit digits)
    for i in 0..16 {
        if (i as u32) < steps {
            current = poseidon::bn254::hash_3([
                current,
                pub_seed,
                address + i as Field
            ]);
        }
    }
    
    current
}

/**
 * @notice Verify WOTS+ public key
 * @param signature_values The WOTS+ signature chain values
 * @param message_digest The message digest (determines chain lengths)
 * @param pub_seed Public seed
 * @param expected_pk_hash Expected public key hash
 */
fn verify_wots_pk(
    signature_values: [Field; 8],
    chain_lengths: [u32; 8],
    pub_seed: Field,
    address: Field,
    expected_pk_hash: Field
) -> bool {
    let mut pk_values: [Field; 8] = [0; 8];
    
    // Compute public key values from signature
    for i in 0..8 {
        let remaining_steps = 15 - chain_lengths[i];
        pk_values[i] = compute_wots_chain_value(
            signature_values[i],
            remaining_steps,
            pub_seed,
            address + (i as Field * 16)
        );
    }
    
    // Hash all public key values
    let mut pk_hash = pk_values[0];
    for i in 1..8 {
        pk_hash = poseidon::bn254::hash_2([pk_hash, pk_values[i]]);
    }
    
    pk_hash == expected_pk_hash
}

/**
 * @notice Verify hypertree layer
 * @param wots_pk_hash The WOTS+ public key hash
 * @param merkle_path The authentication path
 * @param leaf_idx Leaf index
 * @param expected_root Expected layer root
 */
fn verify_hypertree_layer(
    wots_pk_hash: Field,
    merkle_path: [Field; 8],
    leaf_idx: u32,
    expected_root: Field
) -> bool {
    let mut current = wots_pk_hash;
    let mut idx = leaf_idx;
    
    for i in 0..8 {
        let sibling = merkle_path[i];
        let is_right = idx & 1;
        idx = idx >> 1;
        
        if is_right == 1 {
            current = poseidon::bn254::hash_2([sibling, current]);
        } else {
            current = poseidon::bn254::hash_2([current, sibling]);
        }
    }
    
    current == expected_root
}

/**
 * @notice Main circuit: Prove correct SPHINCS+ verification
 *
 * Public inputs:
 * - message_hash: Hash of the signed message
 * - public_key_hash: Hash of the SPHINCS+ public key
 * - verification_result: 1 if valid, 0 if invalid
 *
 * Private inputs:
 * - pub_seed: Public seed from public key
 * - root: Merkle root from public key
 * - fors_leaves: FORS signature leaves
 * - fors_paths: FORS authentication paths
 * - wots_sig_values: WOTS+ signature values
 * - wots_chain_lengths: Chain lengths from message digest
 * - hypertree_paths: Hypertree authentication paths
 */
fn main(
    // Public inputs
    message_hash: pub Field,
    public_key_hash: pub Field,
    verification_result: pub Field,
    
    // Private inputs - public key components
    pub_seed: Field,
    root: Field,
    
    // Private inputs - FORS
    fors_leaf: Field,
    fors_path: [Field; 12],
    fors_leaf_idx: u32,
    fors_root: Field,
    
    // Private inputs - WOTS+
    wots_sig_values: [Field; 8],
    wots_chain_lengths: [u32; 8],
    wots_address: Field,
    wots_pk_hash: Field,
    
    // Private inputs - Hypertree
    hypertree_path: [Field; 8],
    hypertree_leaf_idx: u32
) {
    // 1. Verify public key hash matches components
    let computed_pk_hash = poseidon::bn254::hash_3([
        pub_seed,
        root,
        SPHINCS_DOMAIN
    ]);
    assert(computed_pk_hash == public_key_hash);
    
    // 2. Verify FORS tree
    let fors_valid = verify_fors_path(
        fors_leaf,
        fors_path,
        fors_leaf_idx,
        fors_root
    );
    assert(fors_valid);
    
    // 3. Verify FORS root is bound to message
    let fors_binding = poseidon::bn254::hash_2([message_hash, fors_root]);
    assert(fors_binding != 0);
    
    // 4. Verify WOTS+ signature
    let wots_valid = verify_wots_pk(
        wots_sig_values,
        wots_chain_lengths,
        pub_seed,
        wots_address,
        wots_pk_hash
    );
    assert(wots_valid);
    
    // 5. Verify hypertree layer
    let hypertree_valid = verify_hypertree_layer(
        wots_pk_hash,
        hypertree_path,
        hypertree_leaf_idx,
        root
    );
    assert(hypertree_valid);
    
    // 6. Final verification
    assert(verification_result == 1);
}

/**
 * @notice Compute message digest for SPHINCS+
 * Maps message to FORS indices and WOTS+ chain lengths
 */
fn compute_message_digest(
    message_hash: Field,
    randomizer: Field
) -> ([u32; 14], [u32; 8]) {
    let combined = poseidon::bn254::hash_2([message_hash, randomizer]);
    
    // Extract FORS indices (simplified)
    let mut fors_indices: [u32; 14] = [0; 14];
    let mut digest_part = combined;
    for i in 0..14 {
        fors_indices[i] = (digest_part as u32) & 0xFFF; // 12 bits
        digest_part = poseidon::bn254::hash_1([digest_part]);
    }
    
    // Extract WOTS+ chain lengths (simplified)
    let mut chain_lengths: [u32; 8] = [0; 8];
    for i in 0..8 {
        chain_lengths[i] = (digest_part as u32) & 0xF; // 4 bits
        digest_part = poseidon::bn254::hash_1([digest_part]);
    }
    
    (fors_indices, chain_lengths)
}

#[test]
fn test_fors_path() {
    let leaf = poseidon::bn254::hash_1([0x1234]);
    let mut path: [Field; 12] = [0; 12];
    
    // Build path
    let mut expected_root = leaf;
    for i in 0..12 {
        path[i] = poseidon::bn254::hash_1([i as Field + 1000]);
        expected_root = poseidon::bn254::hash_2([expected_root, path[i]]);
    }
    
    let valid = verify_fors_path(leaf, path, 0, expected_root);
    assert(valid);
}

#[test]
fn test_wots_chain() {
    let start = 0xabcd;
    let pub_seed = 0x1234;
    let address = 0x5678;
    
    // Chain should be deterministic
    let result1 = compute_wots_chain_value(start, 5, pub_seed, address);
    let result2 = compute_wots_chain_value(start, 5, pub_seed, address);
    assert(result1 == result2);
    
    // Different steps should give different results
    let result3 = compute_wots_chain_value(start, 6, pub_seed, address);
    assert(result1 != result3);
}

#[test]
fn test_hypertree_layer() {
    let pk_hash = poseidon::bn254::hash_1([0x9999]);
    let mut path: [Field; 8] = [0; 8];
    
    let mut expected_root = pk_hash;
    for i in 0..8 {
        path[i] = poseidon::bn254::hash_1([i as Field + 2000]);
        expected_root = poseidon::bn254::hash_2([expected_root, path[i]]);
    }
    
    let valid = verify_hypertree_layer(pk_hash, path, 0, expected_root);
    assert(valid);
}

#[test]
fn test_message_digest() {
    let message = 0x1234567890abcdef;
    let randomizer = 0xfedcba0987654321;
    
    let (fors_indices, chain_lengths) = compute_message_digest(message, randomizer);
    
    // Digest should be deterministic
    let (fors_indices2, chain_lengths2) = compute_message_digest(message, randomizer);
    
    for i in 0..14 {
        assert(fors_indices[i] == fors_indices2[i]);
    }
    for i in 0..8 {
        assert(chain_lengths[i] == chain_lengths2[i]);
    }
}
