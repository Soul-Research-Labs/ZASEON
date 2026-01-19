use std::hash::poseidon;

/// @title CrossDomainNullifierCircuit
/// @notice Circuit for domain-separated nullifiers (CDNA)
/// @dev Nullifiers that compose algebraically across chains, epochs, and applications
///      N = H(secret, app_id, chain_id, epoch, transition_id)
/// 
/// Enables cross-chain double-spend prevention without global state.

/// CDNA version prefix (ASCII for "CDNA_v1" padded)
global CDNA_PREFIX: Field = 0x434e4441_76310000;

struct DomainContext {
    chain_id: Field,
    app_id: Field,
    epoch_id: Field,
}

/// Compute domain separator for nullifier scope
fn compute_domain_separator(domain: DomainContext) -> Field {
    poseidon::bn254::hash_4([CDNA_PREFIX, domain.chain_id, domain.app_id, domain.epoch_id])
}

/// Compute a domain-separated nullifier
fn compute_domain_nullifier(
    secret: Field,
    domain: DomainContext,
    transition_id: Field
) -> Field {
    let separator = compute_domain_separator(domain);
    poseidon::bn254::hash_4([secret, separator, transition_id, 0])
}

/// Verify a domain nullifier
fn verify_domain_nullifier(
    expected_nullifier: Field,
    secret: Field,
    domain: DomainContext,
    transition_id: Field
) -> bool {
    let computed = compute_domain_nullifier(secret, domain, transition_id);
    computed == expected_nullifier
}

/// Derive a child secret for cross-domain derivation
fn derive_child_secret(
    parent_secret: Field,
    source_nullifier: Field,
    target_chain_id: Field
) -> Field {
    poseidon::bn254::hash_4([parent_secret, source_nullifier, target_chain_id, 0])
}

/// Verify cross-domain nullifier derivation
fn verify_cross_domain_derivation(
    // Source domain
    source_domain: DomainContext,
    source_nullifier: Field,
    // Target domain
    target_domain: DomainContext,
    target_nullifier: Field,
    target_transition_id: Field,
    // Private inputs
    parent_secret: Field,
    derivation_nonce: Field
) -> bool {
    // Step 1: Verify source nullifier derivation
    let source_transition_id = poseidon::bn254::hash_1([derivation_nonce]);
    let computed_source = compute_domain_nullifier(
        parent_secret,
        source_domain,
        source_transition_id
    );
    let source_valid = computed_source == source_nullifier;
    
    // Step 2: Derive child secret for target domain
    let child_secret = derive_child_secret(
        parent_secret,
        source_nullifier,
        target_domain.chain_id
    );
    
    // Step 3: Verify target nullifier
    let computed_target = compute_domain_nullifier(
        child_secret,
        target_domain,
        target_transition_id
    );
    let target_valid = computed_target == target_nullifier;
    
    source_valid & target_valid
}

/// Verify cross-epoch evolution
fn verify_epoch_evolution(
    old_nullifier: Field,
    new_nullifier: Field,
    secret: Field,
    chain_id: Field,
    app_id: Field,
    old_epoch: Field,
    new_epoch: Field,
    transition_id: Field
) -> bool {
    let old_domain = DomainContext {
        chain_id,
        app_id,
        epoch_id: old_epoch
    };
    
    let new_domain = DomainContext {
        chain_id,
        app_id,
        epoch_id: new_epoch
    };
    
    // Verify old nullifier
    let old_valid = verify_domain_nullifier(old_nullifier, secret, old_domain, transition_id);
    
    // Verify new nullifier with evolved epoch
    let new_valid = verify_domain_nullifier(new_nullifier, secret, new_domain, transition_id);
    
    // Verify epoch increased
    let old_e: u64 = old_epoch as u64;
    let new_e: u64 = new_epoch as u64;
    let epoch_increased = new_e > old_e;
    
    old_valid & new_valid & epoch_increased
}

/// Main entry point
fn main(
    // Private inputs
    parent_secret: Field,
    derivation_nonce: Field,
    // Public inputs - source domain
    source_chain_id: pub Field,
    source_app_id: pub Field,
    source_epoch_id: pub Field,
    source_nullifier: pub Field,
    // Public inputs - target domain
    target_chain_id: pub Field,
    target_app_id: pub Field,
    target_epoch_id: pub Field,
    target_nullifier: pub Field,
    target_transition_id: pub Field
) -> pub bool {
    let source_domain = DomainContext {
        chain_id: source_chain_id,
        app_id: source_app_id,
        epoch_id: source_epoch_id
    };
    
    let target_domain = DomainContext {
        chain_id: target_chain_id,
        app_id: target_app_id,
        epoch_id: target_epoch_id
    };
    
    verify_cross_domain_derivation(
        source_domain,
        source_nullifier,
        target_domain,
        target_nullifier,
        target_transition_id,
        parent_secret,
        derivation_nonce
    )
}

#[test]
fn test_domain_separator() {
    let domain = DomainContext {
        chain_id: 1,
        app_id: 100,
        epoch_id: 1
    };
    
    let sep1 = compute_domain_separator(domain);
    let sep2 = compute_domain_separator(domain);
    
    // Same inputs should give same separator
    assert(sep1 == sep2);
}

#[test]
fn test_nullifier_derivation() {
    let secret = 0x1234;
    let domain = DomainContext {
        chain_id: 1,
        app_id: 100,
        epoch_id: 1
    };
    let transition_id = 42;
    
    let nullifier = compute_domain_nullifier(secret, domain, transition_id);
    
    assert(verify_domain_nullifier(nullifier, secret, domain, transition_id));
}

#[test]
fn test_different_domains_different_nullifiers() {
    let secret = 0x1234;
    let transition_id = 42;
    
    let domain1 = DomainContext { chain_id: 1, app_id: 100, epoch_id: 1 };
    let domain2 = DomainContext { chain_id: 137, app_id: 100, epoch_id: 1 };
    
    let null1 = compute_domain_nullifier(secret, domain1, transition_id);
    let null2 = compute_domain_nullifier(secret, domain2, transition_id);
    
    // Different chains should produce different nullifiers
    assert(null1 != null2);
}
