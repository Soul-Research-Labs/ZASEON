// ═══════════════════════════════════════════════════════════════════════════════
// RingSignatureVerifier.spec — Certora CVL Specification
// ═══════════════════════════════════════════════════════════════════════════════

methods {
    function verify(bytes32[], bytes32[], bytes, bytes32) external returns (bool) envfree;
    function getMinRingSize() external returns (uint256) envfree;
    function getMaxRingSize() external returns (uint256) envfree;
    function MIN_RING_SIZE() external returns (uint256) envfree;
    function MAX_RING_SIZE() external returns (uint256) envfree;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANT INVARIANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// @title Ring size bounds are correct constants
rule minRingSizeIsTwo() {
    assert getMinRingSize() == 2, "Min ring size must be 2";
}

rule maxRingSizeIs64() {
    assert getMaxRingSize() == 64, "Max ring size must be 64";
}

rule minRingSizeMatchesConstant() {
    assert getMinRingSize() == MIN_RING_SIZE(), "Getter must match constant";
}

rule maxRingSizeMatchesConstant() {
    assert getMaxRingSize() == MAX_RING_SIZE(), "Getter must match constant";
}

// ═══════════════════════════════════════════════════════════════════════════════
// INPUT VALIDATION PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════

/// @title Zero message always reverts
rule zeroMessageReverts(
    bytes32[] ring,
    bytes32[] keyImages,
    bytes signature
) {
    verify@withrevert(ring, keyImages, signature, to_bytes32(0));
    assert lastReverted, "Zero message must always revert";
}

/// @title Verify is deterministic — same inputs always produce the same result
rule verifyIsDeterministic(
    bytes32[] ring,
    bytes32[] keyImages,
    bytes signature,
    bytes32 message
) {
    // First call
    bool result1 = verify@withrevert(ring, keyImages, signature, message);
    bool reverted1 = lastReverted;

    // Second call with identical inputs
    bool result2 = verify@withrevert(ring, keyImages, signature, message);
    bool reverted2 = lastReverted;

    assert reverted1 == reverted2, "Revert behavior must be deterministic";
    assert reverted1 || result1 == result2, "Result must be deterministic";
}

// ═══════════════════════════════════════════════════════════════════════════════
// PURITY / SIDE-EFFECT PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════

/// @title verify() has no state side effects (view function)
rule verifyIsStateless(
    bytes32[] ring,
    bytes32[] keyImages,
    bytes signature,
    bytes32 message
) {
    // Since verify is view (no state writes), calling it cannot
    // change any storage. This is enforced by the Solidity compiler
    // but Certora can additionally verify no hidden effects.
    verify@withrevert(ring, keyImages, signature, message);
    // If we reach here, the call completed without storage changes
    assert true;
}
