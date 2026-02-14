// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/libraries/PoseidonT3.sol";
import "../../contracts/libraries/PoseidonYul.sol";

/// @dev Harness for the internal PoseidonT3.hash2
contract PoseidonT3Harness {
    function hash2(uint256 a, uint256 b) external pure returns (uint256) {
        return PoseidonT3.hash2(a, b);
    }
}

/// @dev Harness for the deprecated PoseidonYul.hash2 (now delegates to PoseidonT3)
contract PoseidonHarness {
    function hash2(uint256 a, uint256 b) external pure returns (uint256) {
        return PoseidonYul.hash2(a, b);
    }
}

contract PoseidonYulTest is Test {
    PoseidonHarness poseidon;
    PoseidonT3Harness poseidonT3;

    uint256 constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        poseidon = new PoseidonHarness();
        poseidonT3 = new PoseidonT3Harness();
    }

    /* ══════════════════════════════════════════════════
                     BASIC PROPERTIES
       ══════════════════════════════════════════════════ */

    function test_hash2_deterministic() public view {
        uint256 h1 = poseidon.hash2(1, 2);
        uint256 h2 = poseidon.hash2(1, 2);
        assertEq(h1, h2);
    }

    function test_hash2_nonZero() public view {
        uint256 h = poseidon.hash2(0, 0);
        assertGt(h, 0, "hash(0,0) should be non-zero");
    }

    function test_hash2_differentInputsDifferentOutputs() public view {
        uint256 h1 = poseidon.hash2(1, 2);
        uint256 h2 = poseidon.hash2(2, 1);
        assertTrue(h1 != h2, "hash2 should be order-dependent");
    }

    function test_hash2_resultInField() public view {
        uint256 h = poseidon.hash2(42, 99);
        assertLt(h, P, "result must be < P");
    }

    function test_hash2_zeroInputs() public view {
        uint256 h = poseidon.hash2(0, 0);
        assertLt(h, P);
    }

    function test_hash2_largeInputs() public view {
        uint256 h = poseidon.hash2(P - 1, P - 1);
        assertLt(h, P);
    }

    function test_hash2_oneOneVsOneTwo() public view {
        uint256 h1 = poseidon.hash2(1, 1);
        uint256 h2 = poseidon.hash2(1, 2);
        assertTrue(h1 != h2);
    }

    /* ══════════════════════════════════════════════════
                       FUZZ TESTS
       ══════════════════════════════════════════════════ */

    function testFuzz_hash2_resultInField(uint256 a, uint256 b) public view {
        uint256 h = poseidon.hash2(a, b);
        assertLt(h, P, "result must be in BN254 scalar field");
    }

    function testFuzz_hash2_deterministic(uint256 a, uint256 b) public view {
        assertEq(poseidon.hash2(a, b), poseidon.hash2(a, b));
    }

    function testFuzz_hash2_inputSensitivity(uint256 a) public view {
        vm.assume(a < P - 1);
        uint256 h1 = poseidon.hash2(a, 0);
        uint256 h2 = poseidon.hash2(a + 1, 0);
        assertTrue(h1 != h2, "incrementing input should change output");
    }

    /* ══════════════════════════════════════════════════
                     GAS BENCHMARK
       ══════════════════════════════════════════════════ */

    function test_hash2_gasUnder120k() public view {
        uint256 gasBefore = gasleft();
        poseidon.hash2(123, 456);
        uint256 gasUsed = gasBefore - gasleft();
        // PoseidonYul now delegates to full 65-round PoseidonT3
        // Gas budget increased from 25k to 120k for full security
        assertLt(gasUsed, 120_000, "gas too high");
    }

    /* ══════════════════════════════════════════════════
                    COLLISION RESISTANCE
       ══════════════════════════════════════════════════ */

    function test_hash2_noTrivialCollision() public view {
        // Check several small value pairs don't collide
        uint256 h00 = poseidon.hash2(0, 0);
        uint256 h01 = poseidon.hash2(0, 1);
        uint256 h10 = poseidon.hash2(1, 0);
        uint256 h11 = poseidon.hash2(1, 1);

        assertTrue(h00 != h01);
        assertTrue(h00 != h10);
        assertTrue(h00 != h11);
        assertTrue(h01 != h10);
        assertTrue(h01 != h11);
        assertTrue(h10 != h11);
    }

    /* ══════════════════════════════════════════════════
                    CONSTANT VERIFICATION
       ══════════════════════════════════════════════════ */

    function test_primeFieldModulus() public pure {
        assertEq(
            PoseidonYul.P,
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        );
    }

    /* ══════════════════════════════════════════════════
               POSEIDON T3 (FULL 65-ROUND) TESTS
       ══════════════════════════════════════════════════ */

    function test_T3_deterministic() public view {
        uint256 h1 = poseidonT3.hash2(1, 2);
        uint256 h2 = poseidonT3.hash2(1, 2);
        assertEq(h1, h2, "PoseidonT3 must be deterministic");
    }

    function test_T3_nonZero() public view {
        uint256 h = poseidonT3.hash2(0, 0);
        assertGt(h, 0, "PoseidonT3(0,0) should be non-zero");
    }

    function test_T3_resultInField() public view {
        uint256 h = poseidonT3.hash2(42, 99);
        assertLt(h, P, "PoseidonT3 result must be < P");
    }

    function test_T3_orderDependent() public view {
        uint256 h1 = poseidonT3.hash2(1, 2);
        uint256 h2 = poseidonT3.hash2(2, 1);
        assertTrue(h1 != h2, "PoseidonT3 must be order-dependent");
    }

    function test_T3_largeInputs() public view {
        uint256 h = poseidonT3.hash2(P - 1, P - 1);
        assertLt(h, P, "PoseidonT3 large inputs must stay in field");
    }

    /// @notice PoseidonYul wrapper must produce identical results to PoseidonT3
    function test_wrapper_delegation() public view {
        assertEq(poseidon.hash2(0, 0), poseidonT3.hash2(0, 0));
        assertEq(poseidon.hash2(1, 2), poseidonT3.hash2(1, 2));
        assertEq(poseidon.hash2(P - 1, P - 1), poseidonT3.hash2(P - 1, P - 1));
        assertEq(poseidon.hash2(42, 99), poseidonT3.hash2(42, 99));
    }

    /* ══════════════════════════════════════════════════
              POSEIDON T3 FUZZ TESTS
       ══════════════════════════════════════════════════ */

    function testFuzz_T3_resultInField(uint256 a, uint256 b) public view {
        uint256 h = poseidonT3.hash2(a, b);
        assertLt(h, P, "PoseidonT3 result must be in BN254 scalar field");
    }

    function testFuzz_T3_deterministic(uint256 a, uint256 b) public view {
        assertEq(poseidonT3.hash2(a, b), poseidonT3.hash2(a, b));
    }

    function testFuzz_T3_inputSensitivity(uint256 a) public view {
        vm.assume(a < P - 1);
        uint256 h1 = poseidonT3.hash2(a, 0);
        uint256 h2 = poseidonT3.hash2(a + 1, 0);
        assertTrue(h1 != h2, "incrementing input should change output");
    }

    function testFuzz_T3_wrapperIdentical(uint256 a, uint256 b) public view {
        assertEq(
            poseidon.hash2(a, b),
            poseidonT3.hash2(a, b),
            "PoseidonYul wrapper must match PoseidonT3"
        );
    }

    /* ══════════════════════════════════════════════════
              POSEIDON T3 GAS BENCHMARK
       ══════════════════════════════════════════════════ */

    function test_T3_gasUnder120k() public view {
        uint256 gasBefore = gasleft();
        poseidonT3.hash2(123, 456);
        uint256 gasUsed = gasBefore - gasleft();
        // Full 65-round Poseidon costs more than 8-round simplified version
        // Target: < 120,000 gas for full security
        assertLt(gasUsed, 120_000, "PoseidonT3 gas too high");
    }

    /* ══════════════════════════════════════════════════
              COLLISION RESISTANCE (T3)
       ══════════════════════════════════════════════════ */

    function test_T3_noTrivialCollision() public view {
        uint256 h00 = poseidonT3.hash2(0, 0);
        uint256 h01 = poseidonT3.hash2(0, 1);
        uint256 h10 = poseidonT3.hash2(1, 0);
        uint256 h11 = poseidonT3.hash2(1, 1);

        assertTrue(h00 != h01);
        assertTrue(h00 != h10);
        assertTrue(h00 != h11);
        assertTrue(h01 != h10);
        assertTrue(h01 != h11);
        assertTrue(h10 != h11);
    }
}
