// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/adapters/NoirVerifierAdapter.sol";

/// @dev Mock Noir verifier that checks signal count and returns configurable result
contract MockNoirVerifier {
    bool public result;
    uint256 public lastCallSignalCount;

    constructor(bool _result) {
        result = _result;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external view returns (bool) {
        return result;
    }

    function setResult(bool _v) external {
        result = _v;
    }
}

/// @dev Concrete adapter for testing
contract TestNoirAdapter is NoirVerifierAdapter {
    uint256 private _inputCount;

    constructor(
        address _noirVerifier,
        uint256 inputCount_
    ) NoirVerifierAdapter(_noirVerifier) {
        _inputCount = inputCount_;
    }

    function verify(
        bytes32,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory signals = _prepareSignals(publicInputs);
        return _verifyNoir(proof, signals);
    }

    function getPublicInputCount() external view override returns (uint256) {
        return _inputCount;
    }

    /// @dev Expose internal for testing
    function exposePrepareSignals(
        bytes calldata publicInputs
    ) external pure returns (bytes32[] memory) {
        return _prepareSignals(publicInputs);
    }
}

contract NoirVerifierAdapterTest is Test {
    TestNoirAdapter public adapter;
    MockNoirVerifier public noirV;

    address alice = address(0xBEEF);

    function setUp() public {
        noirV = new MockNoirVerifier(true);
        adapter = new TestNoirAdapter(address(noirV), 2);
    }

    // ──────── Deployment ────────

    function test_deploy_verifierSet() public view {
        assertEq(adapter.noirVerifier(), address(noirV));
    }

    function test_isReady() public view {
        assertTrue(adapter.isReady());
    }

    function test_getPublicInputCount() public view {
        assertEq(adapter.getPublicInputCount(), 2);
    }

    // ──────── verify(bytes, uint256[]) ────────

    function test_verifyUint256Array_success() public view {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 1;
        inputs[1] = 2;

        bool valid = adapter.verify(bytes("proof"), inputs);
        assertTrue(valid);
    }

    function test_verifyUint256Array_wrongCountReverts() public {
        uint256[] memory inputs = new uint256[](3); // expects 2
        inputs[0] = 1;
        inputs[1] = 2;
        inputs[2] = 3;

        vm.expectRevert("SIG_COUNT_MISMATCH");
        adapter.verify(bytes("proof"), inputs);
    }

    function test_verifyUint256Array_failsWhenVerifierRejects() public {
        noirV.setResult(false);

        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 1;
        inputs[1] = 2;

        bool valid = adapter.verify(bytes("proof"), inputs);
        assertFalse(valid);
    }

    // ──────── verifySingle ────────

    function test_verifySingle_wrongCountReverts() public {
        // Adapter expects 2 inputs, verifySingle provides 1
        vm.expectRevert("SIG_COUNT_MISMATCH");
        adapter.verifySingle(bytes("proof"), 42);
    }

    function test_verifySingle_success() public {
        // Deploy an adapter with 1 input
        TestNoirAdapter adapter1 = new TestNoirAdapter(address(noirV), 1);
        bool valid = adapter1.verifySingle(bytes("proof"), 42);
        assertTrue(valid);
    }

    // ──────── verifyProof(bytes, bytes) ────────

    function test_verifyProof_success() public view {
        // Encode 2 signals as bytes
        bytes memory pubInputs = abi.encode(
            uint256(2),
            bytes32(uint256(10)),
            bytes32(uint256(20))
        );

        bool valid = adapter.verifyProof(bytes("proof"), pubInputs);
        assertTrue(valid);
    }

    // ──────── verify(bytes32, bytes, bytes) — circuit hash variant ────────

    function test_verifyCircuitHash_success() public view {
        bytes memory pubInputs = abi.encode(
            uint256(2),
            bytes32(uint256(100)),
            bytes32(uint256(200))
        );

        bool valid = adapter.verify(
            bytes32(uint256(1)),
            bytes("proof"),
            pubInputs
        );
        assertTrue(valid);
    }

    // ──────── _prepareSignals FIELD_OVERFLOW check ────────

    function test_prepareSignals_fieldOverflow() public {
        // The BN254 field size
        uint256 FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        // Create an adapter with 1 input to avoid count mismatch
        TestNoirAdapter adapterOverflow = new TestNoirAdapter(
            address(noirV),
            1
        );

        // Encode a value >= FIELD_SIZE
        bytes memory pubInputs = abi.encode(uint256(1), bytes32(FIELD_SIZE));

        vm.expectRevert("FIELD_OVERFLOW");
        adapterOverflow.exposePrepareSignals(pubInputs);
    }

    function test_prepareSignals_justBelowFieldSize() public {
        uint256 FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        TestNoirAdapter adapterBelow = new TestNoirAdapter(address(noirV), 1);
        bytes memory pubInputs = abi.encode(
            uint256(1),
            bytes32(FIELD_SIZE - 1)
        );

        bytes32[] memory signals = adapterBelow.exposePrepareSignals(pubInputs);
        assertEq(signals.length, 1);
        assertEq(signals[0], bytes32(FIELD_SIZE - 1));
    }

    // ──────── Zero-address verifier ────────

    function test_isReady_zeroAddress() public {
        TestNoirAdapter adapter0 = new TestNoirAdapter(address(0), 1);
        assertFalse(adapter0.isReady());
    }

    // ──────── Fuzz ────────

    function testFuzz_verifyUint256_validInputs(
        uint256 a,
        uint256 b
    ) public view {
        uint256 FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        a = bound(a, 0, FIELD_SIZE - 1);
        b = bound(b, 0, FIELD_SIZE - 1);

        uint256[] memory inputs = new uint256[](2);
        inputs[0] = a;
        inputs[1] = b;

        bool valid = adapter.verify(bytes("proof"), inputs);
        assertTrue(valid);
    }
}
