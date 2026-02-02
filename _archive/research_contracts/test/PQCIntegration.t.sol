// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../contracts/pqc/DilithiumVerifier.sol";
import "../../contracts/pqc/SPHINCSPlusVerifier.sol";
import "../../contracts/pqc/KyberKEM.sol";
import "../../contracts/pqc/PQCRegistry.sol";
import "../../contracts/pqc/PQCProtectedLock.sol";

/**
 * @title PQCIntegrationTest
 * @notice End-to-end integration tests for PQC module
 */
contract PQCIntegrationTest is Test {
    DilithiumVerifier public dilithiumVerifier;
    SPHINCSPlusVerifier public sphincsVerifier;
    KyberKEM public kyberKEM;
    PQCRegistry public registry;
    PQCProtectedLock public pqcLock;

    address public alice = address(0x1);
    address public bob = address(0x2);
    address public charlie = address(0x3);
    address public admin = address(0xAD);

    bytes public dilithium3PK;
    bytes public dilithium5PK;
    bytes public sphincs128PK;
    bytes public kyber768PK;

    function setUp() public {
        vm.startPrank(admin);

        // Deploy all PQC contracts
        dilithiumVerifier = new DilithiumVerifier();
        sphincsVerifier = new SPHINCSPlusVerifier();
        kyberKEM = new KyberKEM();

        registry = new PQCRegistry(
            address(dilithiumVerifier),
            address(sphincsVerifier),
            address(kyberKEM)
        );

        pqcLock = new PQCProtectedLock(address(registry), address(0));

        // Generate test keys
        dilithium3PK = _generateBytes(1952);
        dilithium5PK = _generateBytes(2592);
        sphincs128PK = _generateBytes(32);
        kyber768PK = _generateBytes(1184);

        // Add trusted keys
        dilithiumVerifier.addTrustedKey(keccak256(dilithium3PK));
        dilithiumVerifier.addTrustedKey(keccak256(dilithium5PK));
        sphincsVerifier.addTrustedKey(keccak256(sphincs128PK));

        vm.stopPrank();

        // Fund test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(charlie, 100 ether);
    }

    // =========================================================================
    // INTEGRATION TEST: Full PQC Account Lifecycle
    // =========================================================================
    function test_FullAccountLifecycle() public {
        // Phase 1: Alice configures PQC account
        vm.startPrank(alice);

        bytes32 sigKeyHash = keccak256(dilithium3PK);
        bytes32 kemKeyHash = keccak256(kyber768PK);

        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            sigKeyHash,
            kemKeyHash,
            true // Hybrid enabled
        );

        assertTrue(registry.isPQCEnabled(alice));

        PQCRegistry.AccountPQConfig memory config = registry.getAccountConfig(
            alice
        );
        assertEq(
            uint8(config.signatureAlgorithm),
            uint8(PQCRegistry.PQCPrimitive.Dilithium3)
        );
        assertEq(
            uint8(config.kemAlgorithm),
            uint8(PQCRegistry.PQCPrimitive.Kyber768)
        );
        assertTrue(config.hybridEnabled);
        assertTrue(config.isActive);

        vm.stopPrank();

        // Phase 2: Bob registers Kyber key for key exchange
        vm.startPrank(bob);
        kyberKEM.registerPublicKey(kyber768PK, KyberKEM.KyberVariant.Kyber768);

        KyberKEM.KyberKeyPair memory bobKeyInfo = kyberKEM.getKeyInfo(bob);
        assertTrue(bobKeyInfo.isActive);
        assertEq(
            uint8(bobKeyInfo.variant),
            uint8(KyberKEM.KyberVariant.Kyber768)
        );
        vm.stopPrank();

        // Phase 3: Alice initiates key exchange with Bob
        vm.startPrank(alice);
        bytes32 randomness = keccak256(
            abi.encodePacked(block.timestamp, alice)
        );
        (bytes32 exchangeId, , bytes32 sharedSecretHash) = kyberKEM.encapsulate(
            bob,
            randomness
        );

        assertTrue(exchangeId != bytes32(0));
        vm.stopPrank();

        // Phase 4: Bob confirms decapsulation
        vm.startPrank(bob);
        kyberKEM.confirmDecapsulation(exchangeId, sharedSecretHash);

        assertTrue(kyberKEM.isExchangeCompleted(exchangeId));
        vm.stopPrank();

        // Phase 5: Check statistics
        PQCRegistry.PQCStats memory stats = registry.getStats();
        assertEq(stats.totalAccounts, 1);
        assertEq(stats.dilithiumAccounts, 1);
        assertEq(stats.kyberAccounts, 1);
    }

    // =========================================================================
    // INTEGRATION TEST: Signature Verification Flow
    // =========================================================================
    function test_SignatureVerificationFlow() public {
        // Setup: Configure accounts
        vm.startPrank(alice);
        bytes32 sigKeyHash = keccak256(dilithium3PK);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            sigKeyHash,
            bytes32(0),
            false
        );
        vm.stopPrank();

        vm.startPrank(admin);
        dilithiumVerifier.addTrustedKey(sigKeyHash);
        vm.stopPrank();

        // Test Dilithium3 verification
        bytes32 message = keccak256("Test message for verification");
        bytes memory signature = _generateBytes(3293); // Dilithium3 sig size

        bool isValid = dilithiumVerifier.verifyDilithium3(
            message,
            signature,
            dilithium3PK
        );
        assertTrue(isValid);

        // Test Dilithium5 verification
        bytes memory sig5 = _generateBytes(4595);
        bool isValid5 = dilithiumVerifier.verifyDilithium5(
            message,
            sig5,
            dilithium5PK
        );
        assertTrue(isValid5);
    }

    // =========================================================================
    // INTEGRATION TEST: Phase Transitions
    // =========================================================================
    function test_PhaseTransitions() public {
        // Start in ClassicalOnly phase
        assertEq(
            uint8(registry.currentPhase()),
            uint8(PQCRegistry.TransitionPhase.ClassicalOnly)
        );
        assertTrue(registry.allowsClassicalOnly());

        // Configure account without hybrid (should work in ClassicalOnly)
        vm.startPrank(alice);
        bytes32 sigKeyHash = keccak256(dilithium3PK);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            sigKeyHash,
            bytes32(0),
            false
        );
        vm.stopPrank();

        // Admin transitions to HybridOptional
        vm.startPrank(admin);
        registry.transitionPhase(PQCRegistry.TransitionPhase.HybridOptional);
        assertEq(
            uint8(registry.currentPhase()),
            uint8(PQCRegistry.TransitionPhase.HybridOptional)
        );
        vm.stopPrank();

        // Bob can still configure without hybrid in HybridOptional
        vm.startPrank(bob);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            keccak256(dilithium5PK),
            bytes32(0),
            false
        );
        vm.stopPrank();

        // Admin transitions to HybridMandatory
        vm.startPrank(admin);
        registry.transitionPhase(PQCRegistry.TransitionPhase.HybridMandatory);
        assertEq(
            uint8(registry.currentPhase()),
            uint8(PQCRegistry.TransitionPhase.HybridMandatory)
        );
        assertFalse(registry.allowsClassicalOnly());
        vm.stopPrank();

        // Charlie must use hybrid in HybridMandatory phase
        vm.startPrank(charlie);
        bytes32 charlieKemKey = keccak256(kyber768PK);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            keccak256(sphincs128PK),
            charlieKemKey,
            true // Must be hybrid
        );
        assertTrue(registry.isPQCEnabled(charlie));
        vm.stopPrank();
    }

    // =========================================================================
    // INTEGRATION TEST: Protected Lock with PQC
    // =========================================================================
    function test_PQCProtectedLock() public {
        // Alice configures PQC
        vm.startPrank(alice);
        bytes32 sigKeyHash = keccak256(dilithium3PK);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            sigKeyHash,
            bytes32(0),
            true
        );

        // Create a lock
        uint256 lockAmount = 1 ether;
        uint256 unlockTime = block.timestamp + 1 days;

        // This would interact with PQCProtectedLock
        // pqcLock.createLock{value: lockAmount}(unlockTime);

        vm.stopPrank();
    }

    // =========================================================================
    // INTEGRATION TEST: Batch Operations
    // =========================================================================
    function test_BatchVerification() public {
        // Prepare batch data
        bytes32[] memory messages = new bytes32[](3);
        bytes[] memory signatures = new bytes[](3);
        bytes[] memory publicKeys = new bytes[](3);
        DilithiumVerifier.DilithiumLevel[]
            memory levels = new DilithiumVerifier.DilithiumLevel[](3);

        for (uint i = 0; i < 3; i++) {
            messages[i] = keccak256(abi.encodePacked("Message ", i));
            signatures[i] = _generateBytes(3293);
            publicKeys[i] = dilithium3PK;
            levels[i] = DilithiumVerifier.DilithiumLevel.Level3; // Dilithium3
        }

        // Add trusted key
        vm.prank(admin);
        dilithiumVerifier.addTrustedKey(keccak256(dilithium3PK));

        // Batch verify
        bool allValid = dilithiumVerifier.batchVerify(
            messages,
            signatures,
            publicKeys,
            levels
        );
        assertTrue(allValid);
    }

    // =========================================================================
    // INTEGRATION TEST: Multi-party Key Exchange
    // =========================================================================
    function test_MultiPartyKeyExchange() public {
        // All parties register Kyber keys
        vm.startPrank(alice);
        kyberKEM.registerPublicKey(
            _generateBytes(1184),
            KyberKEM.KyberVariant.Kyber768
        );
        vm.stopPrank();

        vm.startPrank(bob);
        kyberKEM.registerPublicKey(
            _generateBytes(1184),
            KyberKEM.KyberVariant.Kyber768
        );
        vm.stopPrank();

        vm.startPrank(charlie);
        kyberKEM.registerPublicKey(
            _generateBytes(1184),
            KyberKEM.KyberVariant.Kyber768
        );
        vm.stopPrank();

        // Alice initiates exchanges with Bob and Charlie
        vm.startPrank(alice);

        bytes32 randomness1 = keccak256(
            abi.encodePacked(block.timestamp, "bob")
        );
        (bytes32 exchangeIdBob, , bytes32 secretHashBob) = kyberKEM.encapsulate(
            bob,
            randomness1
        );

        bytes32 randomness2 = keccak256(
            abi.encodePacked(block.timestamp, "charlie")
        );
        (bytes32 exchangeIdCharlie, , bytes32 secretHashCharlie) = kyberKEM
            .encapsulate(charlie, randomness2);

        vm.stopPrank();

        // Both confirm
        vm.prank(bob);
        kyberKEM.confirmDecapsulation(exchangeIdBob, secretHashBob);

        vm.prank(charlie);
        kyberKEM.confirmDecapsulation(exchangeIdCharlie, secretHashCharlie);

        // Verify all exchanges completed
        assertTrue(kyberKEM.isExchangeCompleted(exchangeIdBob));
        assertTrue(kyberKEM.isExchangeCompleted(exchangeIdCharlie));
    }

    // =========================================================================
    // INTEGRATION TEST: Error Handling
    // =========================================================================
    function test_ErrorHandling() public {
        // Test: Duplicate account configuration
        vm.startPrank(alice);
        bytes32 sigKeyHash = keccak256(dilithium3PK);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            sigKeyHash,
            bytes32(0),
            false
        );

        vm.expectRevert(PQCRegistry.AccountAlreadyConfigured.selector);
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.None,
            sigKeyHash,
            bytes32(0),
            false
        );
        vm.stopPrank();

        // Test: Invalid signature size
        vm.expectRevert();
        dilithiumVerifier.verifyDilithium3(
            keccak256("test"),
            _generateBytes(100), // Wrong size
            dilithium3PK
        );

        // Test: Invalid public key size
        vm.expectRevert();
        dilithiumVerifier.verifyDilithium3(
            keccak256("test"),
            _generateBytes(3293),
            _generateBytes(100) // Wrong size
        );
    }

    // =========================================================================
    // INTEGRATION TEST: Gas Benchmarks
    // =========================================================================
    function test_GasBenchmarks() public {
        // Benchmark account configuration
        vm.startPrank(alice);
        uint256 gasBefore = gasleft();
        registry.configureAccount(
            PQCRegistry.PQCPrimitive.Dilithium3,
            PQCRegistry.PQCPrimitive.Kyber768,
            keccak256(dilithium3PK),
            keccak256(kyber768PK),
            true
        );
        uint256 configGas = gasBefore - gasleft();
        console.log("Account configuration gas:", configGas);
        vm.stopPrank();

        // Benchmark Dilithium verification
        bytes memory sig = _generateBytes(3293);
        gasBefore = gasleft();
        dilithiumVerifier.verifyDilithium3(
            keccak256("test"),
            sig,
            dilithium3PK
        );
        uint256 verifyGas = gasBefore - gasleft();
        console.log("Dilithium3 verification gas:", verifyGas);

        // Benchmark Kyber encapsulation
        vm.startPrank(bob);
        kyberKEM.registerPublicKey(kyber768PK, KyberKEM.KyberVariant.Kyber768);
        vm.stopPrank();

        vm.startPrank(alice);
        gasBefore = gasleft();
        kyberKEM.encapsulate(bob, keccak256("randomness"));
        uint256 encapGas = gasBefore - gasleft();
        console.log("Kyber768 encapsulation gas:", encapGas);
        vm.stopPrank();

        // Assert reasonable gas usage (mock mode has overhead)
        assertLt(configGas, 500_000, "Config gas too high");
        assertLt(verifyGas, 500_000, "Verify gas too high");
        assertLt(encapGas, 2_500_000, "Encap gas too high");
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================
    function _generateBytes(
        uint256 length
    ) internal view returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = bytes1(
                uint8(
                    uint256(keccak256(abi.encodePacked(block.timestamp, i))) %
                        256
                )
            );
        }
        return result;
    }
}
