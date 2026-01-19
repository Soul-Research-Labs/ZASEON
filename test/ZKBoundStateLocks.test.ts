import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, encodeAbiParameters, parseAbiParameters } from "viem";

/**
 * ZKBoundStateLocks (ZK-SLocks) Test Suite
 * 
 * Tests the novel ZK-Bound State Lock primitive for cross-chain 
 * confidential state transitions.
 */
describe("ZKBoundStateLocks", function () {
    this.timeout(120000);

    // Helper function to generate test data
    function generateTestCommitment(value: bigint): `0x${string}` {
        return keccak256(encodeAbiParameters(
            parseAbiParameters("uint256 value"),
            [value]
        ));
    }

    function generateTransitionPredicate(predicateType: string): `0x${string}` {
        return keccak256(toBytes(predicateType));
    }

    // ==========================================================================
    // Core Lock Creation Tests
    // ==========================================================================
    describe("Lock Creation", function () {
        
        it("should create a new ZK-SLock", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, user1] = await viem.getWalletClients();
            
            // Deploy mock verifier
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            await mockVerifier.write.setVerificationResult([true]);

            // Deploy ZKBoundStateLocks
            const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);

            // Get a valid domain separator
            const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
            
            const stateCommitment = generateTestCommitment(1000n);
            const transitionPredicate = generateTransitionPredicate("transfer");
            const policyHash = "0x" + "00".repeat(32) as `0x${string}`;
            
            // Create lock using the actual function signature
            await zkSlocks.write.createLock([
                stateCommitment,
                transitionPredicate,
                policyHash,
                domainSeparator,
                0n // unlockDeadline
            ], { account: user1.account });
            
            // Verify lock was created
            const activeLocks = await zkSlocks.read.getActiveLockIds();
            expect(activeLocks.length).to.be.greaterThan(0);
        });

        it("should generate unique lock IDs", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, user1] = await viem.getWalletClients();
            
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            await mockVerifier.write.setVerificationResult([true]);

            const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);
            const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
            
            const stateCommitment1 = generateTestCommitment(1000n);
            const stateCommitment2 = generateTestCommitment(2000n);
            const transitionPredicate = generateTransitionPredicate("transfer");
            const policyHash = "0x" + "00".repeat(32) as `0x${string}`;
            
            // Create two locks
            await zkSlocks.write.createLock([
                stateCommitment1,
                transitionPredicate,
                policyHash,
                domainSeparator,
                0n
            ], { account: user1.account });
            
            await zkSlocks.write.createLock([
                stateCommitment2,
                transitionPredicate,
                policyHash,
                domainSeparator,
                0n
            ], { account: user1.account });
            
            // Both locks should be active
            const activeLocks = await zkSlocks.read.getActiveLockIds();
            expect(activeLocks.length).to.equal(2);
        });
    });

    // ==========================================================================
    // Unlock Tests
    // ==========================================================================
    describe("Lock Unlocking", function () {
        
        it("should unlock with valid proof", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, user1] = await viem.getWalletClients();
            
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            await mockVerifier.write.setVerificationResult([true]);

            const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);
            const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
            
            const stateCommitment = generateTestCommitment(1000n);
            const newStateCommitment = generateTestCommitment(500n);
            const transitionPredicate = generateTransitionPredicate("transfer");
            const policyHash = "0x" + "00".repeat(32) as `0x${string}`;
            
            // Create lock
            await zkSlocks.write.createLock([
                stateCommitment,
                transitionPredicate,
                policyHash,
                domainSeparator,
                0n
            ], { account: user1.account });
            
            const activeLocks = await zkSlocks.read.getActiveLockIds();
            const lockId = activeLocks[0];
            
            // Create unlock proof struct
            const unlockProof = {
                lockId: lockId,
                zkProof: "0x" + "ab".repeat(64) as `0x${string}`,
                newStateCommitment: newStateCommitment,
                nullifier: generateTestCommitment(12345n),
                verifierKeyHash: "0x" + "00".repeat(32) as `0x${string}`,
                auxiliaryData: "0x" as `0x${string}`
            };
            
            await zkSlocks.write.unlock([unlockProof], { account: user1.account });
            
            // Verify lock is no longer active
            const locksAfter = await zkSlocks.read.getActiveLockIds();
            expect(locksAfter.length).to.equal(0);
        });
    });

    // ==========================================================================
    // Domain Management Tests
    // ==========================================================================
    describe("Domain Management", function () {
        
        it("should register a new domain", async function () {
            const { viem } = await hre.network.connect();
            const [deployer] = await viem.getWalletClients();
            
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);
            
            const chainId = 100;
            const appId = 1;
            const epoch = 1;
            const domainName = "test-domain";
            
            await zkSlocks.write.registerDomain([
                chainId,
                appId,
                epoch,
                domainName
            ], { account: deployer.account });
            
            // Generate domain separator to verify
            const domainSeparator = await zkSlocks.read.generateDomainSeparator([
                chainId,
                appId,
                epoch
            ]);
            
            expect(domainSeparator).to.not.equal("0x" + "00".repeat(32));
        });

        it("should generate unique domain separators", async function () {
            const { viem } = await hre.network.connect();
            
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);
            
            const separator1 = await zkSlocks.read.generateDomainSeparator([1, 100, 1]);
            const separator2 = await zkSlocks.read.generateDomainSeparator([2, 100, 1]);
            
            expect(separator1).to.not.equal(separator2);
        });
    });

    // ==========================================================================
    // Nullifier Generation Tests
    // ==========================================================================
    describe("Nullifier Generation", function () {
        
        it("should generate deterministic nullifiers", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, user1] = await viem.getWalletClients();
            
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);
            const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
            
            const stateCommitment = generateTestCommitment(1000n);
            const transitionPredicate = generateTransitionPredicate("transfer");
            const policyHash = "0x" + "00".repeat(32) as `0x${string}`;
            
            // Create lock
            await zkSlocks.write.createLock([
                stateCommitment,
                transitionPredicate,
                policyHash,
                domainSeparator,
                0n
            ], { account: user1.account });
            
            const activeLocks = await zkSlocks.read.getActiveLockIds();
            const lockId = activeLocks[0];
            
            // Generate nullifier twice with same secret - should be the same
            const secret = generateTestCommitment(99999n);
            const nullifier1 = await zkSlocks.read.generateNullifier([
                secret,
                lockId,
                domainSeparator
            ]);
            
            const nullifier2 = await zkSlocks.read.generateNullifier([
                secret,
                lockId,
                domainSeparator
            ]);
            
            expect(nullifier1).to.equal(nullifier2);
        });

        it("should generate different nullifiers for different secrets", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, user1] = await viem.getWalletClients();
            
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);
            const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
            
            const stateCommitment = generateTestCommitment(1000n);
            const transitionPredicate = generateTransitionPredicate("transfer");
            const policyHash = "0x" + "00".repeat(32) as `0x${string}`;
            
            // Create lock
            await zkSlocks.write.createLock([
                stateCommitment,
                transitionPredicate,
                policyHash,
                domainSeparator,
                0n
            ], { account: user1.account });
            
            const activeLocks = await zkSlocks.read.getActiveLockIds();
            const lockId = activeLocks[0];
            
            // Generate nullifiers for different secrets
            const secret1 = generateTestCommitment(11111n);
            const secret2 = generateTestCommitment(22222n);
            
            const nullifier1 = await zkSlocks.read.generateNullifier([
                secret1,
                lockId,
                domainSeparator
            ]);
            
            const nullifier2 = await zkSlocks.read.generateNullifier([
                secret2,
                lockId,
                domainSeparator
            ]);
            
            expect(nullifier1).to.not.equal(nullifier2);
        });
    });

    // ==========================================================================
    // Active Lock Count Tests
    // ==========================================================================
    describe("Active Lock Tracking", function () {
        
        it("should accurately track active lock count", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, user1] = await viem.getWalletClients();
            
            const mockVerifier = await viem.deployContract("MockProofVerifier");
            const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [mockVerifier.address]);
            const domainSeparator = await zkSlocks.read.generateDomainSeparator([1, 0, 0]);
            
            // Initially no locks
            let count = await zkSlocks.read.getActiveLockCount();
            expect(count).to.equal(0n);
            
            // Create first lock
            const stateCommitment1 = generateTestCommitment(1000n);
            await zkSlocks.write.createLock([
                stateCommitment1,
                generateTransitionPredicate("transfer"),
                "0x" + "00".repeat(32) as `0x${string}`,
                domainSeparator,
                0n
            ], { account: user1.account });
            
            count = await zkSlocks.read.getActiveLockCount();
            expect(count).to.equal(1n);
            
            // Create second lock
            const stateCommitment2 = generateTestCommitment(2000n);
            await zkSlocks.write.createLock([
                stateCommitment2,
                generateTransitionPredicate("update"),
                "0x" + "00".repeat(32) as `0x${string}`,
                domainSeparator,
                0n
            ], { account: user1.account });
            
            count = await zkSlocks.read.getActiveLockCount();
            expect(count).to.equal(2n);
        });
    });
});
