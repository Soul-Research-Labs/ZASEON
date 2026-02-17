import { expect } from "chai";
import hre from "hardhat";
import { keccak256, encodeAbiParameters, parseAbiParameters } from "viem";

/**
 * HeterogeneousRelayerRegistry Test Suite
 * 
 * Tests role-separated relayer system inspired by Zero's Block Producer/Validator split.
 * Covers ProofGenerator, LightRelayer, and Watchtower registration, task assignment, 
 * performance tracking, and slashing.
 */
describe("HeterogeneousRelayerRegistry", function () {
    this.timeout(120000);

    function generateHash(value: bigint): `0x${string}` {
        return keccak256(encodeAbiParameters(
            parseAbiParameters("uint256 value"),
            [value]
        ));
    }

    // ==========================================================================
    // Registration Tests
    // ==========================================================================
    describe("Relayer Registration", function () {

        it("should register a Proof Generator with sufficient stake", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, generator] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            const capabilityHash = generateHash(42n);

            await registry.write.registerProofGenerator([
                [1n, 137n, 42161n], // Ethereum, Polygon, Arbitrum
                capabilityHash
            ], {
                account: generator.account,
                value: BigInt(1e18) // 1 ETH
            });

            const relayer = await registry.read.getRelayer([generator.account.address]);
            expect(relayer.role).to.equal(0); // ProofGenerator
            expect(relayer.status).to.equal(0); // Active
            expect(relayer.stake).to.equal(BigInt(1e18));
        });

        it("should register a Light Relayer with lower stake", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, relayer1] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            await registry.write.registerLightRelayer([
                [1n, 10n] // Ethereum, Optimism
            ], {
                account: relayer1.account,
                value: BigInt(1e17) // 0.1 ETH
            });

            const relayer = await registry.read.getRelayer([relayer1.account.address]);
            expect(relayer.role).to.equal(1); // LightRelayer
            expect(relayer.status).to.equal(0); // Active
        });

        it("should register a Watchtower", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, watcher] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            await registry.write.registerWatchtower({
                account: watcher.account,
                value: BigInt(5e17) // 0.5 ETH
            });

            const relayer = await registry.read.getRelayer([watcher.account.address]);
            expect(relayer.role).to.equal(2); // Watchtower
        });

        it("should reject Proof Generator with insufficient stake", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, generator] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            try {
                await registry.write.registerProofGenerator([
                    [1n],
                    generateHash(1n)
                ], {
                    account: generator.account,
                    value: BigInt(1e16) // 0.01 ETH (below 1 ETH minimum)
                });
                expect.fail("Should have reverted");
            } catch (e: any) {
                expect(e).to.exist;
            }
        });

        it("should reject duplicate registration", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, relayer1] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            await registry.write.registerLightRelayer([[1n]], {
                account: relayer1.account,
                value: BigInt(1e17)
            });

            // Try to register again
            try {
                await registry.write.registerLightRelayer([[1n]], {
                    account: relayer1.account,
                    value: BigInt(1e17)
                });
                expect.fail("Should have reverted");
            } catch (e: any) {
                expect(e).to.exist;
            }
        });

        it("should track relayer counts per role", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, r1, r2, r3] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            await registry.write.registerProofGenerator([[1n], generateHash(1n)], {
                account: r1.account, value: BigInt(1e18)
            });
            await registry.write.registerLightRelayer([[1n]], {
                account: r2.account, value: BigInt(1e17)
            });
            await registry.write.registerWatchtower({
                account: r3.account, value: BigInt(5e17)
            });

            expect(await registry.read.getRelayerCount([0])).to.equal(1n); // ProofGenerator
            expect(await registry.read.getRelayerCount([1])).to.equal(1n); // LightRelayer
            expect(await registry.read.getRelayerCount([2])).to.equal(1n); // Watchtower
        });
    });

    // ==========================================================================
    // Task Assignment Tests
    // ==========================================================================
    describe("Task Assignment", function () {

        it("should assign proof generation task to a Proof Generator", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, generator, assigner] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            // Register a proof generator
            await registry.write.registerProofGenerator([
                [1n, 42161n],
                generateHash(99n)
            ], {
                account: generator.account,
                value: BigInt(1e18)
            });

            // Grant task assigner role
            const TASK_ASSIGNER_ROLE = keccak256(new TextEncoder().encode("TASK_ASSIGNER_ROLE") as any);
            await registry.write.grantRole([TASK_ASSIGNER_ROLE, assigner.account.address], {
                account: deployer.account
            });

            // Assign task
            const proofDataHash = generateHash(12345n);
            await registry.write.assignTask([
                0, // ProofGeneration
                proofDataHash,
                1n,     // source chain
                42161n, // dest chain
                0n      // auto deadline
            ], {
                account: assigner.account,
                value: BigInt(1e16) // 0.01 ETH reward
            });

            const totalTasks = await registry.read.totalTasks();
            expect(totalTasks).to.equal(1n);
        });
    });

    // ==========================================================================
    // Task Completion Tests
    // ==========================================================================
    describe("Task Completion", function () {

        it("should allow assigned relayer to complete task", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, relayer1] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            // Register relayer
            await registry.write.registerLightRelayer([[1n, 10n]], {
                account: relayer1.account,
                value: BigInt(1e17)
            });

            // Assign a relay task (deployer has TASK_ASSIGNER_ROLE by default)
            await registry.write.assignTask([
                2, // ProofRelay
                generateHash(111n),
                1n,
                10n,
                0n
            ], {
                account: deployer.account,
                value: BigInt(5e15) // reward
            });

            const totalCompleted = await registry.read.totalTasksCompleted();
            expect(totalCompleted).to.equal(0n);
        });
    });

    // ==========================================================================
    // Slashing Tests
    // ==========================================================================
    describe("Slashing", function () {

        it("should slash a relayer and update their status", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, badRelayer] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            // Register
            await registry.write.registerLightRelayer([[1n]], {
                account: badRelayer.account,
                value: BigInt(1e17)
            });

            // Slash
            const slashAmount = BigInt(5e16); // 0.05 ETH
            await registry.write.slashRelayer([
                badRelayer.account.address,
                slashAmount,
                "Failed to relay proof within deadline"
            ], { account: deployer.account });

            const relayer = await registry.read.getRelayer([badRelayer.account.address]);
            expect(relayer.status).to.equal(2); // Slashed
            expect(relayer.stake).to.equal(BigInt(5e16)); // 0.1 - 0.05 = 0.05
            expect(relayer.totalSlashed).to.equal(slashAmount);
        });
    });

    // ==========================================================================
    // Role Separation Verification Tests
    // ==========================================================================
    describe("Role Separation", function () {

        it("should return correct minimum stakes per role", async function () {
            const { viem } = await hre.network.connect();
            const [deployer] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            // ProofGenerator: 1 ETH
            expect(await registry.read.getMinStake([0])).to.equal(BigInt(1e18));
            // LightRelayer: 0.1 ETH
            expect(await registry.read.getMinStake([1])).to.equal(BigInt(1e17));
            // Watchtower: 0.5 ETH
            expect(await registry.read.getMinStake([2])).to.equal(BigInt(5e17));
        });

        it("should list relayers by role", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, r1, r2, r3] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            await registry.write.registerProofGenerator([[1n], generateHash(1n)], {
                account: r1.account, value: BigInt(1e18)
            });
            await registry.write.registerProofGenerator([[1n], generateHash(2n)], {
                account: r2.account, value: BigInt(1e18)
            });
            await registry.write.registerLightRelayer([[1n]], {
                account: r3.account, value: BigInt(1e17)
            });

            const generators = await registry.read.getRelayersByRole([0]);
            expect(generators.length).to.equal(2);

            const relayers = await registry.read.getRelayersByRole([1]);
            expect(relayers.length).to.equal(1);
        });
    });

    // ==========================================================================
    // Performance Reporting Tests
    // ==========================================================================
    describe("Performance Tracking", function () {

        it("should report performance and update reputation", async function () {
            const { viem } = await hre.network.connect();
            const [deployer, relayer1] = await viem.getWalletClients();

            const registry = await viem.deployContract("HeterogeneousRelayerRegistry", [
                deployer.account.address
            ]);

            await registry.write.registerLightRelayer([[1n]], {
                account: relayer1.account,
                value: BigInt(1e17)
            });

            // Report good performance
            await registry.write.reportPerformance([
                relayer1.account.address,
                {
                    avgLatencyMs: 500n,
                    successRate: 9500n,       // 95%
                    uptimePercentage: 9900n,  // 99%
                    tasksLastEpoch: 100n,
                    proofsGenerated: 0n,
                    proofsRelayed: 85n,
                    disputesRaised: 0n,
                    disputesWon: 0n
                }
            ], { account: deployer.account });

            const relayer = await registry.read.getRelayer([relayer1.account.address]);
            expect(relayer.reputationScore).to.be.greaterThan(0n);
        });
    });
});
