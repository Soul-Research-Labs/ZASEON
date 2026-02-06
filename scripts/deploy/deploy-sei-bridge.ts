import { ethers } from "hardhat";

/**
 * Deployment script for the Sei Bridge Adapter
 *
 * Deploys:
 * 1. MockWrappedSEI (wSEI — 6-decimal ERC-20)
 * 2. MockSeiValidatorOracle (Tendermint BFT validator tracking)
 * 3. SeiBridgeAdapter (main bridge contract)
 *
 * Configures:
 * - Registers 4 initial validators with voting power
 * - Sets min validator signatures to 3 (≥ 2/3+1 of 4)
 * - Sets required block confirmations to 8
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-sei-bridge.ts --network <network>
 */
async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying Sei Bridge with account:", deployer.address);
    console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

    // =========================================================================
    // 1. Deploy MockWrappedSEI
    // =========================================================================
    console.log("\n--- Deploying MockWrappedSEI (wSEI, 6 decimals) ---");
    const MockWrappedSEI = await ethers.getContractFactory("MockWrappedSEI");
    const wSEI = await MockWrappedSEI.deploy();
    await wSEI.waitForDeployment();
    const wSEIAddress = await wSEI.getAddress();
    console.log("MockWrappedSEI deployed to:", wSEIAddress);

    // =========================================================================
    // 2. Deploy MockSeiValidatorOracle
    // =========================================================================
    console.log("\n--- Deploying MockSeiValidatorOracle ---");
    const MockSeiValidatorOracle = await ethers.getContractFactory("MockSeiValidatorOracle");
    const oracle = await MockSeiValidatorOracle.deploy();
    await oracle.waitForDeployment();
    const oracleAddress = await oracle.getAddress();
    console.log("MockSeiValidatorOracle deployed to:", oracleAddress);

    // Register initial validators with voting power (Tendermint BFT)
    const validators = [
        { address: "0x0000000000000000000000000000000000001001", votingPower: 100 },
        { address: "0x0000000000000000000000000000000000001002", votingPower: 100 },
        { address: "0x0000000000000000000000000000000000001003", votingPower: 100 },
        { address: "0x0000000000000000000000000000000000001004", votingPower: 100 },
    ];

    for (let i = 0; i < validators.length; i++) {
        const tx = await oracle.addValidator(validators[i].address, validators[i].votingPower);
        await tx.wait();
        console.log(`  Validator ${i + 1} registered: ${validators[i].address} (power: ${validators[i].votingPower})`);
    }

    // =========================================================================
    // 3. Deploy SeiBridgeAdapter
    // =========================================================================
    console.log("\n--- Deploying SeiBridgeAdapter ---");
    const SeiBridgeAdapter = await ethers.getContractFactory("SeiBridgeAdapter");
    const bridge = await SeiBridgeAdapter.deploy(deployer.address);
    await bridge.waitForDeployment();
    const bridgeAddress = await bridge.getAddress();
    console.log("SeiBridgeAdapter deployed to:", bridgeAddress);

    // =========================================================================
    // 4. Configure Bridge
    // =========================================================================
    console.log("\n--- Configuring SeiBridgeAdapter ---");

    const seiBridgeContract = ethers.ZeroAddress.replace(/.$/, "1"); // Placeholder
    const minValidatorSignatures = 3;
    const requiredBlockConfirmations = 8;

    const configureTx = await bridge.configure(
        seiBridgeContract,
        wSEIAddress,
        oracleAddress,
        minValidatorSignatures,
        requiredBlockConfirmations
    );
    await configureTx.wait();
    console.log("  Bridge configured:");
    console.log("    seiBridgeContract:", seiBridgeContract);
    console.log("    wrappedSEI:", wSEIAddress);
    console.log("    validatorOracle:", oracleAddress);
    console.log("    minValidatorSignatures:", minValidatorSignatures);
    console.log("    requiredBlockConfirmations:", requiredBlockConfirmations);

    // Mint initial wSEI supply to bridge for testing
    const initialSupply = ethers.parseUnits("1000000", 6); // 1M SEI in usei
    const mintTx = await wSEI.mint(bridgeAddress, initialSupply);
    await mintTx.wait();
    console.log("  Initial wSEI minted to bridge:", ethers.formatUnits(initialSupply, 6), "SEI");

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n========================================");
    console.log("  SEI BRIDGE DEPLOYMENT COMPLETE");
    console.log("========================================");
    console.log("Network:", (await ethers.provider.getNetwork()).name);
    console.log("Chain ID:", (await ethers.provider.getNetwork()).chainId.toString());
    console.log("");
    console.log("Contracts:");
    console.log("  MockWrappedSEI:          ", wSEIAddress);
    console.log("  MockSeiValidatorOracle:  ", oracleAddress);
    console.log("  SeiBridgeAdapter:        ", bridgeAddress);
    console.log("");
    console.log("Configuration:");
    console.log("  Sei Chain ID:                    1329");
    console.log("  Token Decimals:                  6 (usei)");
    console.log("  Bridge Fee:                      0.05% (5 BPS)");
    console.log("  Min Deposit:                     0.1 SEI");
    console.log("  Max Deposit:                     10,000,000 SEI");
    console.log("  Withdrawal Refund Delay:         36 hours");
    console.log("  Min Escrow Timelock:             1 hour");
    console.log("  Max Escrow Timelock:             30 days");
    console.log("  Block Confirmations:             8");
    console.log("  Validators Registered:           4");
    console.log("  Min Validator Signatures:        3");
    console.log("  Consensus:                       Twin-Turbo (~400ms)");
    console.log("========================================");

    // Write deployment artifact
    const fs = await import("fs");
    const artifact = {
        network: (await ethers.provider.getNetwork()).name,
        chainId: (await ethers.provider.getNetwork()).chainId.toString(),
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
        contracts: {
            MockWrappedSEI: wSEIAddress,
            MockSeiValidatorOracle: oracleAddress,
            SeiBridgeAdapter: bridgeAddress,
        },
        configuration: {
            seiChainId: 1329,
            tokenDecimals: 6,
            denomination: "usei",
            bridgeFeeBps: 5,
            minDepositSei: "0.1",
            maxDepositSei: "10000000",
            withdrawalRefundDelayHours: 36,
            minEscrowTimelockHours: 1,
            maxEscrowTimelockDays: 30,
            blockConfirmations: requiredBlockConfirmations,
            validatorCount: validators.length,
            minValidatorSignatures: minValidatorSignatures,
            consensus: "Twin-Turbo (Tendermint BFT)",
            blockTimeMs: 400,
        },
    };

    const path = `deployments/sei-bridge-${(await ethers.provider.getNetwork()).chainId}.json`;
    fs.writeFileSync(path, JSON.stringify(artifact, null, 2));
    console.log(`\nDeployment artifact written to: ${path}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
