/**
 * Soul Protocol - BNB Chain Bridge Deployment Script
 *
 * Deploys the complete BNB Chain bridge infrastructure:
 * 1. MockWrappedBNB (wBNB) ERC-20 token
 * 2. MockBSCValidatorOracle (PoSA validator mock)
 * 3. BNBBridgeAdapter
 * 4. Configure bridge parameters
 * 5. Grant roles (RELAYER, GUARDIAN, TREASURY)
 * 6. Grant MINTER_ROLE to bridge on wBNB token
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-bnb-bridge.ts --network <network>
 */

import hre from "hardhat";
import fs from "fs";
import path from "path";

async function main() {
    const [deployer] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();

    const deployerAddress = deployer.account.address;
    console.log("Deploying BNB Chain bridge with account:", deployerAddress);

    const chainId = await publicClient.getChainId();
    console.log("Chain ID:", chainId);

    // =========================================================================
    // Phase 1: Deploy MockWrappedBNB
    // =========================================================================
    console.log("\n📦 Phase 1: Deploying MockWrappedBNB...");

    const wBNB = await hre.viem.deployContract("MockWrappedBNB", [
        deployerAddress,
    ]);
    console.log("  wBNB deployed at:", wBNB.address);

    // =========================================================================
    // Phase 2: Deploy MockBSCValidatorOracle
    // =========================================================================
    console.log("\n📦 Phase 2: Deploying MockBSCValidatorOracle...");

    const oracle = await hre.viem.deployContract("MockBSCValidatorOracle", [
        deployerAddress,
    ]);
    console.log("  ValidatorOracle deployed at:", oracle.address);

    // Register 5 validator addresses (simulating BSC validator set subset)
    const validatorAddresses = [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444",
        "0x5555555555555555555555555555555555555555",
    ] as `0x${string}`[];

    for (const addr of validatorAddresses) {
        await oracle.write.registerValidator([addr]);
    }
    console.log("  Registered 5 validators");

    // =========================================================================
    // Phase 3: Deploy BNBBridgeAdapter
    // =========================================================================
    console.log("\n📦 Phase 3: Deploying BNBBridgeAdapter...");

    const bridge = await hre.viem.deployContract("BNBBridgeAdapter", [
        deployerAddress,
    ]);
    console.log("  BNBBridgeAdapter deployed at:", bridge.address);

    // =========================================================================
    // Phase 4: Configure Bridge
    // =========================================================================
    console.log("\n⚙️  Phase 4: Configuring bridge...");

    // BSC-side bridge contract address (placeholder for production)
    const bscBridgeContract =
        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" as `0x${string}`;

    await bridge.write.configure([
        bscBridgeContract,
        wBNB.address,
        oracle.address,
        BigInt(3), // minValidatorSignatures (3 of 5)
        BigInt(15), // requiredBlockConfirmations
    ]);
    console.log("  Bridge configured");
    console.log("    BSC bridge contract:", bscBridgeContract);
    console.log("    Min validator signatures: 3");
    console.log("    Required block confirmations: 15");

    // =========================================================================
    // Phase 5: Grant Roles
    // =========================================================================
    console.log("\n🔐 Phase 5: Granting roles...");

    // In production, these would be separate addresses
    const relayerAddress = deployerAddress;
    const guardianAddress = deployerAddress;
    const treasuryAddress = deployerAddress;

    const RELAYER_ROLE = await bridge.read.RELAYER_ROLE();
    const GUARDIAN_ROLE = await bridge.read.GUARDIAN_ROLE();
    const TREASURY_ROLE = await bridge.read.TREASURY_ROLE();

    await bridge.write.grantRole([RELAYER_ROLE, relayerAddress]);
    console.log("  Granted RELAYER_ROLE to:", relayerAddress);

    await bridge.write.grantRole([GUARDIAN_ROLE, guardianAddress]);
    console.log("  Granted GUARDIAN_ROLE to:", guardianAddress);

    await bridge.write.grantRole([TREASURY_ROLE, treasuryAddress]);
    console.log("  Granted TREASURY_ROLE to:", treasuryAddress);

    // =========================================================================
    // Phase 6: Grant MINTER_ROLE to bridge on wBNB
    // =========================================================================
    console.log("\n🪙 Phase 6: Granting MINTER_ROLE to bridge...");

    await wBNB.write.grantMinter([bridge.address]);
    console.log("  Granted MINTER_ROLE on wBNB to bridge");

    // =========================================================================
    // Save Deployment Artifact
    // =========================================================================
    const deployment = {
        network: chainId.toString(),
        deployer: deployerAddress,
        timestamp: new Date().toISOString(),
        contracts: {
            MockWrappedBNB: wBNB.address,
            MockBSCValidatorOracle: oracle.address,
            BNBBridgeAdapter: bridge.address,
        },
        configuration: {
            bscBridgeContract,
            minValidatorSignatures: 3,
            requiredBlockConfirmations: 15,
            validatorCount: validatorAddresses.length,
            bridgeFeeBps: 25,
            bscChainId: 56,
            weiPerBnb: "1000000000000000000",
        },
        roles: {
            relayer: relayerAddress,
            guardian: guardianAddress,
            treasury: treasuryAddress,
        },
    };

    const deploymentsDir = path.join(__dirname, "../../deployments");
    if (!fs.existsSync(deploymentsDir)) {
        fs.mkdirSync(deploymentsDir, { recursive: true });
    }

    const artifactPath = path.join(
        deploymentsDir,
        `bnb-bridge-${chainId}.json`
    );
    fs.writeFileSync(artifactPath, JSON.stringify(deployment, null, 2));
    console.log("\n💾 Deployment artifact saved to:", artifactPath);

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n" + "=".repeat(60));
    console.log("  BNB CHAIN BRIDGE DEPLOYMENT COMPLETE");
    console.log("=".repeat(60));
    console.log("  wBNB:               ", wBNB.address);
    console.log("  ValidatorOracle:    ", oracle.address);
    console.log("  BNBBridgeAdapter:   ", bridge.address);
    console.log("  Min Validators:      3/5");
    console.log("  Block Confirmations: 15");
    console.log("  Bridge Fee:          0.25%");
    console.log("=".repeat(60));
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
