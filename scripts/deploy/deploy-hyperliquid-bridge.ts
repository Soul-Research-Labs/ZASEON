/**
 * Soul Protocol - Hyperliquid Bridge Deployment Script
 *
 * Deploys the complete Hyperliquid bridge infrastructure:
 * 1. MockWrappedHYPE (wHYPE) ERC-20 token (8 decimals)
 * 2. MockHyperBFTValidatorOracle (HyperBFT validator mock)
 * 3. HyperliquidBridgeAdapter
 * 4. Configure bridge parameters
 * 5. Grant roles (RELAYER, GUARDIAN, TREASURY)
 * 6. Verify deployment
 *
 * Hyperliquid-specific:
 * - Chain ID: 999 (HyperEVM mainnet)
 * - 1 HYPE = 1e8 drips (8 decimals)
 * - 4 active validators, 3/4 supermajority
 * - 3 block confirmations (~0.6s BFT finality)
 * - 0.15% bridge fee
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-hyperliquid-bridge.ts --network <network>
 */

import hre from "hardhat";
import fs from "fs";
import path from "path";

async function main() {
    const [deployer] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();

    const deployerAddress = deployer.account.address;
    console.log(
        "Deploying Hyperliquid bridge with account:",
        deployerAddress
    );

    const chainId = await publicClient.getChainId();
    console.log("Chain ID:", chainId);

    // =========================================================================
    // Phase 1: Deploy MockWrappedHYPE
    // =========================================================================
    console.log("\n📦 Phase 1: Deploying MockWrappedHYPE (8 decimals)...");

    const wHYPE = await hre.viem.deployContract("MockWrappedHYPE", []);
    console.log("  wHYPE deployed at:", wHYPE.address);

    // =========================================================================
    // Phase 2: Deploy MockHyperBFTValidatorOracle
    // =========================================================================
    console.log("\n📦 Phase 2: Deploying MockHyperBFTValidatorOracle...");

    const oracle = await hre.viem.deployContract(
        "MockHyperBFTValidatorOracle",
        []
    );
    console.log("  ValidatorOracle deployed at:", oracle.address);

    // Register 4 HyperBFT validator addresses
    const validatorAddresses = [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444",
    ] as `0x${string}`[];

    for (const addr of validatorAddresses) {
        await oracle.write.addValidator([addr]);
    }
    console.log("  Registered 4 HyperBFT validators");

    // =========================================================================
    // Phase 3: Deploy HyperliquidBridgeAdapter
    // =========================================================================
    console.log("\n📦 Phase 3: Deploying HyperliquidBridgeAdapter...");

    const bridge = await hre.viem.deployContract("HyperliquidBridgeAdapter", [
        deployerAddress,
    ]);
    console.log("  HyperliquidBridgeAdapter deployed at:", bridge.address);

    // =========================================================================
    // Phase 4: Configure Bridge
    // =========================================================================
    console.log("\n⚙️  Phase 4: Configuring bridge...");

    // Hyperliquid-side bridge contract address (placeholder for production)
    const hlBridgeContract =
        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" as `0x${string}`;

    await bridge.write.configure([
        hlBridgeContract,
        wHYPE.address,
        oracle.address,
        BigInt(3), // minValidatorSignatures (3 of 4 = supermajority)
        BigInt(3), // requiredBlockConfirmations (~0.6s BFT finality)
    ]);
    console.log("  Bridge configured");
    console.log("    Hyperliquid bridge contract:", hlBridgeContract);
    console.log("    Min validator signatures: 3 (of 4)");
    console.log("    Required block confirmations: 3 (~0.6s)");

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
    // Phase 6: Verify Deployment
    // =========================================================================
    console.log("\n✅ Phase 6: Verifying deployment...");

    const config = await bridge.read.bridgeConfig();
    console.log("  Bridge active:", config[5]); // .active field
    console.log("  wHYPE address matches:", config[1] === wHYPE.address);
    console.log(
        "  Oracle address matches:",
        config[2] === oracle.address
    );

    // =========================================================================
    // Save Deployment Artifact
    // =========================================================================
    const deployment = {
        network: chainId.toString(),
        deployer: deployerAddress,
        timestamp: new Date().toISOString(),
        contracts: {
            MockWrappedHYPE: wHYPE.address,
            MockHyperBFTValidatorOracle: oracle.address,
            HyperliquidBridgeAdapter: bridge.address,
        },
        configuration: {
            hlBridgeContract,
            minValidatorSignatures: 3,
            requiredBlockConfirmations: 3,
            validatorCount: validatorAddresses.length,
            bridgeFeeBps: 15,
            hyperliquidChainId: 999,
            dripsPerHype: "100000000",
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
        `hyperliquid-bridge-${chainId}.json`
    );
    fs.writeFileSync(artifactPath, JSON.stringify(deployment, null, 2));
    console.log("\n💾 Deployment artifact saved to:", artifactPath);

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n" + "=".repeat(60));
    console.log("  HYPERLIQUID BRIDGE DEPLOYMENT COMPLETE");
    console.log("=".repeat(60));
    console.log("  wHYPE (8 dec):       ", wHYPE.address);
    console.log("  ValidatorOracle:     ", oracle.address);
    console.log("  HyperliquidBridge:   ", bridge.address);
    console.log("  Min Validators:       3/4 (BFT supermajority)");
    console.log("  Block Confirmations:  3 (~0.6s)");
    console.log("  Bridge Fee:           0.15%");
    console.log("  HYPE Precision:       8 decimals (1e8 drips)");
    console.log("  Chain ID:             999 (HyperEVM)");
    console.log("=".repeat(60));
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
