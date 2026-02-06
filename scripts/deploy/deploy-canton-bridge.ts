/**
 * Soul Protocol - Canton Network Bridge Deployment Script
 *
 * Deploys the complete Canton Network bridge infrastructure:
 * 1. MockWrappedCANTON (wCANTON) ERC-20 token (6 decimals)
 * 2. MockCantonMediatorOracle (Global Synchronizer mediator mock)
 * 3. CantonBridgeAdapter
 * 4. Configure bridge parameters
 * 5. Grant roles (RELAYER, GUARDIAN, TREASURY)
 * 6. Verify deployment
 *
 * Canton Network-specific:
 * - Chain ID: 510 (canton-global-1 EVM mapping)
 * - 1 CANTON = 1e6 microcanton (6 decimals)
 * - 6 active mediators (test), 5/6 supermajority
 * - 5 round confirmations (~10s synchronizer finality)
 * - 0.05% bridge fee (5 BPS)
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-canton-bridge.ts --network <network>
 */

import hre from "hardhat";
import fs from "fs";
import path from "path";

async function main() {
    const [deployer] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();

    const deployerAddress = deployer.account.address;
    console.log(
        "Deploying Canton Network bridge with account:",
        deployerAddress
    );

    const chainId = await publicClient.getChainId();
    console.log("Chain ID:", chainId);

    // =========================================================================
    // Phase 1: Deploy MockWrappedCANTON
    // =========================================================================
    console.log("\n📦 Phase 1: Deploying MockWrappedCANTON (6 decimals)...");

    const wCANTON = await hre.viem.deployContract("MockWrappedCANTON", []);
    console.log("  wCANTON deployed at:", wCANTON.address);

    // =========================================================================
    // Phase 2: Deploy MockCantonMediatorOracle
    // =========================================================================
    console.log("\n📦 Phase 2: Deploying MockCantonMediatorOracle...");

    const oracle = await hre.viem.deployContract(
        "MockCantonMediatorOracle",
        []
    );
    console.log("  MediatorOracle deployed at:", oracle.address);

    // Register 6 Canton Global Synchronizer mediator addresses
    const mediatorAddresses = [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444",
        "0x5555555555555555555555555555555555555555",
        "0x6666666666666666666666666666666666666666",
    ] as `0x${string}`[];

    for (const addr of mediatorAddresses) {
        await oracle.write.addMediator([addr]);
    }
    console.log("  Registered 6 Canton mediators");

    // =========================================================================
    // Phase 3: Deploy CantonBridgeAdapter
    // =========================================================================
    console.log("\n📦 Phase 3: Deploying CantonBridgeAdapter...");

    const bridge = await hre.viem.deployContract("CantonBridgeAdapter", [
        deployerAddress,
    ]);
    console.log("  CantonBridgeAdapter deployed at:", bridge.address);

    // =========================================================================
    // Phase 4: Configure Bridge
    // =========================================================================
    console.log("\n⚙️  Phase 4: Configuring bridge...");

    // Canton-side bridge contract address (placeholder for production)
    const cantonBridgeContract =
        "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" as `0x${string}`;

    await bridge.write.configure([
        cantonBridgeContract,
        wCANTON.address,
        oracle.address,
        BigInt(5), // minMediatorSignatures (5 of 6 = supermajority)
        BigInt(5), // requiredRoundConfirmations (~10s)
    ]);
    console.log("  Bridge configured");
    console.log("    Canton bridge contract:", cantonBridgeContract);
    console.log("    Min mediator signatures: 5 (of 6)");
    console.log("    Required round confirmations: 5 (~10s)");

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
    console.log("  wCANTON address matches:", config[1] === wCANTON.address);
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
            MockWrappedCANTON: wCANTON.address,
            MockCantonMediatorOracle: oracle.address,
            CantonBridgeAdapter: bridge.address,
        },
        configuration: {
            cantonBridgeContract,
            minMediatorSignatures: 5,
            requiredRoundConfirmations: 5,
            mediatorCount: mediatorAddresses.length,
            bridgeFeeBps: 5,
            cantonChainId: 510,
            microcantonPerCanton: "1000000",
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
        `canton-bridge-${chainId}.json`
    );
    fs.writeFileSync(artifactPath, JSON.stringify(deployment, null, 2));
    console.log("\n💾 Deployment artifact saved to:", artifactPath);

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n" + "=".repeat(60));
    console.log("  CANTON NETWORK BRIDGE DEPLOYMENT COMPLETE");
    console.log("=".repeat(60));
    console.log("  wCANTON (6 dec):      ", wCANTON.address);
    console.log("  MediatorOracle:       ", oracle.address);
    console.log("  CantonBridge:         ", bridge.address);
    console.log("  Min Mediators:         5/6 (supermajority)");
    console.log("  Round Confirmations:   5 (~10s)");
    console.log("  Bridge Fee:            0.05%");
    console.log("  CANTON Precision:      6 decimals (1e6 microcanton)");
    console.log("  Chain ID:              510 (canton-global-1)");
    console.log("=".repeat(60));
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
