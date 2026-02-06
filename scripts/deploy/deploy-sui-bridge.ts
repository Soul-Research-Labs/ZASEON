import { ethers } from "hardhat";

/**
 * Deployment script for the Sui Bridge Adapter
 *
 * Deploys:
 * 1. MockWrappedSUI (wSUI — 9-decimal ERC-20)
 * 2. MockSuiValidatorOracle (validator committee tracking)
 * 3. SuiBridgeAdapter (main bridge contract)
 *
 * Configures:
 * - Registers 4 initial validators (BLS pub key hashes)
 * - Sets min committee signatures to 3 (≥ 2/3+1 of 4)
 * - Sets required checkpoint confirmations to 10
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-sui-bridge.ts --network <network>
 */
async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying Sui Bridge with account:", deployer.address);
    console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

    // =========================================================================
    // 1. Deploy MockWrappedSUI
    // =========================================================================
    console.log("\n--- Deploying MockWrappedSUI (wSUI, 9 decimals) ---");
    const MockWrappedSUI = await ethers.getContractFactory("MockWrappedSUI");
    const wSUI = await MockWrappedSUI.deploy();
    await wSUI.waitForDeployment();
    const wSUIAddress = await wSUI.getAddress();
    console.log("MockWrappedSUI deployed to:", wSUIAddress);

    // =========================================================================
    // 2. Deploy MockSuiValidatorOracle
    // =========================================================================
    console.log("\n--- Deploying MockSuiValidatorOracle ---");
    const MockSuiValidatorOracle = await ethers.getContractFactory("MockSuiValidatorOracle");
    const oracle = await MockSuiValidatorOracle.deploy();
    await oracle.waitForDeployment();
    const oracleAddress = await oracle.getAddress();
    console.log("MockSuiValidatorOracle deployed to:", oracleAddress);

    // Register initial validators (4 validators for Sui committee)
    const validators = [
        ethers.keccak256(ethers.toUtf8Bytes("sui_validator_1")),
        ethers.keccak256(ethers.toUtf8Bytes("sui_validator_2")),
        ethers.keccak256(ethers.toUtf8Bytes("sui_validator_3")),
        ethers.keccak256(ethers.toUtf8Bytes("sui_validator_4")),
    ];

    for (let i = 0; i < validators.length; i++) {
        const tx = await oracle.addValidator(validators[i]);
        await tx.wait();
        console.log(`  Validator ${i + 1} registered: ${validators[i].slice(0, 18)}...`);
    }

    // Set minimum signatures to 3 (≥ 2/3+1 of 4 validators)
    const minSigsTx = await oracle.setMinRequiredSignatures(3);
    await minSigsTx.wait();
    console.log("  Min required signatures set to 3");

    // =========================================================================
    // 3. Deploy SuiBridgeAdapter
    // =========================================================================
    console.log("\n--- Deploying SuiBridgeAdapter ---");
    const SuiBridgeAdapter = await ethers.getContractFactory("SuiBridgeAdapter");
    const bridge = await SuiBridgeAdapter.deploy(deployer.address);
    await bridge.waitForDeployment();
    const bridgeAddress = await bridge.getAddress();
    console.log("SuiBridgeAdapter deployed to:", bridgeAddress);

    // =========================================================================
    // 4. Configure Bridge
    // =========================================================================
    console.log("\n--- Configuring SuiBridgeAdapter ---");

    const suiBridgeContract = ethers.ZeroAddress.replace(/.$/, "1"); // Placeholder
    const minCommitteeSignatures = 3;
    const requiredCheckpointConfirmations = 10;

    const configureTx = await bridge.configure(
        suiBridgeContract,
        wSUIAddress,
        oracleAddress,
        minCommitteeSignatures,
        requiredCheckpointConfirmations
    );
    await configureTx.wait();
    console.log("  Bridge configured:");
    console.log("    suiBridgeContract:", suiBridgeContract);
    console.log("    wrappedSUI:", wSUIAddress);
    console.log("    validatorCommitteeOracle:", oracleAddress);
    console.log("    minCommitteeSignatures:", minCommitteeSignatures);
    console.log("    requiredCheckpointConfirmations:", requiredCheckpointConfirmations);

    // Mint initial wSUI supply to bridge for testing
    const initialSupply = ethers.parseUnits("1000000", 9); // 1M SUI in MIST
    const mintTx = await wSUI.mint(bridgeAddress, initialSupply);
    await mintTx.wait();
    console.log("  Initial wSUI minted to bridge:", ethers.formatUnits(initialSupply, 9), "SUI");

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n========================================");
    console.log("  SUI BRIDGE DEPLOYMENT COMPLETE");
    console.log("========================================");
    console.log("Network:", (await ethers.provider.getNetwork()).name);
    console.log("Chain ID:", (await ethers.provider.getNetwork()).chainId.toString());
    console.log("");
    console.log("Contracts:");
    console.log("  MockWrappedSUI:         ", wSUIAddress);
    console.log("  MockSuiValidatorOracle: ", oracleAddress);
    console.log("  SuiBridgeAdapter:       ", bridgeAddress);
    console.log("");
    console.log("Configuration:");
    console.log("  Sui Chain ID:                    784");
    console.log("  Token Decimals:                  9 (MIST)");
    console.log("  Bridge Fee:                      0.06% (6 BPS)");
    console.log("  Min Deposit:                     0.1 SUI");
    console.log("  Max Deposit:                     10,000,000 SUI");
    console.log("  Withdrawal Refund Delay:         48 hours");
    console.log("  Min Escrow Timelock:             1 hour");
    console.log("  Max Escrow Timelock:             30 days");
    console.log("  Checkpoint Confirmations:        10");
    console.log("  Validators Registered:           4");
    console.log("  Min Committee Signatures:        3");
    console.log("  Consensus:                       Mysticeti BFT (~400ms)");
    console.log("========================================");

    // Write deployment artifact
    const fs = await import("fs");
    const artifact = {
        network: (await ethers.provider.getNetwork()).name,
        chainId: (await ethers.provider.getNetwork()).chainId.toString(),
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
        contracts: {
            MockWrappedSUI: wSUIAddress,
            MockSuiValidatorOracle: oracleAddress,
            SuiBridgeAdapter: bridgeAddress,
        },
        configuration: {
            suiChainId: 784,
            tokenDecimals: 9,
            denomination: "MIST",
            bridgeFeeBps: 6,
            minDepositSui: "0.1",
            maxDepositSui: "10000000",
            withdrawalRefundDelayHours: 48,
            minEscrowTimelockHours: 1,
            maxEscrowTimelockDays: 30,
            checkpointConfirmations: requiredCheckpointConfirmations,
            validatorCount: validators.length,
            minCommitteeSignatures: minCommitteeSignatures,
            consensus: "Mysticeti BFT",
            blockTimeMs: 400,
        },
    };

    const path = `deployments/sui-bridge-${(await ethers.provider.getNetwork()).chainId}.json`;
    fs.writeFileSync(path, JSON.stringify(artifact, null, 2));
    console.log(`\nDeployment artifact written to: ${path}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
