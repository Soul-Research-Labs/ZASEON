import { ethers } from "hardhat";

/**
 * Deployment script for the Aptos Bridge Adapter
 *
 * Deploys:
 * 1. MockWrappedAPT (wAPT — 8-decimal ERC-20)
 * 2. MockAptosValidatorOracle (AptosBFT validator tracking)
 * 3. AptosBridgeAdapter (main bridge contract)
 *
 * Configures:
 * - Registers 4 initial validators with voting power
 * - Sets min validator signatures to 3 (≥ 2/3+1 of 4)
 * - Sets required ledger confirmations to 6
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-aptos-bridge.ts --network <network>
 */
async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying Aptos Bridge with account:", deployer.address);
    console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)));

    // =========================================================================
    // 1. Deploy MockWrappedAPT
    // =========================================================================
    console.log("\n--- Deploying MockWrappedAPT (wAPT, 8 decimals) ---");
    const MockWrappedAPT = await ethers.getContractFactory("MockWrappedAPT");
    const wAPT = await MockWrappedAPT.deploy();
    await wAPT.waitForDeployment();
    const wAPTAddress = await wAPT.getAddress();
    console.log("MockWrappedAPT deployed to:", wAPTAddress);

    // =========================================================================
    // 2. Deploy MockAptosValidatorOracle
    // =========================================================================
    console.log("\n--- Deploying MockAptosValidatorOracle ---");
    const MockAptosValidatorOracle = await ethers.getContractFactory("MockAptosValidatorOracle");
    const oracle = await MockAptosValidatorOracle.deploy();
    await oracle.waitForDeployment();
    const oracleAddress = await oracle.getAddress();
    console.log("MockAptosValidatorOracle deployed to:", oracleAddress);

    // Register initial validators with voting power (AptosBFT)
    const validators = [
        { address: "0x0000000000000000000000000000000000002001", votingPower: 100 },
        { address: "0x0000000000000000000000000000000000002002", votingPower: 100 },
        { address: "0x0000000000000000000000000000000000002003", votingPower: 100 },
        { address: "0x0000000000000000000000000000000000002004", votingPower: 100 },
    ];

    for (let i = 0; i < validators.length; i++) {
        const tx = await oracle.addValidator(validators[i].address, validators[i].votingPower);
        await tx.wait();
        console.log(`  Validator ${i + 1} registered: ${validators[i].address} (power: ${validators[i].votingPower})`);
    }

    // =========================================================================
    // 3. Deploy AptosBridgeAdapter
    // =========================================================================
    console.log("\n--- Deploying AptosBridgeAdapter ---");
    const AptosBridgeAdapter = await ethers.getContractFactory("AptosBridgeAdapter");
    const bridge = await AptosBridgeAdapter.deploy(deployer.address);
    await bridge.waitForDeployment();
    const bridgeAddress = await bridge.getAddress();
    console.log("AptosBridgeAdapter deployed to:", bridgeAddress);

    // =========================================================================
    // 4. Configure Bridge
    // =========================================================================
    console.log("\n--- Configuring AptosBridgeAdapter ---");

    const aptosBridgeContract = ethers.ZeroAddress.replace(/.$/, "1"); // Placeholder
    const minValidatorSignatures = 3;
    const requiredLedgerConfirmations = 6;

    const configureTx = await bridge.configure(
        aptosBridgeContract,
        wAPTAddress,
        oracleAddress,
        minValidatorSignatures,
        requiredLedgerConfirmations
    );
    await configureTx.wait();
    console.log("  Bridge configured:");
    console.log("    aptosBridgeContract:", aptosBridgeContract);
    console.log("    wrappedAPT:", wAPTAddress);
    console.log("    validatorOracle:", oracleAddress);
    console.log("    minValidatorSignatures:", minValidatorSignatures);
    console.log("    requiredLedgerConfirmations:", requiredLedgerConfirmations);

    // Mint initial wAPT supply to bridge for testing
    const initialSupply = ethers.parseUnits("1000000", 8); // 1M APT in Octas
    const mintTx = await wAPT.mint(bridgeAddress, initialSupply);
    await mintTx.wait();
    console.log("  Initial wAPT minted to bridge:", ethers.formatUnits(initialSupply, 8), "APT");

    // =========================================================================
    // Summary
    // =========================================================================
    console.log("\n========================================");
    console.log("  APTOS BRIDGE DEPLOYMENT COMPLETE");
    console.log("========================================");
    console.log("Network:", (await ethers.provider.getNetwork()).name);
    console.log("Chain ID:", (await ethers.provider.getNetwork()).chainId.toString());
    console.log("");
    console.log("Contracts:");
    console.log("  MockWrappedAPT:            ", wAPTAddress);
    console.log("  MockAptosValidatorOracle:  ", oracleAddress);
    console.log("  AptosBridgeAdapter:        ", bridgeAddress);
    console.log("");
    console.log("Configuration:");
    console.log("  Aptos Chain ID:                  1");
    console.log("  Token Decimals:                  8 (Octas)");
    console.log("  Bridge Fee:                      0.04% (4 BPS)");
    console.log("  Min Deposit:                     0.1 APT");
    console.log("  Max Deposit:                     10,000,000 APT");
    console.log("  Withdrawal Refund Delay:         24 hours");
    console.log("  Min Escrow Timelock:             1 hour");
    console.log("  Max Escrow Timelock:             30 days");
    console.log("  Ledger Confirmations:            6");
    console.log("  Validators Registered:           4");
    console.log("  Min Validator Signatures:        3");
    console.log("  Consensus:                       AptosBFT (~160ms)");
    console.log("========================================");

    // Write deployment artifact
    const fs = await import("fs");
    const artifact = {
        network: (await ethers.provider.getNetwork()).name,
        chainId: (await ethers.provider.getNetwork()).chainId.toString(),
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
        contracts: {
            MockWrappedAPT: wAPTAddress,
            MockAptosValidatorOracle: oracleAddress,
            AptosBridgeAdapter: bridgeAddress,
        },
        configuration: {
            aptosChainId: 1,
            tokenDecimals: 8,
            denomination: "Octas",
            bridgeFeeBps: 4,
            minDepositApt: "0.1",
            maxDepositApt: "10000000",
            withdrawalRefundDelayHours: 24,
            minEscrowTimelockHours: 1,
            maxEscrowTimelockDays: 30,
            ledgerConfirmations: requiredLedgerConfirmations,
            validatorCount: validators.length,
            minValidatorSignatures: minValidatorSignatures,
            consensus: "AptosBFT (DiemBFT v4)",
            blockTimeMs: 160,
        },
    };

    const path = `deployments/aptos-bridge-${(await ethers.provider.getNetwork()).chainId}.json`;
    fs.writeFileSync(path, JSON.stringify(artifact, null, 2));
    console.log(`\nDeployment artifact written to: ${path}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
