import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Soul Protocol — XRP Ledger Bridge Deployment Script
 *
 * Deploys:
 * 1. MockWrappedXRP (or connects to existing wXRP token)
 * 2. MockXRPLValidatorOracle (or connects to existing oracle)
 * 3. XRPLBridgeAdapter
 * 4. Configures roles, bridge parameters, and minter permissions
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-xrpl-bridge.ts --network sepolia
 *   npx hardhat run scripts/deploy/deploy-xrpl-bridge.ts --network localhost
 *
 * Environment Variables:
 *   XRPL_WRAPPED_XRP_ADDRESS  — Existing wXRP token address (skip mock deploy)
 *   XRPL_VALIDATOR_ORACLE     — Existing oracle address (skip mock deploy)
 *   XRPL_MULTISIG_ACCOUNT     — XRPL bridge multisig (hex-encoded bytes20)
 *   XRPL_MIN_SIGNATURES       — Minimum validator signatures (default: 3)
 *   XRPL_LEDGER_CONFIRMATIONS — Required ledger confirmations (default: 32)
 *   RELAYER_ADDRESS            — Address to grant RELAYER_ROLE
 *   GUARDIAN_ADDRESS           — Address to grant GUARDIAN_ROLE
 *   TREASURY_ADDRESS           — Address to set as fee treasury
 */

interface XRPLDeployment {
  network: string;
  chainId: number;
  timestamp: string;
  deployer: string;
  contracts: {
    wrappedXRP: string;
    validatorOracle: string;
    xrplBridgeAdapter: string;
  };
  configuration: {
    xrplMultisigAccount: string;
    minSignatures: number;
    requiredLedgerConfirmations: number;
  };
  roles: {
    admin: string;
    relayer: string;
    guardian: string;
    treasury: string;
  };
  txHashes: Record<string, string>;
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const chainId = (await ethers.provider.getNetwork()).chainId;

  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║          Soul Protocol — XRPL Bridge Deployment        ║");
  console.log("╚══════════════════════════════════════════════════════════╝");
  console.log(`  Network:  ${network.name} (chain ${chainId})`);
  console.log(`  Deployer: ${deployer.address}`);
  console.log(`  Balance:  ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} ETH`);
  console.log("");

  const deployment: XRPLDeployment = {
    network: network.name,
    chainId: Number(chainId),
    timestamp: new Date().toISOString(),
    deployer: deployer.address,
    contracts: { wrappedXRP: "", validatorOracle: "", xrplBridgeAdapter: "" },
    configuration: { xrplMultisigAccount: "", minSignatures: 0, requiredLedgerConfirmations: 0 },
    roles: { admin: "", relayer: "", guardian: "", treasury: "" },
    txHashes: {},
  };

  // ─── Phase 1: Deploy or connect wXRP token ────────────────────────
  console.log("📦 Phase 1: Wrapped XRP Token");

  let wrappedXRPAddress: string;
  if (process.env.XRPL_WRAPPED_XRP_ADDRESS) {
    wrappedXRPAddress = process.env.XRPL_WRAPPED_XRP_ADDRESS;
    console.log(`  ✅ Using existing wXRP: ${wrappedXRPAddress}`);
  } else {
    console.log("  🔨 Deploying MockWrappedXRP...");
    const MockWrappedXRP = await ethers.getContractFactory("MockWrappedXRP");
    const wXRP = await MockWrappedXRP.deploy(deployer.address);
    await wXRP.waitForDeployment();
    wrappedXRPAddress = await wXRP.getAddress();
    deployment.txHashes["MockWrappedXRP"] = wXRP.deploymentTransaction()?.hash || "";
    console.log(`  ✅ MockWrappedXRP deployed: ${wrappedXRPAddress}`);
  }
  deployment.contracts.wrappedXRP = wrappedXRPAddress;

  // ─── Phase 2: Deploy or connect Validator Oracle ──────────────────
  console.log("\n🔮 Phase 2: Validator Oracle");

  let oracleAddress: string;
  if (process.env.XRPL_VALIDATOR_ORACLE) {
    oracleAddress = process.env.XRPL_VALIDATOR_ORACLE;
    console.log(`  ✅ Using existing oracle: ${oracleAddress}`);
  } else {
    console.log("  🔨 Deploying MockXRPLValidatorOracle...");
    const MockOracle = await ethers.getContractFactory("MockXRPLValidatorOracle");
    const oracle = await MockOracle.deploy(deployer.address);
    await oracle.waitForDeployment();
    oracleAddress = await oracle.getAddress();
    deployment.txHashes["MockXRPLValidatorOracle"] = oracle.deploymentTransaction()?.hash || "";
    console.log(`  ✅ MockXRPLValidatorOracle deployed: ${oracleAddress}`);

    // Register default validators
    console.log("  🔑 Registering default validators...");
    const validatorKeys = [
      ethers.keccak256(ethers.toUtf8Bytes("xrpl_validator_1")),
      ethers.keccak256(ethers.toUtf8Bytes("xrpl_validator_2")),
      ethers.keccak256(ethers.toUtf8Bytes("xrpl_validator_3")),
      ethers.keccak256(ethers.toUtf8Bytes("xrpl_validator_4")),
      ethers.keccak256(ethers.toUtf8Bytes("xrpl_validator_5")),
    ];
    const tx = await oracle.registerValidators(validatorKeys);
    await tx.wait();
    console.log(`  ✅ ${validatorKeys.length} validators registered`);
  }
  deployment.contracts.validatorOracle = oracleAddress;

  // ─── Phase 3: Deploy XRPLBridgeAdapter ────────────────────────────
  console.log("\n🌉 Phase 3: XRPL Bridge Adapter");
  console.log("  🔨 Deploying XRPLBridgeAdapter...");

  const BridgeAdapter = await ethers.getContractFactory("XRPLBridgeAdapter");
  const bridge = await BridgeAdapter.deploy(deployer.address);
  await bridge.waitForDeployment();
  const bridgeAddress = await bridge.getAddress();
  deployment.txHashes["XRPLBridgeAdapter"] = bridge.deploymentTransaction()?.hash || "";
  console.log(`  ✅ XRPLBridgeAdapter deployed: ${bridgeAddress}`);
  deployment.contracts.xrplBridgeAdapter = bridgeAddress;

  // ─── Phase 4: Configure Bridge ────────────────────────────────────
  console.log("\n⚙️  Phase 4: Configuration");

  const xrplMultisig = process.env.XRPL_MULTISIG_ACCOUNT || "0x" + "AA".repeat(20);
  const minSignatures = parseInt(process.env.XRPL_MIN_SIGNATURES || "3");
  const ledgerConfirmations = parseInt(process.env.XRPL_LEDGER_CONFIRMATIONS || "32");

  console.log(`  📝 XRPL Multisig:    ${xrplMultisig}`);
  console.log(`  📝 Min Signatures:   ${minSignatures}`);
  console.log(`  📝 Ledger Confirms:  ${ledgerConfirmations}`);

  const configTx = await bridge.configure(
    xrplMultisig,
    wrappedXRPAddress,
    oracleAddress,
    minSignatures,
    ledgerConfirmations
  );
  await configTx.wait();
  deployment.txHashes["configure"] = configTx.hash;
  console.log("  ✅ Bridge configured");

  deployment.configuration = {
    xrplMultisigAccount: xrplMultisig,
    minSignatures,
    requiredLedgerConfirmations: ledgerConfirmations,
  };

  // ─── Phase 5: Grant Roles ─────────────────────────────────────────
  console.log("\n🔐 Phase 5: Role Assignment");

  const relayerAddr = process.env.RELAYER_ADDRESS || deployer.address;
  const guardianAddr = process.env.GUARDIAN_ADDRESS || deployer.address;
  const treasuryAddr = process.env.TREASURY_ADDRESS || deployer.address;

  // Grant RELAYER_ROLE
  const RELAYER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("RELAYER_ROLE"));
  if (relayerAddr !== deployer.address) {
    const tx1 = await bridge.grantRole(RELAYER_ROLE, relayerAddr);
    await tx1.wait();
    deployment.txHashes["grantRelayer"] = tx1.hash;
  }
  console.log(`  ✅ RELAYER_ROLE → ${relayerAddr}`);

  // Grant GUARDIAN_ROLE
  const GUARDIAN_ROLE = ethers.keccak256(ethers.toUtf8Bytes("GUARDIAN_ROLE"));
  if (guardianAddr !== deployer.address) {
    const tx2 = await bridge.grantRole(GUARDIAN_ROLE, guardianAddr);
    await tx2.wait();
    deployment.txHashes["grantGuardian"] = tx2.hash;
  }
  console.log(`  ✅ GUARDIAN_ROLE → ${guardianAddr}`);

  // Set treasury
  if (treasuryAddr !== deployer.address) {
    const tx3 = await bridge.setTreasury(treasuryAddr);
    await tx3.wait();
    deployment.txHashes["setTreasury"] = tx3.hash;
  }
  console.log(`  ✅ Treasury → ${treasuryAddr}`);

  deployment.roles = {
    admin: deployer.address,
    relayer: relayerAddr,
    guardian: guardianAddr,
    treasury: treasuryAddr,
  };

  // ─── Phase 6: Grant Minter Role on wXRP ───────────────────────────
  console.log("\n🪙  Phase 6: Token Permissions");

  if (!process.env.XRPL_WRAPPED_XRP_ADDRESS) {
    const wXRPContract = await ethers.getContractAt("MockWrappedXRP", wrappedXRPAddress);
    const grantMintTx = await wXRPContract.grantMinter(bridgeAddress);
    await grantMintTx.wait();
    deployment.txHashes["grantMinter"] = grantMintTx.hash;
    console.log(`  ✅ MINTER_ROLE granted to bridge on wXRP`);
  } else {
    console.log("  ⚠️  Using external wXRP — grant MINTER_ROLE manually");
  }

  // ─── Save Deployment ──────────────────────────────────────────────
  console.log("\n💾 Saving deployment...");

  const deploymentsDir = path.join(__dirname, "..", "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const filename = `xrpl-bridge-${network.name}-${chainId}.json`;
  const filepath = path.join(deploymentsDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(deployment, null, 2));
  console.log(`  ✅ Saved to deployments/${filename}`);

  // ─── Summary ──────────────────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════════════════╗");
  console.log("║                 Deployment Summary                      ║");
  console.log("╠══════════════════════════════════════════════════════════╣");
  console.log(`║  MockWrappedXRP:          ${wrappedXRPAddress}`);
  console.log(`║  MockXRPLValidatorOracle: ${oracleAddress}`);
  console.log(`║  XRPLBridgeAdapter:       ${bridgeAddress}`);
  console.log("╠══════════════════════════════════════════════════════════╣");
  console.log(`║  XRPL Multisig: ${xrplMultisig}`);
  console.log(`║  Min Sigs: ${minSignatures} | Ledger Confirms: ${ledgerConfirmations}`);
  console.log("╚══════════════════════════════════════════════════════════╝");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
