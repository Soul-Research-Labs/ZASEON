import { RelayerService, RelayerConfig } from "./network/RelayerService";

async function main() {
  console.log("═".repeat(60));
  console.log("  PIL Relayer Node Starting...");
  console.log("═".repeat(60));

  const config: RelayerConfig = {
    stake: parseFloat(process.env.MIN_STAKE || "0.1"),
    endpoints: (process.env.ENDPOINTS || "http://localhost:8545").split(","),
    chains: (process.env.CHAINS || "ethereum,polygon,arbitrum").split(","),
    decoyTrafficRatio: parseFloat(process.env.DECOY_RATIO || "0.1"),
    minDelay: parseInt(process.env.MIN_DELAY || "100"),
    maxDelay: parseInt(process.env.MAX_DELAY || "5000"),
  };

  console.log("\n📋 Configuration:");
  console.log(`   Stake: ${config.stake} ETH`);
  console.log(`   Endpoints: ${config.endpoints.join(", ")}`);
  console.log(`   Chains: ${config.chains.join(", ")}`);
  console.log(`   Decoy Ratio: ${config.decoyTrafficRatio}`);
  console.log(`   Delay Range: ${config.minDelay}-${config.maxDelay}ms\n`);

  const relayer = new RelayerService(config);

  // Handle graceful shutdown
  process.on("SIGINT", () => {
    console.log("\n⚠️  Shutting down relayer...");
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    console.log("\n⚠️  Received SIGTERM, shutting down...");
    process.exit(0);
  });

  try {
    await relayer.start();
    console.log("✅ Relayer is running. Press Ctrl+C to stop.\n");
    
    // Keep the process alive
    await new Promise(() => {});
  } catch (error) {
    console.error("❌ Failed to start relayer:", error);
    process.exit(1);
  }
}

main().catch(console.error);
