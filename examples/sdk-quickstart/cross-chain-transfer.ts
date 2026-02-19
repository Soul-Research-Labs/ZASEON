/**
 * Soul Protocol — Cross-Chain Private Transfer Example
 *
 * Uses the CrossChainPrivacyOrchestrator to send a private transfer
 * from one L2 to another.  The orchestrator coordinates:
 *   1. Secret / commitment / nullifier generation
 *   2. ZK proof generation via the ProverModule
 *   3. Relaying the encrypted state to the destination chain
 */
import {
  CrossChainPrivacyOrchestrator,
  type OrchestratorConfig,
  type ChainConfig,
} from "../../sdk/src/privacy/CrossChainPrivacyOrchestrator";

// --- Configuration -----------------------------------------------------------
const config: OrchestratorConfig = {
  chains: new Map<number, ChainConfig>([
    [
      11155111, // Sepolia
      {
        chainId: 11155111,
        rpcUrl: process.env.SEPOLIA_RPC_URL ?? "https://rpc.sepolia.org",
        shieldedPoolAddress: process.env.SEPOLIA_POOL as `0x${string}`,
        nullifierRegistryAddress: process.env
          .SEPOLIA_NULLIFIER as `0x${string}`,
        proofHubAddress: process.env.SEPOLIA_PROOFHUB as `0x${string}`,
      },
    ],
    [
      421614, // Arbitrum Sepolia
      {
        chainId: 421614,
        rpcUrl:
          process.env.ARB_SEPOLIA_RPC_URL ??
          "https://sepolia-rollup.arbitrum.io/rpc",
        shieldedPoolAddress: process.env.ARB_POOL as `0x${string}`,
        nullifierRegistryAddress: process.env.ARB_NULLIFIER as `0x${string}`,
        proofHubAddress: process.env.ARB_PROOFHUB as `0x${string}`,
      },
    ],
  ]),
  proverUrl: process.env.PROVER_URL ?? "http://localhost:3001",
  relayerUrl: process.env.RELAYER_URL ?? "http://localhost:3002",
};

async function main() {
  const orchestrator = new CrossChainPrivacyOrchestrator(config);

  // 1. Generate cryptographic material
  const secret = orchestrator.generateSecret();
  console.log("Generated secret (32 bytes hex):", secret.slice(0, 18) + "...");

  const recipientAddress = "0x000000000000000000000000000000000000dEaD";
  const amount = BigInt(10_000); // smallest unit

  const commitment = orchestrator.computeCommitment(
    amount,
    secret,
    recipientAddress,
  );
  console.log("Commitment:", commitment);

  const nullifier = orchestrator.deriveNullifier(secret, commitment);
  console.log("Nullifier: ", nullifier);

  // 2. Generate ZK proof (requires a running prover server)
  //    Uncomment when the prover service is available:
  //
  // const proof = await orchestrator.generateCrossChainProof({
  //   sourceChainId: 11155111,
  //   destChainId: 421614,
  //   commitment,
  //   nullifier,
  //   amount,
  // });
  // console.log("Proof generated:", proof.proof.length, "bytes");

  console.log("\n✅ Cryptographic material ready for cross-chain transfer.");
  console.log(
    "   Next: run a prover + relayer and call orchestrator.transferPrivateState()",
  );
}

main().catch(console.error);
