/**
 * Soul Protocol — ZK Proof Generation & Relay Example
 *
 * Shows how to use the ProverModule to generate a ZK proof
 * and the RelayerClient to relay it across chains.
 */
import { SoulSDK } from "../../sdk/src/client/SoulSDK";

// --- Configuration -----------------------------------------------------------
const PROVER_URL = process.env.PROVER_URL ?? "http://localhost:3001";
const RELAYER_URL = process.env.RELAYER_URL ?? "http://localhost:3002";
const DEST_CHAIN = process.env.DEST_CHAIN ?? "arbitrum-sepolia";

async function main() {
  // 1. Instantiate the SDK
  const sdk = new SoulSDK({
    proverUrl: PROVER_URL,
    relayerUrl: RELAYER_URL,
  });

  // 2. Generate a ZK proof for the shielded pool circuit
  console.log("Generating proof for 'shielded_pool' circuit...");
  const proof = await sdk.prover.generateProof({
    circuit: "shielded_pool",
    inputs: {
      amount: "1000",
      recipient: "0x000000000000000000000000000000000000dEaD",
    },
  });
  console.log("Proof length:", proof.proof.length, "bytes");
  console.log("Public inputs length:", proof.publicInputs.length, "bytes");

  // 3. Relay the proof
  console.log(`\nRelaying to ${DEST_CHAIN}...`);
  const receipt = await sdk.relayer.relay({
    proof: proof.proof,
    publicInputs: proof.publicInputs,
    destChain: DEST_CHAIN,
  });
  console.log("Relay receipt:", receipt);

  // 4. Subscribe to incoming private state (receiver side)
  console.log("\nListening for incoming private state on this chain...");
  const sub = sdk.receivePrivateState((packet) => {
    console.log("Received packet from:", packet.sourceChain);
    console.log("  timestamp:", new Date(packet.timestamp).toISOString());
  });

  // Clean up after 10 seconds
  setTimeout(() => {
    sub.unsubscribe();
    console.log("\n✅ Done.");
  }, 10_000);
}

main().catch(console.error);
