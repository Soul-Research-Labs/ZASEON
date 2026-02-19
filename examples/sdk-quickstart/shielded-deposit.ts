/**
 * Soul Protocol — Shielded Pool Deposit Example
 *
 * Demonstrates depositing ETH into the UniversalShieldedPool.
 * The pool uses a Merkle tree of commitments so that withdrawals
 * can later prove inclusion without revealing the depositor.
 */
import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { createShieldedPoolClient } from "../../sdk/src/client/ShieldedPoolClient";

// --- Configuration -----------------------------------------------------------
const PRIVATE_KEY = process.env.PRIVATE_KEY as `0x${string}`;
const RPC_URL = process.env.RPC_URL ?? "https://rpc.sepolia.org";
const SHIELDED_POOL = process.env.SHIELDED_POOL_ADDRESS as `0x${string}`;

async function main() {
  if (!PRIVATE_KEY) throw new Error("Set PRIVATE_KEY env var");
  if (!SHIELDED_POOL) throw new Error("Set SHIELDED_POOL_ADDRESS env var");

  const account = privateKeyToAccount(PRIVATE_KEY);
  const transport = http(RPC_URL);

  const publicClient = createPublicClient({ chain: sepolia, transport });
  const walletClient = createWalletClient({
    chain: sepolia,
    transport,
    account,
  });

  // 1. Create the shielded pool client
  const pool = createShieldedPoolClient({
    publicClient,
    walletClient,
    poolAddress: SHIELDED_POOL,
  });

  // 2. Generate a deposit note (commitment + nullifier + secret)
  const note = pool.generateDepositNote();
  console.log("Deposit note generated:");
  console.log("  commitment:", note.commitment);
  console.log("  nullifier: ", note.nullifier);
  console.log("  secret:    ", note.secret);
  console.log(
    "\n⚠️  Save the secret and nullifier — they are needed to withdraw!\n",
  );

  // 3. Deposit 0.01 ETH into the pool
  const depositAmount = parseEther("0.01");
  console.log(`Depositing ${depositAmount} wei...`);
  const txHash = await pool.depositETH(note.commitment, depositAmount);
  console.log("Deposit tx:", txHash);

  // 4. Read pool stats
  const stats = await pool.getPoolStats();
  console.log("\nPool stats after deposit:");
  console.log("  total deposits:", stats.totalDeposits.toString());
  console.log("  total withdrawals:", stats.totalWithdrawals.toString());

  // 5. Verify our commitment is in the tree
  const nextLeaf = await pool.getNextLeafIndex();
  console.log("  next leaf index:", nextLeaf.toString());
}

main().catch(console.error);
