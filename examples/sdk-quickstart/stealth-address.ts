/**
 * Soul Protocol — Stealth Address Example
 *
 * Demonstrates the full stealth address lifecycle:
 *   1. Receiver registers a stealth meta-address (spending + viewing keys)
 *   2. Sender derives a one-time stealth address for the receiver
 *   3. Sender announces the payment (ephemeral public key)
 *   4. Receiver scans announcements to discover payments
 */
import StealthAddressClient, {
  StealthScheme,
} from "../../sdk/src/privacy/StealthAddressClient";
import { createPublicClient, createWalletClient, http } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// --- Configuration -----------------------------------------------------------
const REGISTRY_ADDRESS = process.env.STEALTH_REGISTRY as `0x${string}`;
const RECEIVER_KEY = process.env.RECEIVER_PRIVATE_KEY as `0x${string}`;
const SENDER_KEY = process.env.SENDER_PRIVATE_KEY as `0x${string}`;
const RPC_URL = process.env.RPC_URL ?? "https://rpc.sepolia.org";

async function main() {
  if (!REGISTRY_ADDRESS) throw new Error("Set STEALTH_REGISTRY env var");
  if (!RECEIVER_KEY) throw new Error("Set RECEIVER_PRIVATE_KEY env var");
  if (!SENDER_KEY) throw new Error("Set SENDER_PRIVATE_KEY env var");

  const transport = http(RPC_URL);

  // --- Receiver setup --------------------------------------------------------
  const receiverAccount = privateKeyToAccount(RECEIVER_KEY);
  const receiverWallet = createWalletClient({
    chain: sepolia,
    transport,
    account: receiverAccount,
  });
  const publicClient = createPublicClient({ chain: sepolia, transport });

  const receiverClient = new StealthAddressClient(
    publicClient as any,
    receiverWallet as any,
    REGISTRY_ADDRESS,
  );

  // 1. Register meta-address  (spending key + viewing key)
  console.log("1. Registering stealth meta-address for receiver...");
  const metaAddress = await receiverClient.registerMetaAddress(
    StealthScheme.DUAL_KEY,
  );
  console.log(
    "   spending pub:",
    metaAddress.spendingPubKey.slice(0, 20) + "...",
  );
  console.log(
    "   viewing pub: ",
    metaAddress.viewingPubKey.slice(0, 20) + "...",
  );

  // --- Sender setup ----------------------------------------------------------
  const senderAccount = privateKeyToAccount(SENDER_KEY);
  const senderWallet = createWalletClient({
    chain: sepolia,
    transport,
    account: senderAccount,
  });

  const senderClient = new StealthAddressClient(
    publicClient as any,
    senderWallet as any,
    REGISTRY_ADDRESS,
  );

  // 2. Derive a one-time stealth address for the receiver
  console.log("\n2. Deriving stealth address...");
  const stealth = await senderClient.generateStealthAddress(
    receiverAccount.address,
  );
  console.log("   stealth address:", stealth.stealthAddress);
  console.log(
    "   ephemeral pub:  ",
    stealth.ephemeralPubKey.slice(0, 20) + "...",
  );

  // 3. Send ETH to the stealth address + announce
  console.log("\n3. Announcing payment...");
  const announceTx = await senderClient.announcePayment(
    stealth.stealthAddress,
    stealth.ephemeralPubKey,
    stealth.viewTag,
  );
  console.log("   announce tx:", announceTx);

  // 4. Receiver scans announcements
  console.log("\n4. Scanning announcements as receiver...");
  const payments = await receiverClient.scanAnnouncements();
  console.log(`   Found ${payments.length} payment(s)`);
  for (const p of payments) {
    console.log(
      "   -",
      p.stealthAddress,
      "ephemeral:",
      p.ephemeralPubKey.slice(0, 20) + "...",
    );
  }

  console.log("\n✅ Full stealth address lifecycle complete.");
}

main().catch(console.error);
