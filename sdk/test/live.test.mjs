/**
 * Soul SDK Live Integration Tests
 * 
 * Tests the SDK against deployed Sepolia contracts with real RPC calls.
 * Run with: SEPOLIA_RPC=<your-rpc> npm run test:live
 * 
 * Note: Public RPCs may be slow or rate-limited. Use a private RPC for reliable tests.
 */

const SEPOLIA_RPC = process.env.SEPOLIA_RPC || "https://rpc.sepolia.org";
const TIMEOUT = 15000; // 15 seconds for RPC calls
const RPC_AVAILABLE = process.env.SEPOLIA_RPC ? true : false;

// Simple test runner
function assert(condition, message) {
  if (!condition) {
    throw new Error(`FAIL: ${message}`);
  }
}

async function describe(name, fn) {
  console.log(`\n  ${name}`);
  return fn();
}

async function it(name, fn, timeout = TIMEOUT) {
  const start = Date.now();
  try {
    await Promise.race([
      fn(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error(`Timeout after ${timeout}ms`)), timeout)
      )
    ]);
    const duration = Date.now() - start;
    console.log(`    ✓ ${name} (${duration}ms)`);
    return { passed: true };
  } catch (e) {
    const duration = Date.now() - start;
    // Check if it's a network/timeout error
    if (e.message?.includes("Timeout") || e.message?.includes("fetch") || 
        e.message?.includes("network") || e.message?.includes("ECONNREFUSED")) {
      console.log(`    ⊘ ${name} (skipped - RPC unavailable)`);
      return { skipped: true };
    }
    console.log(`    ✗ ${name} (${duration}ms)`);
    console.log(`      Error: ${e.message}`);
    return { failed: true };
  }
}

// Dynamic imports
async function runLiveTests() {
  console.log("\n  Soul SDK Live Integration Tests");
  console.log("  " + "=".repeat(48));
  console.log(`  RPC: ${SEPOLIA_RPC.substring(0, 30)}...`);
  if (!RPC_AVAILABLE) {
    console.log("  ⚠️  Using public RPC - tests may be slow or skipped");
    console.log("  💡 Set SEPOLIA_RPC env var for reliable testing");
  }

  let passed = 0;
  let failed = 0;
  let skipped = 0;

  function count(result) {
    if (result.passed) passed++;
    else if (result.failed) failed++;
    else if (result.skipped) skipped++;
  }

  try {
    // Import modules
    const { createReadOnlySoulClient } = await import("../dist/client/SoulProtocolClient.js");
    const { SEPOLIA_ADDRESSES } = await import("../dist/config/addresses.js");

    // Create client
    const client = createReadOnlySoulClient(SEPOLIA_RPC);

    // Test Suite: ZK-Bound State Locks Contract
    await describe("ZKBoundStateLocks Contract", async () => {
      count(await it("should read totalLocksCreated", async () => {
        const total = await client.getTotalLocksCreated();
        assert(typeof total === "bigint", "Should return bigint");
        assert(total >= 0n, "Should be non-negative");
        console.log(`      → Total locks created: ${total}`);
      }));

      count(await it("should read totalLocksUnlocked", async () => {
        const total = await client.getTotalLocksUnlocked();
        assert(typeof total === "bigint", "Should return bigint");
        assert(total >= 0n, "Should be non-negative");
        console.log(`      → Total locks unlocked: ${total}`);
      }));

      count(await it("should read activeLockCount", async () => {
        const active = await client.getActiveLockCount();
        assert(typeof active === "bigint", "Should return bigint");
        assert(active >= 0n, "Should be non-negative");
        console.log(`      → Active locks: ${active}`);
      }));

      count(await it("should check nullifier usage", async () => {
        // Check a random nullifier (should be false)
        const nullifier = "0x0000000000000000000000000000000000000000000000000000000000000001";
        const isUsed = await client.isNullifierUsed(nullifier);
        assert(typeof isUsed === "boolean", "Should return boolean");
        console.log(`      → Nullifier used: ${isUsed}`);
      }));

      count(await it("should check paused status", async () => {
        const isPaused = await client.isPaused();
        assert(typeof isPaused === "boolean", "Should return boolean");
        console.log(`      → Contract paused: ${isPaused}`);
      }));
    });

    // Test Suite: Nullifier Registry Contract
    await describe("NullifierRegistry Contract", async () => {
      count(await it("should read totalNullifiers", async () => {
        const total = await client.getTotalNullifiers();
        assert(typeof total === "bigint", "Should return bigint");
        assert(total >= 0n, "Should be non-negative");
        console.log(`      → Total nullifiers: ${total}`);
      }));

      count(await it("should read merkleRoot", async () => {
        const root = await client.getMerkleRoot();
        assert(typeof root === "string", "Should return string");
        assert(root.startsWith("0x"), "Should be hex");
        console.log(`      → Merkle root: ${root.substring(0, 18)}...`);
      }));

      count(await it("should check nullifier existence", async () => {
        const nullifier = "0x0000000000000000000000000000000000000000000000000000000000000002";
        const exists = await client.nullifierExists(nullifier);
        assert(typeof exists === "boolean", "Should return boolean");
        console.log(`      → Nullifier exists: ${exists}`);
      }));
    });

    // Test Suite: CrossChainProofHub Contract
    await describe("CrossChainProofHub Contract", async () => {
      count(await it("should read totalProofs", async () => {
        const total = await client.getTotalProofs();
        assert(typeof total === "bigint", "Should return bigint");
        assert(total >= 0n, "Should be non-negative");
        console.log(`      → Total proofs: ${total}`);
      }));

      count(await it("should check chain support for Sepolia", async () => {
        const isSupported = await client.isChainSupported(11155111);
        assert(typeof isSupported === "boolean", "Should return boolean");
        console.log(`      → Sepolia supported: ${isSupported}`);
      }));

      count(await it("should check chain support for Arbitrum Sepolia", async () => {
        const isSupported = await client.isChainSupported(421614);
        assert(typeof isSupported === "boolean", "Should return boolean");
        console.log(`      → Arbitrum Sepolia supported: ${isSupported}`);
      }));

      count(await it("should read relayer stake for zero address", async () => {
        const stake = await client.getRelayerStake("0x0000000000000000000000000000000000000000");
        assert(typeof stake === "bigint", "Should return bigint");
        assert(stake === 0n, "Zero address should have no stake");
        console.log(`      → Zero address stake: ${stake}`);
      }));
    });

    // Test Suite: Protocol Stats
    await describe("Protocol Stats", async () => {
      count(await it("should get aggregated protocol stats", async () => {
        const stats = await client.getStats();
        
        assert(typeof stats.totalLocks === "bigint", "totalLocks should be bigint");
        assert(typeof stats.totalUnlocks === "bigint", "totalUnlocks should be bigint");
        assert(typeof stats.activeLocks === "bigint", "activeLocks should be bigint");
        assert(typeof stats.totalNullifiers === "bigint", "totalNullifiers should be bigint");
        assert(typeof stats.totalProofs === "bigint", "totalProofs should be bigint");
        
        console.log(`      → Protocol Stats:`);
        console.log(`        - Total Locks: ${stats.totalLocks}`);
        console.log(`        - Total Unlocks: ${stats.totalUnlocks}`);
        console.log(`        - Active Locks: ${stats.activeLocks}`);
        console.log(`        - Total Nullifiers: ${stats.totalNullifiers}`);
        console.log(`        - Total Proofs: ${stats.totalProofs}`);
      }));
    });

    // Test Suite: Contract Address Verification
    await describe("Contract Addresses", async () => {
      count(await it("should have correct deployed addresses", async () => {
        // Verify addresses match what's on chain by checking they have code
        const { createPublicClient, http } = await import("viem");
        const { sepolia } = await import("viem/chains");
        
        const publicClient = createPublicClient({
          chain: sepolia,
          transport: http(SEPOLIA_RPC),
        });

        const contracts = [
          { name: "zkBoundStateLocks", address: SEPOLIA_ADDRESSES.zkBoundStateLocks },
          { name: "nullifierRegistry", address: SEPOLIA_ADDRESSES.nullifierRegistry },
          { name: "proofHub", address: SEPOLIA_ADDRESSES.proofHub },
          { name: "atomicSwap", address: SEPOLIA_ADDRESSES.atomicSwap },
        ];

        for (const contract of contracts) {
          const code = await publicClient.getBytecode({ address: contract.address });
          assert(code && code.length > 2, `${contract.name} should have bytecode`);
          console.log(`      → ${contract.name}: ✓ deployed`);
        }
      }));
    });

    // Test Suite: Commitment Generation (offline - always works)
    await describe("Commitment Generation", async () => {
      count(await it("should generate valid secrets and commitments", async () => {
        const { secret, nullifier } = client.generateSecrets();
        const { commitment, nullifierHash } = client.generateCommitment(secret, nullifier);
        
        assert(secret.length === 66, "Secret should be 32 bytes");
        assert(nullifier.length === 66, "Nullifier should be 32 bytes");
        assert(commitment.length === 66, "Commitment should be 32 bytes");
        assert(nullifierHash.length === 66, "NullifierHash should be 32 bytes");
        
        // Verify determinism
        const { commitment: c2, nullifierHash: n2 } = client.generateCommitment(secret, nullifier);
        assert(commitment === c2, "Commitment should be deterministic");
        assert(nullifierHash === n2, "NullifierHash should be deterministic");
        
        console.log(`      → Secret: ${secret.substring(0, 18)}...`);
        console.log(`      → Commitment: ${commitment.substring(0, 18)}...`);
      }));
    });

  } catch (error) {
    console.error("\n  ✗ Test setup failed:", error.message);
    failed++;
  }

  console.log("\n  " + "=".repeat(48));
  console.log(`\n  Results: ${passed} passed, ${failed} failed, ${skipped} skipped`);
  
  return failed === 0;
}

// Run tests
console.log("\n  Starting live tests against Sepolia...\n");

runLiveTests()
  .then((success) => {
    if (success) {
      console.log("\n  ✓ All live tests passed!\n");
      process.exit(0);
    } else {
      console.log("\n  ✗ Some live tests failed!\n");
      process.exit(1);
    }
  })
  .catch((error) => {
    console.error("\n  ✗ Test runner error:", error.message);
    process.exit(1);
  });
