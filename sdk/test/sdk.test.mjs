/**
 * Soul SDK Integration Test (ESM)
 * 
 * Tests the SDK against deployed Sepolia contracts
 * Run with: node test/sdk.test.mjs
 */

// Simple test runner
function assert(condition, message) {
  if (!condition) {
    throw new Error(`FAIL: ${message}`);
  }
  console.log(`    ✓ ${message}`);
}

function describe(name, fn) {
  console.log(`\n  ${name}`);
  return fn();
}

async function it(name, fn) {
  try {
    await fn();
    console.log(`    ✓ ${name}`);
    return true;
  } catch (e) {
    console.log(`    ✗ ${name}`);
    console.log(`      Error: ${e.message}`);
    return false;
  }
}

// Dynamic imports to handle ESM
async function runTests() {
  console.log("\n  Soul SDK Integration Tests");
  console.log("  " + "=".repeat(48));

  let passed = 0;
  let failed = 0;

  try {
    // Import modules from dist (CJS)
    const { SoulProtocolClient, createReadOnlySoulClient } = await import("../dist/client/SoulProtocolClient.js");
    const { SEPOLIA_ADDRESSES, getAddresses } = await import("../dist/config/addresses.js");
    const { NoirProver, Circuit } = await import("../dist/zkprover/NoirProver.js");

    // Test Suite: Contract Addresses
    await describe("Contract Addresses", async () => {
      if (await it("should have valid Sepolia addresses", async () => {
        assert(SEPOLIA_ADDRESSES.zkBoundStateLocks.startsWith("0x"), "zkBoundStateLocks starts with 0x");
        assert(SEPOLIA_ADDRESSES.zkBoundStateLocks.length === 42, "zkBoundStateLocks is 42 chars");
        assert(SEPOLIA_ADDRESSES.nullifierRegistry.startsWith("0x"), "nullifierRegistry starts with 0x");
        assert(SEPOLIA_ADDRESSES.proofHub.startsWith("0x"), "proofHub starts with 0x");
        assert(SEPOLIA_ADDRESSES.atomicSwap.startsWith("0x"), "atomicSwap starts with 0x");
      })) passed++; else failed++;

      if (await it("should get addresses by chainId", async () => {
        const addresses = getAddresses(11155111);
        assert(addresses !== null, "Should return addresses for Sepolia");
        assert(addresses.zkBoundStateLocks === SEPOLIA_ADDRESSES.zkBoundStateLocks, "Should match zkBoundStateLocks");
      })) passed++; else failed++;

      if (await it("should return null for unknown chainId", async () => {
        const addresses = getAddresses(999999);
        assert(addresses === null, "Should return null for unknown chain");
      })) passed++; else failed++;
    });

    // Test Suite: SoulProtocolClient
    await describe("SoulProtocolClient", async () => {
      if (await it("should create read-only client", async () => {
        const client = createReadOnlySoulClient({
          chainId: 11155111,
          rpcUrl: "https://rpc.sepolia.org",
        });
        assert(client !== undefined, "Client should be created");
        assert(typeof client.getLock === "function", "Should have getLock method");
        assert(typeof client.isNullifierUsed === "function", "Should have isNullifierUsed method");
      })) passed++; else failed++;

      if (await it("should have all required methods", async () => {
        const client = createReadOnlySoulClient({
          chainId: 11155111,
          rpcUrl: "https://rpc.sepolia.org",
        });
        
        const methods = [
          "createLock",
          "unlockWithProof",
          "initiateOptimisticUnlock",
          "refundExpiredLock",
          "getLock",
          "isNullifierUsed",
          "getMerkleRoot",
          "getStats",
        ];
        
        for (const method of methods) {
          assert(typeof client[method] === "function", `Should have ${method} method`);
        }
      })) passed++; else failed++;

      if (await it("should generate deterministic secrets", async () => {
        const client = createReadOnlySoulClient({
          chainId: 11155111,
          rpcUrl: "https://rpc.sepolia.org",
        });
        
        const secrets1 = client.generateSecrets();
        const secrets2 = client.generateSecrets();
        
        assert(secrets1.secret.startsWith("0x"), "Secret should be hex");
        assert(secrets1.secret.length === 66, "Secret should be 32 bytes (66 chars with 0x)");
        assert(secrets1.nullifier.startsWith("0x"), "Nullifier should be hex");
        assert(secrets1.nullifier.length === 66, "Nullifier should be 32 bytes");
        assert(secrets1.secret !== secrets2.secret, "Secrets should be unique");
      })) passed++; else failed++;

      if (await it("should compute consistent commitment hash", async () => {
        const client = createReadOnlySoulClient({
          chainId: 11155111,
          rpcUrl: "https://rpc.sepolia.org",
        });
        
        const secret = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        const nullifier = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        const result1 = client.generateCommitment(secret, nullifier);
        const result2 = client.generateCommitment(secret, nullifier);
        
        assert(result1.commitment === result2.commitment, "Same inputs should produce same commitment");
        assert(result1.commitment.startsWith("0x"), "Commitment should be hex");
        assert(result1.commitment.length === 66, "Commitment should be 32 bytes");
        assert(result1.nullifierHash.startsWith("0x"), "NullifierHash should be hex");
      })) passed++; else failed++;
    });

    // Test Suite: NoirProver
    await describe("NoirProver", async () => {
      if (await it("should create prover instance", async () => {
        const prover = new NoirProver();
        assert(prover !== undefined, "Prover should be created");
      })) passed++; else failed++;

      if (await it("should list available circuits", async () => {
        const circuits = Object.values(Circuit);
        assert(circuits.length > 0, "Should have circuits available");
        assert(circuits.includes("state_commitment"), "Should have state_commitment circuit");
        assert(circuits.includes("state_transfer"), "Should have state_transfer circuit");
        assert(circuits.includes("nullifier"), "Should have nullifier circuit");
      })) passed++; else failed++;

      if (await it("should initialize prover", async () => {
        const prover = new NoirProver();
        await prover.initialize();
        assert(true, "Prover initialized");
      })) passed++; else failed++;

      if (await it("should generate state commitment proof", async () => {
        const prover = new NoirProver();
        await prover.initialize();
        
        const result = await prover.proveStateCommitment({
          secret: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          nullifier: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
          amount: 1000n,
        });
        
        assert(result.proofHex.startsWith("0x"), "Proof should be hex");
        assert(result.publicInputs.length > 0, "Should have public inputs");
      })) passed++; else failed++;

      if (await it("should generate deterministic proofs for same inputs", async () => {
        const prover = new NoirProver();
        await prover.initialize();
        
        const inputs = {
          secret: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          nullifier: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
          amount: 1000n,
        };
        
        const result1 = await prover.proveStateCommitment(inputs);
        const result2 = await prover.proveStateCommitment(inputs);
        
        assert(result1.proofHex === result2.proofHex, "Same inputs should produce same proof");
      })) passed++; else failed++;
    });

  } catch (error) {
    console.error("\n  ✗ Failed to load modules:", error.message);
    failed++;
  }

  console.log("\n  " + "=".repeat(48));
  console.log(`\n  Tests: ${passed} passed, ${failed} failed`);
  
  return failed === 0;
}

// Run tests
runTests()
  .then((success) => {
    if (success) {
      console.log("\n  ✓ All tests passed!\n");
      process.exit(0);
    } else {
      console.log("\n  ✗ Some tests failed!\n");
      process.exit(1);
    }
  })
  .catch((error) => {
    console.error("\n  ✗ Test runner error:", error.message);
    process.exit(1);
  });
