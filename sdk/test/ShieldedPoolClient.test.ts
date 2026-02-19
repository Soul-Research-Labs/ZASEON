import { expect } from "chai";
import {
  keccak256,
  encodePacked,
  zeroAddress,
  type Hex,
  type Address,
} from "viem";
import {
  ShieldedPoolClient,
  createShieldedPoolClient,
  type ShieldedPoolConfig,
  type PoolStats,
} from "../src/client/ShieldedPoolClient";

// ============================================================
// Helpers
// ============================================================

const MOCK_POOL = ("0x" + "cc".repeat(20)) as Address;

/**
 * Create a ShieldedPoolClient with configurable stubs.
 */
function makeClient(opts?: {
  withWallet?: boolean;
  readStubs?: Record<string, (...args: any[]) => any>;
  writeStub?: (...args: any[]) => Promise<Hex>;
  receiptStub?: (hash: Hex) => Promise<any>;
}) {
  const readStubs = opts?.readStubs ?? {};
  const publicClient = {
    readContract: async (call: any) => {
      const fn = call.functionName;
      if (readStubs[fn]) return readStubs[fn](call);
      throw new Error(`No stub for readContract ${fn}`);
    },
    waitForTransactionReceipt: async ({ hash }: { hash: Hex }) => {
      if (opts?.receiptStub) return opts.receiptStub(hash);
      return {
        transactionHash: hash,
        logs: [
          {
            // Minimal Deposit event log
            data: "0x0000000000000000000000000000000000000000000000000000000000000005" as Hex,
            topics: ["0x1234" as Hex, "0xcommitment" as Hex],
          },
        ],
      };
    },
  } as any;

  const walletClient = opts?.withWallet
    ? {
        chain: null,
        account: { address: "0x" + "aa".repeat(20) },
        writeContract: opts.writeStub ?? (async () => "0xdeadbeef" as Hex),
      }
    : undefined;

  const config: ShieldedPoolConfig = {
    publicClient,
    walletClient: walletClient as any,
    poolAddress: MOCK_POOL,
  };

  return new ShieldedPoolClient(config);
}

// ============================================================
// Tests
// ============================================================

describe("ShieldedPoolClient", () => {
  // ================================================================
  // Constructor & Factory
  // ================================================================

  describe("constructor", () => {
    it("should store publicClient and poolAddress", () => {
      const client = makeClient();
      expect(client.poolAddress).to.equal(MOCK_POOL);
      expect(client.publicClient).to.not.be.undefined;
    });

    it("should set walletClient to undefined when not provided", () => {
      const client = makeClient();
      expect(client.walletClient).to.be.undefined;
    });

    it("should accept walletClient when provided", () => {
      const client = makeClient({ withWallet: true });
      expect(client.walletClient).to.not.be.undefined;
    });
  });

  describe("createShieldedPoolClient()", () => {
    it("should return a ShieldedPoolClient instance", () => {
      const client = createShieldedPoolClient({
        publicClient: {} as any,
        poolAddress: MOCK_POOL,
      });
      expect(client).to.be.instanceOf(ShieldedPoolClient);
    });
  });

  // ================================================================
  // Commitment Generation
  // ================================================================

  describe("generateDepositNote()", () => {
    it("should produce a commitment from secret and nullifier", () => {
      const client = makeClient();
      const note = client.generateDepositNote(1000000n);

      expect(note.commitment).to.match(/^0x[0-9a-f]{64}$/i);
      expect(note.secret).to.match(/^0x[0-9a-f]{64}$/i);
      expect(note.nullifier).to.match(/^0x[0-9a-f]{64}$/i);
      expect(note.amount).to.equal(1000000n);
    });

    it("should default asset to zeroAddress (ETH)", () => {
      const client = makeClient();
      const note = client.generateDepositNote(1n);
      expect(note.asset).to.equal(zeroAddress);
    });

    it("should accept a custom asset address", () => {
      const client = makeClient();
      const token = ("0x" + "dd".repeat(20)) as Address;
      const note = client.generateDepositNote(1n, token);
      expect(note.asset).to.equal(token);
    });

    it("should produce different notes each call", () => {
      const client = makeClient();
      const a = client.generateDepositNote(1n);
      const b = client.generateDepositNote(1n);
      expect(a.secret).to.not.equal(b.secret);
      expect(a.nullifier).to.not.equal(b.nullifier);
      expect(a.commitment).to.not.equal(b.commitment);
    });

    it("should compute commitment = keccak256(secret || nullifier)", () => {
      const client = makeClient();
      const note = client.generateDepositNote(1000n);
      const expected = keccak256(
        encodePacked(["bytes32", "bytes32"], [note.secret, note.nullifier]),
      );
      expect(note.commitment).to.equal(expected);
    });
  });

  describe("computeNullifierHash()", () => {
    it("should return keccak256 of nullifier", () => {
      const client = makeClient();
      const nullifier = ("0x" + "ab".repeat(32)) as Hex;
      const expected = keccak256(nullifier);
      expect(client.computeNullifierHash(nullifier)).to.equal(expected);
    });

    it("should be deterministic", () => {
      const client = makeClient();
      const nullifier = ("0x" + "12".repeat(32)) as Hex;
      const a = client.computeNullifierHash(nullifier);
      const b = client.computeNullifierHash(nullifier);
      expect(a).to.equal(b);
    });

    it("should differ for different nullifiers", () => {
      const client = makeClient();
      const a = client.computeNullifierHash(("0x" + "11".repeat(32)) as Hex);
      const b = client.computeNullifierHash(("0x" + "22".repeat(32)) as Hex);
      expect(a).to.not.equal(b);
    });
  });

  // ================================================================
  // Write Operations
  // ================================================================

  describe("depositETH()", () => {
    it("should call writeContract with deposit and msg.value", async () => {
      let capturedCall: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (call) => {
          capturedCall = call;
          return "0xdeadbeef" as Hex;
        },
      });

      const commitment = ("0x" + "aa".repeat(32)) as Hex;
      const result = await client.depositETH(commitment, 1000000n);

      expect(result.txHash).to.equal("0xdeadbeef");
      expect(result.leafIndex).to.be.a("number");
      expect(capturedCall.functionName).to.equal("deposit");
      expect(capturedCall.address).to.equal(MOCK_POOL);
      expect(capturedCall.value).to.equal(1000000n);
    });

    it("should throw if walletClient is not set", async () => {
      const client = makeClient({ withWallet: false });
      try {
        await client.depositETH(("0x" + "aa".repeat(32)) as Hex, 1n);
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });
  });

  describe("depositERC20()", () => {
    it("should call deposit with token address and no msg.value", async () => {
      let capturedCall: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (call) => {
          capturedCall = call;
          return "0x1234" as Hex;
        },
      });

      const token = ("0x" + "ee".repeat(20)) as Address;
      const commitment = ("0x" + "bb".repeat(32)) as Hex;
      const result = await client.depositERC20(token, 500n, commitment);

      expect(result.txHash).to.equal("0x1234");
      expect(capturedCall.functionName).to.equal("deposit");
      expect(capturedCall.args[1]).to.equal(token);
      expect(capturedCall.args[2]).to.equal(500n);
    });

    it("should throw if walletClient is not set", async () => {
      const client = makeClient({ withWallet: false });
      const token = ("0x" + "ee".repeat(20)) as Address;
      try {
        await client.depositERC20(token, 1n, ("0x" + "aa".repeat(32)) as Hex);
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });
  });

  describe("withdraw()", () => {
    it("should call withdraw with correct args", async () => {
      let capturedCall: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (call) => {
          capturedCall = call;
          return "0xwithdraw" as Hex;
        },
      });

      const nullifierHash = ("0x" + "11".repeat(32)) as Hex;
      const recipient = ("0x" + "22".repeat(20)) as Address;
      const root = ("0x" + "33".repeat(32)) as Hex;
      const proof = ("0x" + "44".repeat(128)) as Hex;

      const txHash = await client.withdraw(
        nullifierHash,
        recipient,
        root,
        proof,
      );

      expect(txHash).to.equal("0xwithdraw");
      expect(capturedCall.functionName).to.equal("withdraw");
      expect(capturedCall.args[0]).to.equal(nullifierHash);
      expect(capturedCall.args[1]).to.equal(recipient);
    });

    it("should accept optional relayer and fee", async () => {
      let capturedCall: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (call) => {
          capturedCall = call;
          return "0xwithdraw" as Hex;
        },
      });

      const relayer = ("0x" + "55".repeat(20)) as Address;
      await client.withdraw(
        ("0x" + "11".repeat(32)) as Hex,
        ("0x" + "22".repeat(20)) as Address,
        ("0x" + "33".repeat(32)) as Hex,
        ("0x" + "44".repeat(128)) as Hex,
        relayer,
        100n,
      );

      expect(capturedCall.args[2]).to.equal(relayer);
      expect(capturedCall.args[3]).to.equal(100n);
    });

    it("should throw if walletClient is not set", async () => {
      const client = makeClient({ withWallet: false });
      try {
        await client.withdraw(
          ("0x" + "11".repeat(32)) as Hex,
          ("0x" + "22".repeat(20)) as Address,
          ("0x" + "33".repeat(32)) as Hex,
          ("0x" + "44".repeat(128)) as Hex,
        );
        expect.fail("Should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });
  });

  // ================================================================
  // Read Operations
  // ================================================================

  describe("getCurrentRoot()", () => {
    it("should call readContract getCurrentRoot", async () => {
      const root = ("0x" + "ab".repeat(32)) as Hex;
      const client = makeClient({
        readStubs: { getCurrentRoot: () => root },
      });
      const result = await client.getCurrentRoot();
      expect(result).to.equal(root);
    });
  });

  describe("isKnownRoot()", () => {
    it("should return true for known root", async () => {
      const client = makeClient({
        readStubs: { isKnownRoot: () => true },
      });
      const result = await client.isKnownRoot(("0x" + "ab".repeat(32)) as Hex);
      expect(result).to.be.true;
    });

    it("should return false for unknown root", async () => {
      const client = makeClient({
        readStubs: { isKnownRoot: () => false },
      });
      const result = await client.isKnownRoot(("0x" + "00".repeat(32)) as Hex);
      expect(result).to.be.false;
    });
  });

  describe("isSpent()", () => {
    it("should return true for spent nullifier", async () => {
      const client = makeClient({
        readStubs: { isSpent: () => true },
      });
      const result = await client.isSpent(("0x" + "bb".repeat(32)) as Hex);
      expect(result).to.be.true;
    });

    it("should return false for unspent nullifier", async () => {
      const client = makeClient({
        readStubs: { isSpent: () => false },
      });
      const result = await client.isSpent(("0x" + "cc".repeat(32)) as Hex);
      expect(result).to.be.false;
    });
  });

  describe("getNextLeafIndex()", () => {
    it("should return the next available leaf index", async () => {
      const client = makeClient({
        readStubs: { nextLeafIndex: () => BigInt(42) },
      });
      const result = await client.getNextLeafIndex();
      expect(result).to.equal(42);
    });
  });

  describe("getPoolStats()", () => {
    it("should aggregate multiple reads into PoolStats", async () => {
      const root = ("0x" + "ff".repeat(32)) as Hex;
      const client = makeClient({
        readStubs: {
          totalDeposited: () => BigInt(1000),
          totalWithdrawn: () => BigInt(200),
          getCurrentRoot: () => root,
          nextLeafIndex: () => BigInt(10),
        },
      });

      const stats: PoolStats = await client.getPoolStats();
      expect(stats.totalDeposits).to.equal(1000n);
      expect(stats.totalWithdrawals).to.equal(200n);
      expect(stats.currentRoot).to.equal(root);
      expect(stats.nextLeafIndex).to.equal(10);
    });
  });

  describe("getRegisteredAssets()", () => {
    it("should return array of asset addresses", async () => {
      const assets = [
        ("0x" + "11".repeat(20)) as Address,
        ("0x" + "22".repeat(20)) as Address,
      ];
      const client = makeClient({
        readStubs: { getRegisteredAssets: () => assets },
      });
      const result = await client.getRegisteredAssets();
      expect(result).to.deep.equal(assets);
    });
  });

  describe("isTestMode()", () => {
    it("should return true when test mode is active", async () => {
      const client = makeClient({
        readStubs: { testMode: () => true },
      });
      const result = await client.isTestMode();
      expect(result).to.be.true;
    });

    it("should return false when test mode is inactive", async () => {
      const client = makeClient({
        readStubs: { testMode: () => false },
      });
      const result = await client.isTestMode();
      expect(result).to.be.false;
    });
  });
});
