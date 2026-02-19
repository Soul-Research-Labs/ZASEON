import { expect } from "chai";
import { type Address, type Hex, zeroAddress } from "viem";
import {
  PrivacyRouterClient,
  createPrivacyRouterClient,
  OperationType,
  type PrivacyRouterConfig,
} from "../src/client/PrivacyRouterClient";

// ============================================================
// Helpers
// ============================================================

const MOCK_ROUTER = ("0x" + "cc".repeat(20)) as Address;
const MOCK_TOKEN = ("0x" + "dd".repeat(20)) as Address;
const MOCK_TX_HASH = ("0x" + "ab".repeat(32)) as Hex;
const MOCK_OP_ID = ("0x" + "ff".repeat(32)) as Hex;
const MOCK_COMMITMENT = ("0x" + "11".repeat(32)) as Hex;
const MOCK_NULLIFIER = ("0x" + "22".repeat(32)) as Hex;
const MOCK_ROOT = ("0x" + "33".repeat(32)) as Hex;
const MOCK_PROOF = ("0x" + "44".repeat(64)) as Hex;

function makeReceipt(txHash: Hex = MOCK_TX_HASH): any {
  return {
    transactionHash: txHash,
    logs: [{ data: "0x" as Hex, topics: ["0xevent" as Hex, MOCK_OP_ID] }],
  };
}

function makeClient(opts?: {
  withWallet?: boolean;
  readStub?: (call: any) => Promise<any>;
  writeStub?: (...args: any[]) => Promise<Hex>;
  receiptStub?: (hash: Hex) => Promise<any>;
}): PrivacyRouterClient {
  const publicClient = {
    readContract: async (call: any) => {
      if (opts?.readStub) return opts.readStub(call);
      throw new Error(`No stub for readContract ${call.functionName}`);
    },
    waitForTransactionReceipt: async ({ hash }: { hash: Hex }) => {
      if (opts?.receiptStub) return opts.receiptStub(hash);
      return makeReceipt(hash);
    },
  } as any;

  const walletClient = opts?.withWallet
    ? {
        chain: null,
        account: { address: "0x" + "aa".repeat(20) },
        writeContract: opts?.writeStub ?? (async () => MOCK_TX_HASH),
      }
    : undefined;

  return new PrivacyRouterClient({
    publicClient,
    walletClient: walletClient as any,
    routerAddress: MOCK_ROUTER,
  });
}

// ============================================================
// Tests
// ============================================================

describe("PrivacyRouterClient", () => {
  describe("constructor & createPrivacyRouterClient", () => {
    it("should store routerAddress", () => {
      const client = makeClient();
      expect(client.routerAddress).to.equal(MOCK_ROUTER);
    });

    it("createPrivacyRouterClient factory should return a PrivacyRouterClient", () => {
      const client = createPrivacyRouterClient({
        publicClient: {} as any,
        routerAddress: MOCK_ROUTER,
      });
      expect(client).to.be.instanceOf(PrivacyRouterClient);
    });
  });

  // --------------------------------------------------------
  // Write operations — wallet required guard
  // --------------------------------------------------------
  describe("wallet-required guard", () => {
    const client = makeClient({ withWallet: false });

    it("depositETH should throw without wallet", async () => {
      try {
        await client.depositETH(MOCK_COMMITMENT, 1000n);
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });

    it("depositERC20 should throw without wallet", async () => {
      try {
        await client.depositERC20(MOCK_TOKEN, 500n, MOCK_COMMITMENT);
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });

    it("withdraw should throw without wallet", async () => {
      try {
        await client.withdraw({
          nullifierHash: MOCK_NULLIFIER,
          recipient: MOCK_TOKEN,
          root: MOCK_ROOT,
          proof: MOCK_PROOF,
        });
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });

    it("crossChainTransfer should throw without wallet", async () => {
      try {
        await client.crossChainTransfer({
          commitment: MOCK_COMMITMENT,
          nullifierHash: MOCK_NULLIFIER,
          destinationChainId: 42161,
          proof: MOCK_PROOF,
          amount: 1000n,
        });
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });
  });

  // --------------------------------------------------------
  // depositETH
  // --------------------------------------------------------
  describe("depositETH", () => {
    it("should send tx with commitment and value, return operationId", async () => {
      let capturedArgs: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (args: any) => {
          capturedArgs = args;
          return MOCK_TX_HASH;
        },
      });

      const result = await client.depositETH(MOCK_COMMITMENT, 5000n);
      expect(result.txHash).to.equal(MOCK_TX_HASH);
      expect(result.operationId).to.equal(MOCK_OP_ID);
      expect(capturedArgs.functionName).to.equal("depositETH");
      expect(capturedArgs.args).to.deep.equal([MOCK_COMMITMENT]);
      expect(capturedArgs.value).to.equal(5000n);
    });
  });

  // --------------------------------------------------------
  // depositERC20
  // --------------------------------------------------------
  describe("depositERC20", () => {
    it("should call with token, amount, commitment", async () => {
      let capturedArgs: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (args: any) => {
          capturedArgs = args;
          return MOCK_TX_HASH;
        },
      });

      const result = await client.depositERC20(
        MOCK_TOKEN,
        1000n,
        MOCK_COMMITMENT,
      );
      expect(result.txHash).to.equal(MOCK_TX_HASH);
      expect(capturedArgs.functionName).to.equal("depositERC20");
      expect(capturedArgs.args).to.deep.equal([
        MOCK_TOKEN,
        1000n,
        MOCK_COMMITMENT,
      ]);
    });
  });

  // --------------------------------------------------------
  // withdraw
  // --------------------------------------------------------
  describe("withdraw", () => {
    it("should call with all withdrawal params, default relayer to zeroAddress", async () => {
      let capturedArgs: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (args: any) => {
          capturedArgs = args;
          return MOCK_TX_HASH;
        },
      });

      const result = await client.withdraw({
        nullifierHash: MOCK_NULLIFIER,
        recipient: MOCK_TOKEN,
        root: MOCK_ROOT,
        proof: MOCK_PROOF,
      });

      expect(result.operationId).to.equal(MOCK_OP_ID);
      expect(capturedArgs.functionName).to.equal("withdraw");
      // relayer defaults to zeroAddress, fee defaults to 0n
      expect(capturedArgs.args[2]).to.equal(zeroAddress);
      expect(capturedArgs.args[3]).to.equal(0n);
    });

    it("should use provided relayer and fee", async () => {
      let capturedArgs: any;
      const relayer = ("0x" + "ee".repeat(20)) as Address;
      const client = makeClient({
        withWallet: true,
        writeStub: async (args: any) => {
          capturedArgs = args;
          return MOCK_TX_HASH;
        },
      });

      await client.withdraw({
        nullifierHash: MOCK_NULLIFIER,
        recipient: MOCK_TOKEN,
        root: MOCK_ROOT,
        proof: MOCK_PROOF,
        relayer,
        fee: 100n,
      });

      expect(capturedArgs.args[2]).to.equal(relayer);
      expect(capturedArgs.args[3]).to.equal(100n);
    });
  });

  // --------------------------------------------------------
  // crossChainTransfer
  // --------------------------------------------------------
  describe("crossChainTransfer", () => {
    it("should call with correct params and convert chainId to bigint", async () => {
      let capturedArgs: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (args: any) => {
          capturedArgs = args;
          return MOCK_TX_HASH;
        },
      });

      const result = await client.crossChainTransfer({
        commitment: MOCK_COMMITMENT,
        nullifierHash: MOCK_NULLIFIER,
        destinationChainId: 42161,
        proof: MOCK_PROOF,
        amount: 2000n,
      });

      expect(result.operationId).to.equal(MOCK_OP_ID);
      expect(capturedArgs.functionName).to.equal("crossChainTransfer");
      expect(capturedArgs.args[2]).to.equal(42161n);
    });
  });

  // --------------------------------------------------------
  // Read operations
  // --------------------------------------------------------
  describe("getOperationCount", () => {
    it("should return bigint count", async () => {
      const client = makeClient({
        readStub: async () => 42n,
      });

      const count = await client.getOperationCount();
      expect(count).to.equal(42n);
    });
  });

  describe("getOperationReceipt", () => {
    it("should parse tuple into OperationReceipt", async () => {
      const client = makeClient({
        readStub: async () => ({
          operationId: MOCK_OP_ID,
          operationType: 0, // DEPOSIT
          sender: MOCK_TOKEN,
          timestamp: 1000000n,
          chainId: 1n,
        }),
      });

      const receipt = await client.getOperationReceipt(MOCK_OP_ID);
      expect(receipt.operationId).to.equal(MOCK_OP_ID);
      expect(receipt.operationType).to.equal(OperationType.DEPOSIT);
      expect(receipt.sender).to.equal(MOCK_TOKEN);
      expect(receipt.chainId).to.equal(1);
    });
  });

  describe("isPaused", () => {
    it("should return boolean", async () => {
      const client = makeClient({ readStub: async () => false });
      expect(await client.isPaused()).to.be.false;
    });
  });

  describe("isComplianceEnabled", () => {
    it("should return boolean", async () => {
      const client = makeClient({ readStub: async () => true });
      expect(await client.isComplianceEnabled()).to.be.true;
    });
  });

  // --------------------------------------------------------
  // Edge: parseOperationId with no matching log
  // --------------------------------------------------------
  describe("parseOperationId fallback", () => {
    it("should return 0x when no logs have topics", async () => {
      const client = makeClient({
        withWallet: true,
        receiptStub: async () => ({
          transactionHash: MOCK_TX_HASH,
          logs: [{ data: "0x" as Hex, topics: [] }],
        }),
      });

      const result = await client.depositETH(MOCK_COMMITMENT, 100n);
      expect(result.operationId).to.equal("0x");
    });
  });
});
