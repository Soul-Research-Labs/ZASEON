import { expect } from "chai";
import { type Address, type Hex } from "viem";
import {
  RelayerFeeMarketClient,
  createRelayerFeeMarketClient,
  RequestStatus,
  type RelayerFeeMarketConfig,
} from "../src/client/RelayerFeeMarketClient";

// ============================================================
// Helpers
// ============================================================

const MOCK_FEE_MARKET = ("0x" + "cc".repeat(20)) as Address;
const MOCK_TX_HASH = ("0x" + "ab".repeat(32)) as Hex;
const MOCK_REQ_ID = ("0x" + "ff".repeat(32)) as Hex;
const MOCK_PROOF_DATA = ("0x" + "dd".repeat(64)) as Hex;

function makeReceipt(txHash: Hex = MOCK_TX_HASH): any {
  return {
    transactionHash: txHash,
    logs: [{ data: "0x" as Hex, topics: ["0xevent" as Hex, MOCK_REQ_ID] }],
  };
}

function makeClient(opts?: {
  withWallet?: boolean;
  readStub?: (call: any) => Promise<any>;
  writeStub?: (...args: any[]) => Promise<Hex>;
  receiptStub?: (hash: Hex) => Promise<any>;
}): RelayerFeeMarketClient {
  const publicClient = {
    readContract: async (call: any) => {
      if (opts?.readStub) return opts.readStub(call);
      throw new Error(`No stub for ${call.functionName}`);
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

  return new RelayerFeeMarketClient({
    publicClient,
    walletClient: walletClient as any,
    feeMarketAddress: MOCK_FEE_MARKET,
  });
}

// ============================================================
// Tests
// ============================================================

describe("RelayerFeeMarketClient", () => {
  describe("constructor", () => {
    it("should store feeMarketAddress", () => {
      const client = makeClient();
      expect(client.feeMarketAddress).to.equal(MOCK_FEE_MARKET);
    });

    it("createRelayerFeeMarketClient factory returns instance", () => {
      const client = createRelayerFeeMarketClient({
        publicClient: {} as any,
        feeMarketAddress: MOCK_FEE_MARKET,
      });
      expect(client).to.be.instanceOf(RelayerFeeMarketClient);
    });
  });

  // --------------------------------------------------------
  // Wallet-required guard
  // --------------------------------------------------------
  describe("wallet-required guard", () => {
    const client = makeClient({ withWallet: false });

    for (const method of [
      "submitRelayRequest",
      "cancelRelayRequest",
      "claimRelayRequest",
      "completeRelay",
      "expireRelayRequest",
    ]) {
      it(`${method} should throw without wallet`, async () => {
        try {
          if (method === "submitRelayRequest") {
            await (client as any)[method](
              1,
              42161,
              MOCK_PROOF_DATA,
              1000000n,
              1000n,
            );
          } else if (method === "completeRelay") {
            await (client as any)[method](MOCK_REQ_ID, MOCK_PROOF_DATA);
          } else {
            await (client as any)[method](MOCK_REQ_ID);
          }
          expect.fail("should have thrown");
        } catch (e: any) {
          expect(e.message).to.include("Wallet client required");
        }
      });
    }
  });

  // --------------------------------------------------------
  // User operations
  // --------------------------------------------------------
  describe("submitRelayRequest", () => {
    it("should send tx with fee as value", async () => {
      let capturedArgs: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (args: any) => {
          capturedArgs = args;
          return MOCK_TX_HASH;
        },
      });

      const result = await client.submitRelayRequest(
        1,
        42161,
        MOCK_PROOF_DATA,
        1700000000n,
        5000n,
      );

      expect(result.txHash).to.equal(MOCK_TX_HASH);
      expect(result.requestId).to.equal(MOCK_REQ_ID);
      expect(capturedArgs.functionName).to.equal("submitRelayRequest");
      expect(capturedArgs.value).to.equal(5000n);
      expect(capturedArgs.args[0]).to.equal(1n); // sourceChain
      expect(capturedArgs.args[1]).to.equal(42161n); // destChain
    });
  });

  describe("cancelRelayRequest", () => {
    it("should return txHash", async () => {
      const client = makeClient({ withWallet: true });
      const txHash = await client.cancelRelayRequest(MOCK_REQ_ID);
      expect(txHash).to.equal(MOCK_TX_HASH);
    });
  });

  // --------------------------------------------------------
  // Relayer operations
  // --------------------------------------------------------
  describe("claimRelayRequest", () => {
    it("should call with requestId", async () => {
      let capturedArgs: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (args: any) => {
          capturedArgs = args;
          return MOCK_TX_HASH;
        },
      });

      await client.claimRelayRequest(MOCK_REQ_ID);
      expect(capturedArgs.functionName).to.equal("claimRelayRequest");
      expect(capturedArgs.args[0]).to.equal(MOCK_REQ_ID);
    });
  });

  describe("completeRelay", () => {
    it("should call with requestId and proof", async () => {
      let capturedArgs: any;
      const client = makeClient({
        withWallet: true,
        writeStub: async (args: any) => {
          capturedArgs = args;
          return MOCK_TX_HASH;
        },
      });

      await client.completeRelay(MOCK_REQ_ID, MOCK_PROOF_DATA);
      expect(capturedArgs.functionName).to.equal("completeRelay");
      expect(capturedArgs.args).to.deep.equal([MOCK_REQ_ID, MOCK_PROOF_DATA]);
    });
  });

  describe("expireRelayRequest", () => {
    it("should call with requestId", async () => {
      const client = makeClient({ withWallet: true });
      const txHash = await client.expireRelayRequest(MOCK_REQ_ID);
      expect(txHash).to.equal(MOCK_TX_HASH);
    });
  });

  // --------------------------------------------------------
  // Read operations
  // --------------------------------------------------------
  describe("estimateFee", () => {
    it("should return bigint fee", async () => {
      const client = makeClient({
        readStub: async (call: any) => {
          if (call.functionName === "estimateFee") return 1000000n;
          throw new Error(`unexpected ${call.functionName}`);
        },
      });

      const fee = await client.estimateFee(1, 42161);
      expect(fee).to.equal(1000000n);
    });
  });

  describe("estimateFeeWithBreakdown", () => {
    it("should compute protocolFee = baseFee * bps / 10000", async () => {
      const client = makeClient({
        readStub: async (call: any) => {
          if (call.functionName === "estimateFee") return 1000000n;
          if (call.functionName === "protocolFeeBps") return 250n; // 2.5%
          throw new Error(`unexpected ${call.functionName}`);
        },
      });

      const estimate = await client.estimateFeeWithBreakdown(1, 42161);
      expect(estimate.baseFee).to.equal(1000000n);
      expect(estimate.protocolFee).to.equal(25000n); // 1000000 * 250 / 10000
      expect(estimate.totalFee).to.equal(1025000n);
    });

    it("should handle zero protocol fee", async () => {
      const client = makeClient({
        readStub: async (call: any) => {
          if (call.functionName === "estimateFee") return 500000n;
          if (call.functionName === "protocolFeeBps") return 0n;
          throw new Error(`unexpected ${call.functionName}`);
        },
      });

      const estimate = await client.estimateFeeWithBreakdown(10, 8453);
      expect(estimate.protocolFee).to.equal(0n);
      expect(estimate.totalFee).to.equal(500000n);
    });
  });

  describe("getRelayRequest", () => {
    it("should parse tuple into RelayRequest", async () => {
      const sender = ("0x" + "bb".repeat(20)) as Address;
      const relayer = ("0x" + "ee".repeat(20)) as Address;

      const client = makeClient({
        readStub: async () => ({
          sender,
          relayer,
          sourceChain: 1n,
          destChain: 42161n,
          fee: 5000n,
          deadline: 1700000000n,
          status: 2, // CLAIMED
          proofData: MOCK_PROOF_DATA,
        }),
      });

      const req = await client.getRelayRequest(MOCK_REQ_ID);
      expect(req.requestId).to.equal(MOCK_REQ_ID);
      expect(req.sender).to.equal(sender);
      expect(req.relayer).to.equal(relayer);
      expect(req.sourceChain).to.equal(1);
      expect(req.destChain).to.equal(42161);
      expect(req.fee).to.equal(5000n);
      expect(req.status).to.equal(RequestStatus.CLAIMED);
    });
  });

  describe("getProtocolFeeBps", () => {
    it("should return bigint bps", async () => {
      const client = makeClient({ readStub: async () => 100n });
      expect(await client.getProtocolFeeBps()).to.equal(100n);
    });
  });

  describe("getAccumulatedProtocolFees", () => {
    it("should return bigint accumulated fees", async () => {
      const client = makeClient({ readStub: async () => 999999n });
      expect(await client.getAccumulatedProtocolFees()).to.equal(999999n);
    });
  });

  // --------------------------------------------------------
  // Edge: parseRequestId no matching log
  // --------------------------------------------------------
  describe("parseRequestId fallback", () => {
    it("should return 0x when no logs match", async () => {
      const client = makeClient({
        withWallet: true,
        receiptStub: async () => ({
          transactionHash: MOCK_TX_HASH,
          logs: [],
        }),
      });

      const result = await client.submitRelayRequest(
        1,
        42161,
        MOCK_PROOF_DATA,
        1000000n,
        1000n,
      );
      expect(result.requestId).to.equal("0x");
    });
  });

  // --------------------------------------------------------
  // RequestStatus enum
  // --------------------------------------------------------
  describe("RequestStatus enum", () => {
    it("should have correct values", () => {
      expect(RequestStatus.NONE).to.equal(0);
      expect(RequestStatus.PENDING).to.equal(1);
      expect(RequestStatus.CLAIMED).to.equal(2);
      expect(RequestStatus.COMPLETED).to.equal(3);
      expect(RequestStatus.CANCELLED).to.equal(4);
      expect(RequestStatus.EXPIRED).to.equal(5);
    });
  });
});
