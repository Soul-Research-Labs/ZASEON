import { expect } from "chai";
import { type Hex, type Address } from "viem";
import {
  CrossChainProofRelayer,
  type RelayerMVPConfig,
  type RelayerStats,
} from "../src/relayer/CrossChainProofRelayer";

describe("CrossChainProofRelayer", () => {
  const makeConfig = (
    overrides?: Partial<RelayerMVPConfig>,
  ): RelayerMVPConfig => ({
    sourceChain: { rpcUrl: "http://localhost:8545", chainId: 421614 },
    destChain: { rpcUrl: "http://localhost:8546", chainId: 84532 },
    proofHubAddress: ("0x" + "aa".repeat(20)) as Address,
    relayAddress: ("0x" + "bb".repeat(20)) as Address,
    privateKey: ("0x" + "11".repeat(32)) as Hex,
    ...overrides,
  });

  // ================================================================
  // Constructor
  // ================================================================

  describe("constructor", () => {
    it("should create instance with valid config", () => {
      const relayer = new CrossChainProofRelayer(makeConfig());
      expect(relayer).to.be.instanceOf(CrossChainProofRelayer);
    });

    it("should default to not running", () => {
      const relayer = new CrossChainProofRelayer(makeConfig());
      expect(relayer.isRunning()).to.be.false;
    });

    it("should initialize empty stats", () => {
      const relayer = new CrossChainProofRelayer(makeConfig());
      const stats = relayer.getStats();
      expect(stats.proofsDetected).to.equal(0);
      expect(stats.proofsRelayed).to.equal(0);
      expect(stats.proofsFailed).to.equal(0);
      expect(stats.startedAt).to.equal(0);
      expect(stats.lastBlockProcessed).to.equal(0n);
    });

    it("should accept custom pollInterval", () => {
      const relayer = new CrossChainProofRelayer(
        makeConfig({ pollInterval: 5000 }),
      );
      expect(relayer).to.be.instanceOf(CrossChainProofRelayer);
    });

    it("should accept custom maxRetries", () => {
      const relayer = new CrossChainProofRelayer(makeConfig({ maxRetries: 5 }));
      expect(relayer).to.be.instanceOf(CrossChainProofRelayer);
    });

    it("should accept onEvent callback", () => {
      const events: any[] = [];
      const relayer = new CrossChainProofRelayer(
        makeConfig({ onEvent: (e) => events.push(e) }),
      );
      expect(relayer).to.be.instanceOf(CrossChainProofRelayer);
    });
  });

  // ================================================================
  // Stop
  // ================================================================

  describe("stop()", () => {
    it("should set running to false", () => {
      const relayer = new CrossChainProofRelayer(makeConfig());
      relayer.stop();
      expect(relayer.isRunning()).to.be.false;
    });
  });

  // ================================================================
  // Stats
  // ================================================================

  describe("getStats()", () => {
    it("should return a copy of stats", () => {
      const relayer = new CrossChainProofRelayer(makeConfig());
      const stats1 = relayer.getStats();
      const stats2 = relayer.getStats();
      expect(stats1).to.deep.equal(stats2);
      expect(stats1).to.not.equal(stats2); // different object references
    });
  });

  // ================================================================
  // Config Types
  // ================================================================

  describe("RelayerMVPConfig", () => {
    it("should support Arbitrum Sepolia → Base Sepolia", () => {
      const config = makeConfig({
        sourceChain: {
          rpcUrl: "https://arb-sepolia.example.com",
          chainId: 421614,
        },
        destChain: {
          rpcUrl: "https://base-sepolia.example.com",
          chainId: 84532,
        },
      });
      expect(config.sourceChain.chainId).to.equal(421614);
      expect(config.destChain.chainId).to.equal(84532);
    });
  });
});
