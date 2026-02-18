import { expect } from "chai";
import { type Hex, type Address, type Hash } from "viem";
import { SoulRelayer, type RelayerConfig } from "../src/relayer/SoulRelayer";

describe("SoulRelayer", () => {
  const makeConfig = (overrides?: Partial<RelayerConfig>): RelayerConfig => ({
    rpcUrl: "http://localhost:8545",
    contractAddress: ("0x" + "ab".repeat(20)) as Address,
    stake: 10n * 10n ** 18n, // 10 ETH
    endpoints: ["https://relay1.soul.io"],
    ...overrides,
  });

  // ================================================================
  // Constructor
  // ================================================================

  describe("constructor", () => {
    it("should create instance without private key (read-only)", () => {
      const relayer = new SoulRelayer(makeConfig());
      expect(relayer).to.be.instanceOf(SoulRelayer);
    });

    it("should create instance with private key", () => {
      const relayer = new SoulRelayer(
        makeConfig({
          privateKey: ("0x" + "11".repeat(32)) as Hex,
        }),
      );
      expect(relayer).to.be.instanceOf(SoulRelayer);
    });

    it("should accept custom endpoints", () => {
      const relayer = new SoulRelayer(
        makeConfig({
          endpoints: ["https://relay1.soul.io", "https://relay2.soul.io"],
        }),
      );
      expect(relayer).to.be.instanceOf(SoulRelayer);
    });
  });

  // ================================================================
  // Configuration Types
  // ================================================================

  describe("RelayerConfig", () => {
    it("should accept bigint stake", () => {
      const config = makeConfig({ stake: 1000000000000000000n });
      expect(config.stake).to.equal(1000000000000000000n);
    });

    it("should accept zero stake", () => {
      const config = makeConfig({ stake: 0n });
      expect(config.stake).to.equal(0n);
    });
  });
});
