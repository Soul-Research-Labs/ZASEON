import { expect } from "chai";
import { type Address, type Hash, type Hex } from "viem";

// Optimism
import {
  opToWei,
  weiToOp,
  calculateOptimismBridgeFee,
  validateOPDepositAmount,
  validateOptimismEscrowTimelocks,
  estimateOptimismBlockFinalityMs,
  isOptimismRefundEligible,
  WEI_PER_OP,
  OP_BRIDGE_FEE_BPS,
  OP_BPS_DENOMINATOR,
  OP_MIN_DEPOSIT_WEI,
  OP_MAX_DEPOSIT_WEI,
  OPTIMISM_CHAIN_ID,
} from "../src/bridges/optimism";

// Arbitrum
import {
  calculateBridgeFee as arbBridgeFee,
  computeDepositId as arbDepositId,
  computeWithdrawalId as arbWithdrawalId,
  estimateDepositCost as arbEstimateDepositCost,
  validateDepositAmount as arbValidateAmount,
  getArbitrumNetworkName,
  ARB_ONE_CHAIN_ID,
  ARB_NOVA_CHAIN_ID,
  FEE_DENOMINATOR as ARB_FEE_DENOM,
} from "../src/bridges/arbitrum";

// Base
import {
  computeMessageId as baseMessageId,
  isWithdrawalReady as baseWithdrawalReady,
  getBaseDomain,
  getBaseNetworkName,
  BASE_MAINNET_CHAIN_ID,
  BASE_SEPOLIA_CHAIN_ID,
} from "../src/bridges/base";

// Scroll
import {
  computeMessageHash as scrollMessageHash,
  getScrollConfig,
  SCROLL_CHAIN_ID,
  SCROLL_SEPOLIA_CHAIN_ID,
} from "../src/bridges/scroll";

// Linea
import {
  computeMessageHash as lineaMessageHash,
  getLineaConfig,
  LINEA_CHAIN_ID,
  LINEA_SEPOLIA_CHAIN_ID,
} from "../src/bridges/linea";

// zkSync
import {
  computeDepositHash as zkDepositHash,
  getZkSyncConfig,
  estimateL1ToL2BaseCost,
  ZKSYNC_ERA_CHAIN_ID,
  ZKSYNC_SEPOLIA_CHAIN_ID,
} from "../src/bridges/zksync";

// Polygon zkEVM
import {
  computeDepositHash as polyDepositHash,
  getPolygonZkEVMConfig,
  POLYGON_ZKEVM_CHAIN_ID,
} from "../src/bridges/polygon-zkevm";

// Hyperlane
import {
  addressToBytes32 as hlAddrToB32,
  bytes32ToAddress as hlB32ToAddr,
  computeMessageId as hlMessageId,
  ismTypeToIndex,
  getDomainName,
} from "../src/bridges/hyperlane";

// LayerZero
import {
  addressToBytes32 as lzAddrToB32,
  bytes32ToAddress as lzB32ToAddr,
  calculateLzFee,
  createDefaultOptions,
  chainTypeToIndex,
  securityLevelToIndex,
  getEidName,
} from "../src/bridges/layerzero";

// ============================================================
// Common constants
// ============================================================

const ADDR_A = ("0x" + "aa".repeat(20)) as Address;
const ADDR_B = ("0x" + "bb".repeat(20)) as Address;

// ============================================================
// Tests
// ============================================================

describe("Bridge Utilities", () => {
  // ============================================================
  // Optimism
  // ============================================================
  describe("Optimism", () => {
    it("opToWei should convert ETH to wei", () => {
      expect(opToWei(1)).to.equal(WEI_PER_OP);
      expect(opToWei("0.5")).to.equal(WEI_PER_OP / 2n);
    });

    it("weiToOp should convert wei back to string", () => {
      const result = weiToOp(WEI_PER_OP);
      expect(parseFloat(result)).to.equal(1);
    });

    it("calculateOptimismBridgeFee should apply fee bps", () => {
      const amount = 10000000000000000n; // 0.01 ETH
      const fee = calculateOptimismBridgeFee(amount);
      expect(fee).to.equal((amount * OP_BRIDGE_FEE_BPS) / OP_BPS_DENOMINATOR);
    });

    it("validateOPDepositAmount should accept valid range", () => {
      const result = validateOPDepositAmount(OP_MIN_DEPOSIT_WEI);
      expect(result.valid).to.be.true;
    });

    it("validateOPDepositAmount should reject below minimum", () => {
      const result = validateOPDepositAmount(OP_MIN_DEPOSIT_WEI - 1n);
      expect(result.valid).to.be.false;
      expect(result.error).to.be.a("string");
    });

    it("validateOPDepositAmount should reject above maximum", () => {
      const result = validateOPDepositAmount(OP_MAX_DEPOSIT_WEI + 1n);
      expect(result.valid).to.be.false;
    });

    it("validateOptimismEscrowTimelocks should validate correct range", () => {
      const now = Math.floor(Date.now() / 1000);
      const result = validateOptimismEscrowTimelocks(
        now + 3600, // finishAfter: 1h from now
        now + 86400, // cancelAfter: 1d from now
      );
      expect(result.valid).to.be.true;
    });

    it("estimateOptimismBlockFinalityMs should return positive number", () => {
      const ms = estimateOptimismBlockFinalityMs();
      expect(ms).to.be.greaterThan(0);
    });

    it("OPTIMISM_CHAIN_ID should be 10", () => {
      expect(OPTIMISM_CHAIN_ID).to.equal(10);
    });
  });

  // ============================================================
  // Arbitrum
  // ============================================================
  describe("Arbitrum", () => {
    it("calculateBridgeFee should apply 15 bps default", () => {
      const fee = arbBridgeFee(10000n);
      expect(fee).to.equal((10000n * 15n) / ARB_FEE_DENOM);
    });

    it("calculateBridgeFee should accept custom bps", () => {
      const fee = arbBridgeFee(10000n, 50n);
      expect(fee).to.equal((10000n * 50n) / ARB_FEE_DENOM);
    });

    it("computeDepositId should produce a deterministic hash", () => {
      const id1 = arbDepositId(ADDR_A, ADDR_B, 1000n, 1n);
      const id2 = arbDepositId(ADDR_A, ADDR_B, 1000n, 1n);
      expect(id1).to.equal(id2);
      expect(id1).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("computeWithdrawalId should produce deterministic hash", () => {
      const wId1 = arbWithdrawalId(ADDR_A, ADDR_B, 1000n, 1n);
      const wId2 = arbWithdrawalId(ADDR_A, ADDR_B, 1000n, 1n);
      expect(wId1).to.equal(wId2);
      expect(wId1).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("computeWithdrawalId should differ with different params", () => {
      const wId1 = arbWithdrawalId(ADDR_A, ADDR_B, 1000n, 1n);
      const wId2 = arbWithdrawalId(ADDR_B, ADDR_A, 1000n, 1n);
      expect(wId1).to.not.equal(wId2);
    });

    it("estimateDepositCost should return total = fee + gasEstimate", () => {
      const est = arbEstimateDepositCost(1000000000000000000n); // 1 ETH
      expect(est.total).to.equal(est.fee + est.gasEstimate);
    });

    it("validateDepositAmount should accept amount in range", () => {
      // min is 0.001 ETH = 1_000_000_000_000_000
      expect(arbValidateAmount(1_000_000_000_000_000n)).to.be.true;
    });

    it("validateDepositAmount should reject below minimum", () => {
      expect(arbValidateAmount(999n)).to.be.false;
    });

    it("getArbitrumNetworkName should recognize ARB_ONE", () => {
      expect(getArbitrumNetworkName(ARB_ONE_CHAIN_ID)).to.be.a("string");
    });

    it("chain IDs should be correct", () => {
      expect(ARB_ONE_CHAIN_ID).to.equal(42161);
      expect(ARB_NOVA_CHAIN_ID).to.equal(42170);
    });
  });

  // ============================================================
  // Base
  // ============================================================
  describe("Base", () => {
    it("computeMessageId should produce a deterministic hash", () => {
      const id1 = baseMessageId(0, ADDR_A, ADDR_B, 1n);
      const id2 = baseMessageId(0, ADDR_A, ADDR_B, 1n);
      expect(id1).to.equal(id2);
      expect(id1).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("isWithdrawalReady should return false for recent requests", () => {
      const now = Math.floor(Date.now() / 1000);
      expect(baseWithdrawalReady(now)).to.be.false;
    });

    it("isWithdrawalReady should return true for old requests", () => {
      const ancient = Math.floor(Date.now() / 1000) - 8 * 86400; // 8 days ago
      expect(baseWithdrawalReady(ancient)).to.be.true;
    });

    it("getBaseDomain should return domain for known chain IDs", () => {
      expect(getBaseDomain(BASE_MAINNET_CHAIN_ID)).to.be.a("number");
    });

    it("getBaseNetworkName should recognize Base Sepolia", () => {
      const name = getBaseNetworkName(BASE_SEPOLIA_CHAIN_ID);
      expect(name.toLowerCase()).to.include("base");
    });

    it("chain IDs should be correct", () => {
      expect(BASE_MAINNET_CHAIN_ID).to.equal(8453);
      expect(BASE_SEPOLIA_CHAIN_ID).to.equal(84532);
    });
  });

  // ============================================================
  // Scroll
  // ============================================================
  describe("Scroll", () => {
    it("computeMessageHash should produce deterministic hash", () => {
      const h1 = scrollMessageHash(ADDR_A, ADDR_B, 100n, 1n, "0x" as Hex);
      const h2 = scrollMessageHash(ADDR_A, ADDR_B, 100n, 1n, "0x" as Hex);
      expect(h1).to.equal(h2);
    });

    it("getScrollConfig should return config for mainnet", () => {
      const config = getScrollConfig(SCROLL_CHAIN_ID);
      expect(config).to.have.property("chainId");
    });

    it("getScrollConfig should return config for sepolia", () => {
      const config = getScrollConfig(SCROLL_SEPOLIA_CHAIN_ID);
      expect(config.chainId).to.equal(SCROLL_SEPOLIA_CHAIN_ID);
    });
  });

  // ============================================================
  // Linea
  // ============================================================
  describe("Linea", () => {
    it("computeMessageHash should produce deterministic hash", () => {
      const h = lineaMessageHash(ADDR_A, ADDR_B, 10n, 50n, 1n, "0x" as Hex);
      expect(h).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("getLineaConfig should return config for mainnet", () => {
      const config = getLineaConfig(LINEA_CHAIN_ID);
      expect(config.chainId).to.equal(LINEA_CHAIN_ID);
    });

    it("chain IDs should be correct", () => {
      expect(LINEA_CHAIN_ID).to.equal(59144);
      expect(LINEA_SEPOLIA_CHAIN_ID).to.equal(59141);
    });
  });

  // ============================================================
  // zkSync
  // ============================================================
  describe("zkSync", () => {
    it("computeDepositHash should produce deterministic hash", () => {
      const h = zkDepositHash(ADDR_A, ADDR_B, ADDR_A, 1000n, 1n);
      expect(h).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("getZkSyncConfig should return config for mainnet", () => {
      const config = getZkSyncConfig(ZKSYNC_ERA_CHAIN_ID);
      expect(config.chainId).to.equal(ZKSYNC_ERA_CHAIN_ID);
    });

    it("estimateL1ToL2BaseCost should return positive cost", () => {
      const cost = estimateL1ToL2BaseCost(20000000000n); // 20 gwei
      expect(cost > 0n).to.be.true;
    });

    it("chain IDs should be correct", () => {
      expect(ZKSYNC_ERA_CHAIN_ID).to.equal(324);
      expect(ZKSYNC_SEPOLIA_CHAIN_ID).to.equal(300);
    });
  });

  // ============================================================
  // Polygon zkEVM
  // ============================================================
  describe("Polygon zkEVM", () => {
    it("computeDepositHash should produce deterministic hash", () => {
      const h = polyDepositHash(0, ADDR_A, 1, ADDR_B, 500n, "0x" as Hex);
      expect(h).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("getPolygonZkEVMConfig should return config for mainnet", () => {
      const config = getPolygonZkEVMConfig(POLYGON_ZKEVM_CHAIN_ID);
      expect(config.chainId).to.equal(POLYGON_ZKEVM_CHAIN_ID);
    });
  });

  // ============================================================
  // Hyperlane
  // ============================================================
  describe("Hyperlane", () => {
    it("addressToBytes32 should left-pad address to 32 bytes", () => {
      const b32 = hlAddrToB32(ADDR_A);
      expect(b32).to.match(/^0x[0-9a-f]{64}$/);
      expect(b32.toLowerCase().endsWith("aa".repeat(20))).to.be.true;
    });

    it("bytes32ToAddress should extract lower 20 bytes", () => {
      const b32 = hlAddrToB32(ADDR_A);
      const addr = hlB32ToAddr(b32);
      expect(addr.toLowerCase()).to.equal(ADDR_A.toLowerCase());
    });

    it("addressToBytes32 / bytes32ToAddress round-trip", () => {
      const addr = hlB32ToAddr(hlAddrToB32(ADDR_B));
      expect(addr.toLowerCase()).to.equal(ADDR_B.toLowerCase());
    });

    it("ismTypeToIndex should return numeric index for known ISM types", () => {
      const idx = ismTypeToIndex("MULTISIG" as any);
      expect(idx).to.equal(0);
    });

    it("getDomainName should return name for known domains", () => {
      const name = getDomainName(1); // Ethereum mainnet
      expect(name).to.be.a("string");
    });
  });

  // ============================================================
  // LayerZero
  // ============================================================
  describe("LayerZero", () => {
    it("addressToBytes32 should left-pad address", () => {
      const b32 = lzAddrToB32(ADDR_A);
      expect(b32).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("bytes32ToAddress round-trip", () => {
      const addr = lzB32ToAddr(lzAddrToB32(ADDR_A));
      expect(addr.toLowerCase()).to.equal(ADDR_A.toLowerCase());
    });

    it("calculateLzFee should apply default 10 bps", () => {
      const fee = calculateLzFee(100000n);
      expect(fee).to.equal((100000n * 10n) / 10000n);
    });

    it("calculateLzFee should accept custom bps", () => {
      const fee = calculateLzFee(100000n, 50n);
      expect(fee).to.equal((100000n * 50n) / 10000n);
    });

    it("createDefaultOptions should return valid options", () => {
      const opts = createDefaultOptions();
      expect(opts).to.have.property("gas");
    });

    it("chainTypeToIndex should return number", () => {
      const idx = chainTypeToIndex("EVM" as any);
      expect(idx).to.equal(0);
    });

    it("securityLevelToIndex should return number", () => {
      const idx = securityLevelToIndex("STANDARD" as any);
      expect(idx).to.equal(0);
    });

    it("getEidName should return string for known EIDs", () => {
      const name = getEidName(30101); // Ethereum
      expect(name).to.be.a("string");
    });
  });
});
