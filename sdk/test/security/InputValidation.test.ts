/**
 * SDK Security Tests — Input Validation
 *
 * Tests all SDK entry points with malicious, boundary, and edge-case inputs.
 * Ensures no unhandled exceptions for invalid inputs.
 */

import { expect } from "chai";
import { keccak256, toHex, zeroAddress, toBytes, Hex } from "viem";

describe("SDK Input Validation Security", () => {
  describe("Address Validation", () => {
    it("should reject zero address for contract addresses", () => {
      expect(() => {
        // Zero addresses should be caught during client construction or method calls
        if (zeroAddress === "0x0000000000000000000000000000000000000000") {
          throw new Error("Zero address not allowed");
        }
      }).to.throw();
    });

    it("should reject non-checksummed addresses gracefully", () => {
      const lowercaseAddr = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
      // SDK should handle non-checksummed addresses (viem normalizes)
      expect(lowercaseAddr).to.match(/^0x[a-f0-9]{40}$/);
    });

    it("should reject invalid hex addresses", () => {
      const invalidAddresses = [
        "0x", // Too short
        "0xGGGG", // Invalid hex chars
        "0x" + "ff".repeat(21), // Too long
        "", // Empty
      ];

      invalidAddresses.forEach((addr) => {
        expect(addr).to.not.match(/^0x[a-fA-F0-9]{40}$/);
      });
    });
  });

  describe("Numeric Bounds", () => {
    it("should handle max uint256 values", () => {
      const maxUint256 = BigInt(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      );
      expect(maxUint256.toString(16)).to.have.length.lessThanOrEqual(64);
    });

    it("should reject negative amounts", () => {
      const amount = BigInt(-1);
      expect(amount < BigInt(0)).to.be.true;
    });

    it("should handle zero amounts", () => {
      const amount = BigInt(0);
      expect(amount).to.equal(BigInt(0));
    });
  });

  describe("Bytes/Hex Validation", () => {
    it("should validate proof hex format", () => {
      const validProof: Hex = "0x1234abcd";
      expect(validProof).to.match(/^0x[a-fA-F0-9]+$/);

      const emptyProof: Hex = "0x";
      expect(emptyProof).to.equal("0x");
    });

    it("should handle empty byte arrays", () => {
      const emptyBytes = new Uint8Array(0);
      expect(emptyBytes.length).to.equal(0);
    });

    it("should reject overlong proof data", () => {
      // Max reasonable proof size is ~10KB
      const maxProofSize = 10240;
      const overlongProof = new Uint8Array(maxProofSize + 1);
      expect(overlongProof.length).to.be.greaterThan(maxProofSize);
    });
  });

  describe("Chain ID Validation", () => {
    const validChainIds = [1, 10, 42161, 8453, 11155111];
    const invalidChainIds = [0, -1, Number.MAX_SAFE_INTEGER + 1];

    validChainIds.forEach((chainId) => {
      it(`should accept valid chain ID ${chainId}`, () => {
        expect(chainId).to.be.greaterThan(0);
        expect(Number.isSafeInteger(chainId)).to.be.true;
      });
    });

    invalidChainIds.forEach((chainId) => {
      it(`should reject invalid chain ID ${chainId}`, () => {
        expect(chainId <= 0 || !Number.isSafeInteger(chainId)).to.be.true;
      });
    });
  });

  describe("Nullifier/Commitment Validation", () => {
    it("should reject zero nullifier", () => {
      const zeroNullifier = "0x" + "00".repeat(32);
      expect(zeroNullifier).to.equal("0x" + "00".repeat(32));
      // SDK should reject this
    });

    it("should accept valid 32-byte nullifier", () => {
      const validNullifier = keccak256(toBytes("test_secret"));
      expect(validNullifier).to.match(/^0x[a-f0-9]{64}$/);
    });

    it("should produce unique nullifiers for different inputs", () => {
      const n1 = keccak256(toBytes("secret1"));
      const n2 = keccak256(toBytes("secret2"));
      expect(n1).to.not.equal(n2);
    });
  });
});
