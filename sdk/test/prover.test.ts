import { expect } from "chai";
import {
  poseidonHash,
  computeCommitment,
  computeNullifier,
  computePubkey,
} from "../src/zkprover/prover";

describe("prover (Poseidon utilities)", () => {
  describe("poseidonHash()", () => {
    it("should hash a single input", () => {
      const h = poseidonHash([BigInt(1)]);
      expect(typeof h).to.equal("bigint");
      expect(h).to.not.equal(BigInt(0));
    });

    it("should hash two inputs", () => {
      const h = poseidonHash([BigInt(1), BigInt(2)]);
      expect(typeof h).to.equal("bigint");
    });

    it("should hash many inputs by chaining", () => {
      const h = poseidonHash([BigInt(1), BigInt(2), BigInt(3), BigInt(4)]);
      expect(typeof h).to.equal("bigint");
    });

    it("should throw on empty input", () => {
      expect(() => poseidonHash([])).to.throw("at least one input");
    });

    it("should be deterministic", () => {
      const a = poseidonHash([BigInt(42), BigInt(99)]);
      const b = poseidonHash([BigInt(42), BigInt(99)]);
      expect(a).to.equal(b);
    });

    it("should produce different outputs for different inputs", () => {
      const a = poseidonHash([BigInt(1)]);
      const b = poseidonHash([BigInt(2)]);
      expect(a).to.not.equal(b);
    });
  });

  describe("computeCommitment()", () => {
    it("should return a bigint", () => {
      const c = computeCommitment([BigInt(10), BigInt(20)], BigInt(99), BigInt(42));
      expect(typeof c).to.equal("bigint");
    });

    it("should be deterministic", () => {
      const fields = [BigInt(10), BigInt(20)];
      const a = computeCommitment(fields, BigInt(99), BigInt(42));
      const b = computeCommitment(fields, BigInt(99), BigInt(42));
      expect(a).to.equal(b);
    });

    it("should change when salt changes", () => {
      const fields = [BigInt(10)];
      const a = computeCommitment(fields, BigInt(1), BigInt(42));
      const b = computeCommitment(fields, BigInt(2), BigInt(42));
      expect(a).to.not.equal(b);
    });
  });

  describe("computeNullifier()", () => {
    it("should return a bigint", () => {
      const n = computeNullifier(BigInt(100), BigInt(42), BigInt(0));
      expect(typeof n).to.equal("bigint");
    });

    it("should change with different nonces", () => {
      const a = computeNullifier(BigInt(100), BigInt(42), BigInt(0));
      const b = computeNullifier(BigInt(100), BigInt(42), BigInt(1));
      expect(a).to.not.equal(b);
    });
  });

  describe("computePubkey()", () => {
    it("should derive a public key from a secret", () => {
      const pk = computePubkey(BigInt(123456));
      expect(typeof pk).to.equal("bigint");
      expect(pk).to.not.equal(BigInt(0));
    });

    it("should be deterministic", () => {
      const a = computePubkey(BigInt(789));
      const b = computePubkey(BigInt(789));
      expect(a).to.equal(b);
    });
  });
});
