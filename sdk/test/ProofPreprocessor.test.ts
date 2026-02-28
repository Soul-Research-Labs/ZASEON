import { expect } from "chai";
import {
  ProofPreprocessor,
  MemoryPreprocessorStorage,
  type PreprocessedData,
  type PreprocessorConfig,
} from "../src/zkprover/ProofPreprocessor";

describe("ProofPreprocessor", () => {
  let preprocessor: ProofPreprocessor;

  beforeEach(() => {
    preprocessor = new ProofPreprocessor();
  });

  describe("preprocess()", () => {
    it("should preprocess witness inputs and return a valid PreprocessedData", async () => {
      const result = await preprocessor.preprocess("balance_proof", {
        balance: "1000000",
        nullifier: "0xabcdef",
      });

      expect(result).to.have.property("id");
      expect(result).to.have.property("circuit", "balance_proof");
      expect(result).to.have.property("witnessCommitment");
      expect(result.witnessCommitment).to.match(/^0x/);
      expect(result).to.have.property("intermediateState");
      expect(result.intermediateState).to.be.instanceOf(Uint8Array);
      expect(result).to.have.property("circuitVersion", "1.0.0");
      expect(result.expiresAt).to.be.greaterThan(Date.now());
    });

    it("should produce different IDs for different inputs", async () => {
      const r1 = await preprocessor.preprocess("balance_proof", {
        balance: "100",
      });
      // small delay to ensure different timestamp
      await new Promise((r) => setTimeout(r, 5));
      const r2 = await preprocessor.preprocess("balance_proof", {
        balance: "200",
      });

      expect(r1.id).to.not.equal(r2.id);
    });

    it("should produce different IDs for different circuits", async () => {
      const r1 = await preprocessor.preprocess("balance_proof", {
        x: "1",
      });
      await new Promise((r) => setTimeout(r, 5));
      const r2 = await preprocessor.preprocess("state_commitment", {
        x: "1",
      });

      expect(r1.id).to.not.equal(r2.id);
    });

    it("should update stats on preprocess", async () => {
      await preprocessor.preprocess("balance_proof", { balance: "100" });
      await preprocessor.preprocess("nullifier_check", { nul: "0x01" });

      const stats = preprocessor.getStats();
      expect(stats.totalPreprocessed).to.equal(2);
    });
  });

  describe("finalize()", () => {
    it("should finalize a preprocessed proof (cache hit)", async () => {
      const preData = await preprocessor.preprocess("balance_proof", {
        balance: "1000000",
      });

      const result = await preprocessor.finalize(preData.id, {
        recipient: "0x1234",
      });

      expect(result.fromCache).to.be.true;
      expect(result.estimatedGasSavings).to.equal(300000);
      expect(result.preprocessedId).to.equal(preData.id);
      expect(result.proof).to.be.instanceOf(Uint8Array);
      expect(result.proofHex).to.match(/^0x/);
      expect(result.publicInputs).to.have.length.greaterThan(0);
    });

    it("should generate a fresh proof on cache miss", async () => {
      const result = await preprocessor.finalize("nonexistent_id", {
        data: "test",
      });

      expect(result.fromCache).to.be.false;
      expect(result.estimatedGasSavings).to.equal(0);
      expect(result.preprocessedId).to.be.undefined;
    });

    it("should remove the cached entry after finalization", async () => {
      const preData = await preprocessor.preprocess("balance_proof", {
        balance: "100",
      });

      await preprocessor.finalize(preData.id);

      // Second finalize should be a cache miss
      const result = await preprocessor.finalize(preData.id);
      expect(result.fromCache).to.be.false;
    });

    it("should handle expired cache entries", async () => {
      const shortTtl = new ProofPreprocessor({ cacheTtlMs: 1 }); // 1ms TTL
      const preData = await shortTtl.preprocess("balance_proof", {
        balance: "100",
      });

      // Wait for TTL to expire
      await new Promise((r) => setTimeout(r, 10));

      const result = await shortTtl.finalize(preData.id);
      expect(result.fromCache).to.be.false;
    });
  });

  describe("circuit versioning", () => {
    it("should invalidate cache on circuit version change", async () => {
      const preData = await preprocessor.preprocess("balance_proof", {
        balance: "100",
      });

      preprocessor.setCircuitVersion("2.0.0");

      const result = await preprocessor.finalize(preData.id);
      expect(result.fromCache).to.be.false;
    });

    it("should report current circuit version", () => {
      expect(preprocessor.getCircuitVersion()).to.equal("1.0.0");

      preprocessor.setCircuitVersion("2.0.0");
      expect(preprocessor.getCircuitVersion()).to.equal("2.0.0");
    });
  });

  describe("cache management", () => {
    it("should retrieve cached data without consuming it", async () => {
      const preData = await preprocessor.preprocess("balance_proof", {
        balance: "100",
      });

      const cached = await preprocessor.getCached(preData.id);
      expect(cached).to.not.be.null;
      expect(cached!.id).to.equal(preData.id);

      // Should still be available
      const cached2 = await preprocessor.getCached(preData.id);
      expect(cached2).to.not.be.null;
    });

    it("should return null for nonexistent cache entries", async () => {
      const cached = await preprocessor.getCached("nonexistent");
      expect(cached).to.be.null;
    });

    it("should clear all cached data", async () => {
      await preprocessor.preprocess("balance_proof", { balance: "100" });
      await preprocessor.preprocess("nullifier_check", { nul: "0x01" });

      await preprocessor.clearCache();

      const stats = preprocessor.getStats();
      // Stats should still track preprocessed count, but cache is empty
      expect(stats.totalPreprocessed).to.equal(2);
    });
  });

  describe("stats tracking", () => {
    it("should track hit rate correctly", async () => {
      const preData = await preprocessor.preprocess("balance_proof", {
        balance: "100",
      });

      // 1 cache hit
      await preprocessor.finalize(preData.id);

      // 1 cache miss
      await preprocessor.finalize("nonexistent");

      const stats = preprocessor.getStats();
      expect(stats.cacheHits).to.equal(1);
      expect(stats.cacheMisses).to.equal(1);
      expect(stats.hitRate).to.equal(0.5);
      expect(stats.estimatedTotalGasSaved).to.equal(300000);
    });

    it("should reset stats", async () => {
      await preprocessor.preprocess("balance_proof", { balance: "100" });
      preprocessor.resetStats();

      const stats = preprocessor.getStats();
      expect(stats.totalPreprocessed).to.equal(0);
      expect(stats.cacheHits).to.equal(0);
      expect(stats.cacheMisses).to.equal(0);
    });
  });

  describe("custom storage backend", () => {
    it("should use a custom storage backend", async () => {
      const storage = new MemoryPreprocessorStorage();
      const pp = new ProofPreprocessor({ storage });

      const preData = await pp.preprocess("balance_proof", {
        balance: "100",
      });

      // Verify data is in the custom storage
      const stored = await storage.get(preData.id);
      expect(stored).to.not.be.null;
      expect(stored!.circuit).to.equal("balance_proof");
    });
  });

  describe("max cache size", () => {
    it("should evict entries when cache is full", async () => {
      const pp = new ProofPreprocessor({ maxCacheSize: 2 });

      const r1 = await pp.preprocess("balance_proof", { x: "1" });
      await new Promise((r) => setTimeout(r, 5));
      const r2 = await pp.preprocess("balance_proof", { x: "2" });
      await new Promise((r) => setTimeout(r, 5));
      // This should trigger eviction of r1
      await pp.preprocess("balance_proof", { x: "3" });

      // r1 should be evicted (oldest)
      const cached = await pp.getCached(r1.id);
      expect(cached).to.be.null;

      // r2 should still be there
      const cached2 = await pp.getCached(r2.id);
      expect(cached2).to.not.be.null;
    });
  });
});
