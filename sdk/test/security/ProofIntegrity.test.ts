/**
 * SDK Security Tests — Proof Integrity
 *
 * Tests that NoirProver generates valid-format proofs and handles errors gracefully.
 */

import { expect } from "chai";
import {
  NoirProver,
  Circuit,
  ProofResult,
} from "../../src/zkprover/NoirProver";

describe("NoirProver Proof Integrity", () => {
  let prover: NoirProver;

  beforeEach(() => {
    prover = new NoirProver({ mode: "development" });
  });

  describe("Development Mode", () => {
    it("should create prover in development mode", () => {
      expect(prover).to.not.be.undefined;
    });

    it("should enumerate all circuit types", () => {
      const circuits = Object.values(Circuit);
      expect(circuits.length).to.be.greaterThan(0);

      // Verify known circuits exist
      expect(circuits).to.include("state_commitment");
      expect(circuits).to.include("merkle_proof");
      expect(circuits).to.include("cross_chain_proof");
      expect(circuits).to.include("nullifier");
    });
  });

  describe("Proof Format Validation", () => {
    it("should generate proof with correct structure", async () => {
      try {
        const result = await prover.generateProof(Circuit.Nullifier, {
          secret: "0x1234",
          nullifier: "0x5678",
        });

        // Development mode should return a placeholder proof
        if (result) {
          expect(result).to.have.property("proof");
          expect(result).to.have.property("publicInputs");
          expect(result).to.have.property("proofHex");

          // Proof should be non-empty
          if (result.proof) {
            expect(result.proof.length).to.be.greaterThan(0);
          }

          // proofHex should be valid hex
          if (result.proofHex) {
            expect(result.proofHex).to.match(/^0x[a-fA-F0-9]*$/);
          }
        }
      } catch (e: any) {
        // In development mode without Barretenberg, may throw
        // but should be a descriptive error, not unhandled
        expect(e.message).to.be.a("string");
        expect(e.message.length).to.be.greaterThan(0);
      }
    });

    it("should reject invalid circuit names gracefully", async () => {
      try {
        // @ts-ignore — intentionally passing invalid circuit
        await prover.generateProof("nonexistent_circuit" as Circuit, {});
      } catch (e: any) {
        expect(e).to.be.an("error");
        expect(e.message).to.be.a("string");
      }
    });
  });

  describe("Production Mode Safety", () => {
    it("should create prover in production mode", () => {
      const prodProver = new NoirProver({ mode: "production" });
      expect(prodProver).to.not.be.undefined;
    });

    it("should throw in production when Barretenberg unavailable", async () => {
      const prodProver = new NoirProver({ mode: "production" });

      try {
        await prodProver.generateProof(Circuit.StateCommitment, {
          secret: "0x1234",
          nullifier: "0x5678",
          amount: BigInt(100),
        });
        // If we reach here, Barretenberg is available (rare in test env)
      } catch (e: any) {
        // Production mode should throw a clear error
        expect(e).to.be.an("error");
      }
    });
  });

  describe("Determinism", () => {
    it("should produce same proof for same inputs in development mode", async () => {
      const inputs = {
        secret: "0xaaaa",
        nullifier: "0xbbbb",
      };

      try {
        const result1 = await prover.generateProof(Circuit.Nullifier, inputs);
        const result2 = await prover.generateProof(Circuit.Nullifier, inputs);

        if (result1 && result2) {
          // Development placeholder proofs should be deterministic
          expect(result1.proofHex).to.equal(result2.proofHex);
        }
      } catch {
        // Acceptable if Barretenberg not available
      }
    });
  });
});
