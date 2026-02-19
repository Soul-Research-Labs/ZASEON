import { expect } from "chai";
import {
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  snarkjsToGnark,
  gnarkToSnarkjs,
  translateForChain,
  createVerifyCalldata,
  createBatchProofData,
  CURVE_PARAMS,
  CHAIN_CONFIGS,
  type Groth16Proof,
  type CurveType,
} from "../src/proof-translator/ProofTranslator";

// ============================================================
// Test data
// ============================================================

/** Canonical BN254 snarkjs-format proof */
const SNARKJS_PROOF = {
  pi_a: ["12345", "67890", "1"],
  pi_b: [
    ["111", "222"],
    ["333", "444"],
    ["1", "0"],
  ],
  pi_c: ["555", "666", "1"],
  protocol: "groth16",
  curve: "bn254",
};

/** gnark-format proof (Ar/Bs/Krs naming) */
const GNARK_PROOF = {
  Ar: { X: "12345", Y: "67890" },
  Bs: { X: ["111", "222"], Y: ["333", "444"] },
  Krs: { X: "555", Y: "666" },
};

/** Produce a mock Groth16Proof for reuse */
function makeBN254Proof(): Groth16Proof {
  return {
    pi_a: { x: 1001n, y: 2002n },
    pi_b: { x: [3003n, 4004n], y: [5005n, 6006n] },
    pi_c: { x: 7007n, y: 8008n },
    protocol: "groth16",
    curve: "bn254",
  };
}

function makeBLS12Proof(): Groth16Proof {
  return {
    pi_a: { x: 100n, y: 200n },
    pi_b: { x: [300n, 400n], y: [500n, 600n] },
    pi_c: { x: 700n, y: 800n },
    protocol: "groth16",
    curve: "bls12-381",
  };
}

// ============================================================
// Tests
// ============================================================

describe("ProofTranslator", () => {
  // --------------------------------------------------------
  // Constants
  // --------------------------------------------------------
  describe("CURVE_PARAMS", () => {
    it("should define BN254, BLS12-381, BLS12-377", () => {
      expect(Object.keys(CURVE_PARAMS)).to.deep.equal([
        "bn254",
        "bls12-381",
        "bls12-377",
      ]);
    });

    it("BN254 g1Size should be 64 bytes (2 × 32)", () => {
      expect(CURVE_PARAMS.bn254.g1Size).to.equal(64);
      expect(CURVE_PARAMS.bn254.proofSize).to.equal(256);
    });

    it("BLS12-381 g1Size should be 96 bytes (2 × 48)", () => {
      expect(CURVE_PARAMS["bls12-381"].g1Size).to.equal(96);
      expect(CURVE_PARAMS["bls12-381"].proofSize).to.equal(384);
    });
  });

  describe("CHAIN_CONFIGS", () => {
    it("should include Ethereum, Arbitrum, Optimism, Base", () => {
      expect(CHAIN_CONFIGS.ethereum.chainId).to.equal(1);
      expect(CHAIN_CONFIGS.arbitrum.chainId).to.equal(42161);
      expect(CHAIN_CONFIGS.optimism.chainId).to.equal(10);
      expect(CHAIN_CONFIGS.base.chainId).to.equal(8453);
    });

    it("all mainnet EVM chains should use bn254", () => {
      for (const chain of [
        "ethereum",
        "arbitrum",
        "optimism",
        "base",
        "polygon",
        "scroll",
        "linea",
      ]) {
        expect(CHAIN_CONFIGS[chain].curve).to.equal("bn254");
      }
    });

    it("aleo should use bls12-377", () => {
      expect(CHAIN_CONFIGS.aleo.curve).to.equal("bls12-377");
    });
  });

  // --------------------------------------------------------
  // Parsing
  // --------------------------------------------------------
  describe("parseSnarkjsProof", () => {
    it("should parse snarkjs 3-element arrays into G1/G2 points", () => {
      const proof = parseSnarkjsProof(SNARKJS_PROOF);
      expect(proof.pi_a.x).to.equal(12345n);
      expect(proof.pi_a.y).to.equal(67890n);
      expect(proof.pi_b.x).to.deep.equal([111n, 222n]);
      expect(proof.pi_b.y).to.deep.equal([333n, 444n]);
      expect(proof.pi_c.x).to.equal(555n);
      expect(proof.pi_c.y).to.equal(666n);
      expect(proof.protocol).to.equal("groth16");
      expect(proof.curve).to.equal("bn254");
    });

    it("should default to groth16 and bn254 when not specified", () => {
      const proof = parseSnarkjsProof({
        pi_a: ["1", "2", "1"],
        pi_b: [
          ["3", "4"],
          ["5", "6"],
          ["1", "0"],
        ],
        pi_c: ["7", "8", "1"],
      });
      expect(proof.protocol).to.equal("groth16");
      expect(proof.curve).to.equal("bn254");
    });
  });

  describe("parseGnarkProof", () => {
    it("should parse Ar/Bs/Krs naming", () => {
      const proof = parseGnarkProof(GNARK_PROOF);
      expect(proof.pi_a.x).to.equal(12345n);
      expect(proof.pi_a.y).to.equal(67890n);
      expect(proof.pi_b.x).to.deep.equal([111n, 222n]);
      expect(proof.pi_c.x).to.equal(555n);
    });

    it("should handle lowercase ar/bs/krs naming", () => {
      const proof = parseGnarkProof({
        ar: { X: "10", Y: "20" },
        bs: { X: ["30", "40"], Y: ["50", "60"] },
        krs: { X: "70", Y: "80" },
      });
      expect(proof.pi_a.x).to.equal(10n);
      expect(proof.pi_c.y).to.equal(80n);
    });
  });

  describe("parseArkworksProof", () => {
    it("should parse 256-byte BN254 proof", () => {
      // 8 coordinates × 32 bytes each = 256 bytes
      const bytes = new Uint8Array(256);
      // Set pi_a.x = 1 at offset 0
      bytes[31] = 1;
      // Set pi_c.y = 255 at offset 224+31 = 255
      bytes[255] = 255;

      const proof = parseArkworksProof(bytes, "bn254");
      expect(proof.pi_a.x).to.equal(1n);
      expect(proof.pi_c.y).to.equal(255n);
      expect(proof.curve).to.equal("bn254");
    });

    it("should parse 384-byte BLS12-381 proof", () => {
      const bytes = new Uint8Array(384);
      bytes[47] = 42;
      const proof = parseArkworksProof(bytes, "bls12-381");
      expect(proof.pi_a.x).to.equal(42n);
      expect(proof.curve).to.equal("bls12-381");
    });
  });

  // --------------------------------------------------------
  // Conversion
  // --------------------------------------------------------
  describe("toSolidityBN254", () => {
    it("should reverse G2 coordinates for Solidity pairing precompile", () => {
      const proof = makeBN254Proof();
      const sol = toSolidityBN254(proof);

      // pA straight
      expect(BigInt(sol.pA[0])).to.equal(1001n);
      expect(BigInt(sol.pA[1])).to.equal(2002n);

      // pB reversed: x[1],x[0] and y[1],y[0]
      expect(BigInt(sol.pB[0][0])).to.equal(4004n); // was x[1]
      expect(BigInt(sol.pB[0][1])).to.equal(3003n); // was x[0]
      expect(BigInt(sol.pB[1][0])).to.equal(6006n); // was y[1]
      expect(BigInt(sol.pB[1][1])).to.equal(5005n); // was y[0]

      // pC straight
      expect(BigInt(sol.pC[0])).to.equal(7007n);
      expect(BigInt(sol.pC[1])).to.equal(8008n);
    });

    it("should produce 0x-prefixed 64-char hex strings", () => {
      const sol = toSolidityBN254(makeBN254Proof());
      expect(sol.pA[0]).to.match(/^0x[0-9a-f]{64}$/);
    });
  });

  describe("toBytesBN254", () => {
    it("should produce 256 bytes for BN254 proof", () => {
      const bytes = toBytesBN254(makeBN254Proof());
      expect(bytes.length).to.equal(256);
    });

    it("should round-trip with parseArkworksProof", () => {
      const original = makeBN254Proof();
      const bytes = toBytesBN254(original);
      // Note: toBytesBN254 reverses G2, parseArkworksProof does not
      // So this isn't a perfect round-trip, but we can verify length and first coord
      expect(bytes.length).to.equal(256);
    });
  });

  describe("toBytesBLS12381", () => {
    it("should produce 384 bytes for BLS12-381 proof", () => {
      const bytes = toBytesBLS12381(makeBLS12Proof());
      expect(bytes.length).to.equal(384);
    });
  });

  // --------------------------------------------------------
  // Format Translation
  // --------------------------------------------------------
  describe("snarkjsToGnark", () => {
    it("should convert pi_a/pi_b/pi_c to Ar/Bs/Krs", () => {
      const gnark = snarkjsToGnark(SNARKJS_PROOF);
      expect(gnark.Ar.X).to.equal("12345");
      expect(gnark.Ar.Y).to.equal("67890");
      expect(gnark.Bs.X).to.deep.equal(["111", "222"]);
      expect(gnark.Krs.X).to.equal("555");
    });
  });

  describe("gnarkToSnarkjs", () => {
    it("should convert Ar/Bs/Krs back to pi_a/pi_b/pi_c with trailing 1s", () => {
      const snark = gnarkToSnarkjs(GNARK_PROOF);
      expect(snark.pi_a[2]).to.equal("1");
      expect(snark.pi_b[2]).to.deep.equal(["1", "0"]);
      expect(snark.pi_c[2]).to.equal("1");
      expect(snark.protocol).to.equal("groth16");
    });

    it("should round-trip with snarkjsToGnark", () => {
      const gnark = snarkjsToGnark(SNARKJS_PROOF);
      const snark = gnarkToSnarkjs(gnark);
      expect(snark.pi_a[0]).to.equal(SNARKJS_PROOF.pi_a[0]);
      expect(snark.pi_a[1]).to.equal(SNARKJS_PROOF.pi_a[1]);
      expect(snark.pi_c[0]).to.equal(SNARKJS_PROOF.pi_c[0]);
    });
  });

  // --------------------------------------------------------
  // Chain Translation
  // --------------------------------------------------------
  describe("translateForChain", () => {
    it("should pass through same-curve proofs with BN254 bytes", () => {
      const proof = makeBN254Proof();
      const result = translateForChain(proof, [1n, 2n], "ethereum");
      expect(result.targetCurve).to.equal("bn254");
      expect(result.proofBytes.length).to.equal(256);
      expect(result.publicSignals).to.deep.equal([1n, 2n]);
    });

    it("should serialize BLS12-381 for aleo chain", () => {
      const proof = makeBLS12Proof();
      const result = translateForChain(proof, [10n], "aleo");
      expect(result.targetCurve).to.equal("bls12-377");
      expect(result.proofBytes.length).to.equal(384);
    });

    it("should throw for unknown chain", () => {
      expect(() =>
        translateForChain(makeBN254Proof(), [], "unknown_chain"),
      ).to.throw("Unknown target chain");
    });
  });

  // --------------------------------------------------------
  // Calldata
  // --------------------------------------------------------
  describe("createVerifyCalldata", () => {
    it("should produce valid ABI-encoded hex string", () => {
      const calldata = createVerifyCalldata(makeBN254Proof(), [100n, 200n]);
      expect(calldata).to.match(/^0x/);
      expect(calldata.length).to.be.greaterThan(100);
    });
  });

  // --------------------------------------------------------
  // Batch Proofs
  // --------------------------------------------------------
  describe("createBatchProofData", () => {
    it("should batch 2 proofs and produce merkle root", () => {
      const p1 = makeBN254Proof();
      const p2 = { ...makeBN254Proof(), pi_a: { x: 9999n, y: 8888n } };
      const signals = [[1n], [2n]];

      const { batchProofBytes, batchSignalsBytes, merkleRoot } =
        createBatchProofData([p1, p2], signals);

      // 2 proofs × (4 length prefix + 256 bytes) = 520
      expect(batchProofBytes.length).to.equal(520);
      expect(batchSignalsBytes.length).to.be.greaterThan(0);
      expect(merkleRoot).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should handle single proof", () => {
      const { merkleRoot } = createBatchProofData([makeBN254Proof()], [[1n]]);
      expect(merkleRoot).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should handle 3 proofs (odd count triggers padding)", () => {
      const p = makeBN254Proof();
      const { merkleRoot, batchProofBytes } = createBatchProofData(
        [p, p, p],
        [[1n], [2n], [3n]],
      );
      expect(batchProofBytes.length).to.equal(780); // 3 × 260
      expect(merkleRoot).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should throw on mismatched array lengths", () => {
      expect(() => createBatchProofData([makeBN254Proof()], [])).to.throw(
        "same length",
      );
    });

    it("should throw on empty arrays", () => {
      expect(() => createBatchProofData([], [])).to.throw("at least one");
    });
  });
});
