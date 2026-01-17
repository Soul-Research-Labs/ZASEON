const { expect } = require("chai");
const { ethers } = require("hardhat");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

/**
 * Multi-Chain Integration Tests
 * Tests proof translation and verification across different chain configurations
 */
describe("Multi-Chain Integration Tests", function () {
  this.timeout(300000); // 5 minutes for proof generation

  let owner, relayer, challenger, user1;
  let poseidon;

  // Contracts
  let crossChainProofHub;
  let crossChainProofVerifier;
  let proofAggregator;
  let stateCommitmentVerifier;
  let verifierHub;

  // Test data
  const CHAIN_IDS = {
    ETHEREUM: 1,
    POLYGON: 137,
    ARBITRUM: 42161,
    OPTIMISM: 10,
    BSC: 56,
  };

  before(async function () {
    [owner, relayer, challenger, user1] = await ethers.getSigners();
    poseidon = await buildPoseidon();
  });

  /*//////////////////////////////////////////////////////////////
                          DEPLOYMENT
  //////////////////////////////////////////////////////////////*/

  describe("Contract Deployment", function () {
    it("should deploy CrossChainProofHubV3", async function () {
      const CrossChainProofHubV3 = await ethers.getContractFactory(
        "CrossChainProofHubV3"
      );
      crossChainProofHub = await CrossChainProofHubV3.deploy();
      await crossChainProofHub.waitForDeployment();

      expect(await crossChainProofHub.getAddress()).to.be.properAddress;
    });

    it("should deploy CrossChainProofVerifier", async function () {
      const CrossChainProofVerifier = await ethers.getContractFactory(
        "CrossChainProofVerifier"
      );
      crossChainProofVerifier = await CrossChainProofVerifier.deploy();
      await crossChainProofVerifier.waitForDeployment();

      expect(await crossChainProofVerifier.getAddress()).to.be.properAddress;
    });

    it("should deploy ProofAggregator", async function () {
      const ProofAggregator = await ethers.getContractFactory(
        "ProofAggregator"
      );
      proofAggregator = await ProofAggregator.deploy(
        await crossChainProofVerifier.getAddress()
      );
      await proofAggregator.waitForDeployment();

      expect(await proofAggregator.getAddress()).to.be.properAddress;
    });

    it("should deploy StateCommitmentVerifier", async function () {
      const StateCommitmentVerifier = await ethers.getContractFactory(
        "StateCommitmentVerifier"
      );
      stateCommitmentVerifier = await StateCommitmentVerifier.deploy();
      await stateCommitmentVerifier.waitForDeployment();

      expect(await stateCommitmentVerifier.getAddress()).to.be.properAddress;
    });

    it("should deploy VerifierHub", async function () {
      const VerifierHub = await ethers.getContractFactory("VerifierHub");
      verifierHub = await VerifierHub.deploy();
      await verifierHub.waitForDeployment();

      expect(await verifierHub.getAddress()).to.be.properAddress;
    });
  });

  /*//////////////////////////////////////////////////////////////
                      CHAIN CONFIGURATION
  //////////////////////////////////////////////////////////////*/

  describe("Multi-Chain Configuration", function () {
    it("should configure supported chains on ProofHub", async function () {
      // Add all supported chains
      for (const [name, chainId] of Object.entries(CHAIN_IDS)) {
        await crossChainProofHub.addSupportedChain(chainId);
        expect(await crossChainProofHub.supportedChains(chainId)).to.be.true;
      }
    });

    it("should register verifiers for different proof types", async function () {
      const GROTH16_BN254 = ethers.keccak256(
        ethers.toUtf8Bytes("GROTH16_BN254")
      );
      const STATE_COMMITMENT = ethers.keccak256(
        ethers.toUtf8Bytes("STATE_COMMITMENT")
      );
      const CROSS_CHAIN = ethers.keccak256(ethers.toUtf8Bytes("CROSS_CHAIN"));

      await crossChainProofHub.setVerifier(
        GROTH16_BN254,
        await stateCommitmentVerifier.getAddress()
      );
      await crossChainProofHub.setVerifier(
        STATE_COMMITMENT,
        await stateCommitmentVerifier.getAddress()
      );
      await crossChainProofHub.setVerifier(
        CROSS_CHAIN,
        await crossChainProofVerifier.getAddress()
      );

      expect(await crossChainProofHub.verifiers(GROTH16_BN254)).to.not.equal(
        ethers.ZeroAddress
      );
    });

    it("should configure VerifierHub with multiple verifiers", async function () {
      // VerifierHub uses CircuitType enum (0-4)
      // 0=StateCommitment, 1=StateTransfer, 2=MerkleProof, 3=CrossChainProof, 4=ComplianceProof
      await verifierHub.registerVerifier(
        0,
        await stateCommitmentVerifier.getAddress()
      );
      await verifierHub.registerVerifier(
        3,
        await crossChainProofVerifier.getAddress()
      );

      const stateVerifierInfo = await verifierHub.verifiers(0);
      expect(stateVerifierInfo.verifier).to.equal(
        await stateCommitmentVerifier.getAddress()
      );
    });
  });

  /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN PROOF RELAY
  //////////////////////////////////////////////////////////////*/

  describe("Cross-Chain Proof Relay", function () {
    let testProofHash, testInputsHash, testCommitment;

    beforeEach(function () {
      testProofHash = ethers.keccak256(
        ethers.toUtf8Bytes("test-proof-" + Date.now())
      );
      testInputsHash = ethers.keccak256(
        ethers.toUtf8Bytes("test-inputs-" + Date.now())
      );
      testCommitment = ethers.keccak256(
        ethers.toUtf8Bytes("test-commitment-" + Date.now())
      );
    });

    it("should submit proof from Ethereum to Polygon", async function () {
      const sourceChain = CHAIN_IDS.ETHEREUM;
      const destChain = CHAIN_IDS.POLYGON;

      // Relayer deposits stake first
      await crossChainProofHub
        .connect(relayer)
        .depositStake({ value: ethers.parseEther("0.2") });

      const mockProof = ethers.randomBytes(256);
      const mockInputs = ethers.randomBytes(64);

      const tx = await crossChainProofHub
        .connect(relayer)
        .submitProof(
          mockProof,
          mockInputs,
          testCommitment,
          sourceChain,
          destChain,
          { value: ethers.parseEther("0.001") }
        );

      const receipt = await tx.wait();
      const event = receipt.logs.find((log) => {
        try {
          return (
            crossChainProofHub.interface.parseLog(log)?.name ===
            "ProofSubmitted"
          );
        } catch {
          return false;
        }
      });

      expect(event).to.not.be.undefined;
    });

    it("should submit proof from Arbitrum to BSC", async function () {
      const sourceChain = CHAIN_IDS.ARBITRUM;
      const destChain = CHAIN_IDS.BSC;

      const mockProof = ethers.randomBytes(256);
      const mockInputs = ethers.randomBytes(64);

      const tx = await crossChainProofHub
        .connect(relayer)
        .submitProof(
          mockProof,
          mockInputs,
          testCommitment,
          sourceChain,
          destChain,
          { value: ethers.parseEther("0.001") }
        );

      await expect(tx).to.emit(crossChainProofHub, "ProofSubmitted");
    });

    it("should reject proof to unsupported chain", async function () {
      const sourceChain = CHAIN_IDS.ETHEREUM;
      const unsupportedChain = 99999;

      const mockProof = ethers.randomBytes(256);
      const mockInputs = ethers.randomBytes(64);

      await expect(
        crossChainProofHub
          .connect(relayer)
          .submitProof(
            mockProof,
            mockInputs,
            testCommitment,
            sourceChain,
            unsupportedChain,
            { value: ethers.parseEther("0.001") }
          )
      ).to.be.revertedWithCustomError(crossChainProofHub, "UnsupportedChain");
    });
  });

  /*//////////////////////////////////////////////////////////////
                      BATCH PROOF SUBMISSION
  //////////////////////////////////////////////////////////////*/

  describe("Batch Proof Submission", function () {
    it("should submit batch of cross-chain proofs", async function () {
      const batchSize = 5;
      const proofs = [];

      for (let i = 0; i < batchSize; i++) {
        proofs.push({
          proofHash: ethers.keccak256(ethers.toUtf8Bytes(`batch-proof-${i}`)),
          publicInputsHash: ethers.keccak256(
            ethers.toUtf8Bytes(`batch-inputs-${i}`)
          ),
          commitment: ethers.keccak256(
            ethers.toUtf8Bytes(`batch-commitment-${i}`)
          ),
          sourceChainId: CHAIN_IDS.ETHEREUM,
          destChainId: CHAIN_IDS.POLYGON,
        });
      }

      // Compute merkle root
      const leaves = proofs.map((p) =>
        ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes32", "bytes32", "bytes32", "uint64", "uint64"],
            [
              p.proofHash,
              p.publicInputsHash,
              p.commitment,
              p.sourceChainId,
              p.destChainId,
            ]
          )
        )
      );
      const merkleRoot = computeMerkleRoot(leaves);

      const tx = await crossChainProofHub.connect(relayer).submitBatch(
        proofs,
        merkleRoot,
        { value: ethers.parseEther("0.005") } // 0.001 * 5
      );

      await expect(tx).to.emit(crossChainProofHub, "BatchSubmitted");
    });

    it("should reject batch exceeding maximum size", async function () {
      const proofs = [];
      for (let i = 0; i < 150; i++) {
        proofs.push({
          proofHash: ethers.keccak256(ethers.toUtf8Bytes(`large-batch-${i}`)),
          publicInputsHash: ethers.keccak256(
            ethers.toUtf8Bytes(`large-inputs-${i}`)
          ),
          commitment: ethers.keccak256(
            ethers.toUtf8Bytes(`large-commitment-${i}`)
          ),
          sourceChainId: CHAIN_IDS.ETHEREUM,
          destChainId: CHAIN_IDS.POLYGON,
        });
      }

      const merkleRoot = ethers.keccak256(
        ethers.toUtf8Bytes("large-batch-root")
      );

      await expect(
        crossChainProofHub
          .connect(relayer)
          .submitBatch(proofs, merkleRoot, { value: ethers.parseEther("1") })
      ).to.be.revertedWithCustomError(crossChainProofHub, "BatchTooLarge");
    });
  });

  /*//////////////////////////////////////////////////////////////
                      PROOF AGGREGATION
  //////////////////////////////////////////////////////////////*/

  describe("Proof Aggregation", function () {
    let proofHashes;

    beforeEach(async function () {
      // Register some proofs
      proofHashes = [];
      for (let i = 0; i < 4; i++) {
        const hash = ethers.keccak256(
          ethers.toUtf8Bytes(`agg-proof-${i}-${Date.now()}`)
        );
        const inputsHash = ethers.keccak256(
          ethers.toUtf8Bytes(`agg-inputs-${i}`)
        );

        await proofAggregator.registerProof(
          hash,
          inputsHash,
          CHAIN_IDS.ETHEREUM
        );
        proofHashes.push(hash);
      }
    });

    it("should create merkle batch from registered proofs", async function () {
      const tx = await proofAggregator.createMerkleBatch(proofHashes);
      const receipt = await tx.wait();

      const event = receipt.logs.find((log) => {
        try {
          return (
            proofAggregator.interface.parseLog(log)?.name === "BatchCreated"
          );
        } catch {
          return false;
        }
      });

      expect(event).to.not.be.undefined;
      const parsed = proofAggregator.interface.parseLog(event);
      expect(parsed.args.proofCount).to.equal(proofHashes.length);
    });

    it("should estimate gas savings for batch aggregation", async function () {
      const numProofs = 10;
      const [individualGas, batchedGas, savings, savingsPercent] =
        await proofAggregator.estimateGasSavings(numProofs);

      expect(savings).to.be.gt(0);
      expect(savingsPercent).to.be.gt(50); // Expect >50% savings
    });

    it("should link proofs to batch after creation", async function () {
      await proofAggregator.createMerkleBatch(proofHashes);

      for (const hash of proofHashes) {
        const batchId = await proofAggregator.proofToBatch(hash);
        expect(batchId).to.not.equal(ethers.ZeroHash);
      }
    });
  });

  /*//////////////////////////////////////////////////////////////
                      CHALLENGE MECHANISM
  //////////////////////////////////////////////////////////////*/

  describe("Cross-Chain Challenge Mechanism", function () {
    let proofId;

    beforeEach(async function () {
      const mockProof = ethers.randomBytes(256);
      const mockInputs = ethers.randomBytes(64);
      const commitment = ethers.keccak256(
        ethers.toUtf8Bytes("challenge-test-" + Date.now())
      );

      const tx = await crossChainProofHub
        .connect(relayer)
        .submitProof(
          mockProof,
          mockInputs,
          commitment,
          CHAIN_IDS.ETHEREUM,
          CHAIN_IDS.POLYGON,
          { value: ethers.parseEther("0.001") }
        );

      const receipt = await tx.wait();
      const event = receipt.logs.find((log) => {
        try {
          return (
            crossChainProofHub.interface.parseLog(log)?.name ===
            "ProofSubmitted"
          );
        } catch {
          return false;
        }
      });
      proofId = crossChainProofHub.interface.parseLog(event).args.proofId;
    });

    it("should allow challenging proof during challenge period", async function () {
      await crossChainProofHub
        .connect(challenger)
        .challengeProof(proofId, "Invalid cross-chain state transition", {
          value: ethers.parseEther("0.05"),
        });

      const challenge = await crossChainProofHub.challenges(proofId);
      expect(challenge.challenger).to.equal(challenger.address);
    });

    it("should update proof status to Challenged", async function () {
      await crossChainProofHub
        .connect(challenger)
        .challengeProof(proofId, "Merkle proof mismatch", {
          value: ethers.parseEther("0.05"),
        });

      const proof = await crossChainProofHub.proofs(proofId);
      expect(proof.status).to.equal(2); // Challenged
    });
  });

  /*//////////////////////////////////////////////////////////////
                    VERIFIER HUB ROUTING
  //////////////////////////////////////////////////////////////*/

  describe("VerifierHub Multi-Chain Routing", function () {
    it("should route proof to correct verifier based on type", async function () {
      // CircuitType.StateCommitment = 0
      const verifierInfo = await verifierHub.verifiers(0);
      expect(verifierInfo.verifier).to.equal(
        await stateCommitmentVerifier.getAddress()
      );
    });

    it("should support multiple verifier registrations", async function () {
      // CircuitType.ComplianceProof = 4
      await verifierHub.registerVerifier(
        4,
        await crossChainProofVerifier.getAddress()
      );

      const verifierInfo = await verifierHub.verifiers(4);
      expect(verifierInfo.verifier).to.equal(
        await crossChainProofVerifier.getAddress()
      );
    });
  });

  /*//////////////////////////////////////////////////////////////
                        GAS BENCHMARKS
  //////////////////////////////////////////////////////////////*/

  describe("Multi-Chain Gas Benchmarks", function () {
    it("should benchmark single proof submission gas", async function () {
      const mockProof = ethers.randomBytes(256);
      const mockInputs = ethers.randomBytes(64);
      const commitment = ethers.keccak256(
        ethers.toUtf8Bytes("gas-test-single")
      );

      const tx = await crossChainProofHub
        .connect(relayer)
        .submitProof(
          mockProof,
          mockInputs,
          commitment,
          CHAIN_IDS.ETHEREUM,
          CHAIN_IDS.POLYGON,
          { value: ethers.parseEther("0.001") }
        );

      const receipt = await tx.wait();
      console.log(`    Single proof submission gas: ${receipt.gasUsed}`);
      expect(receipt.gasUsed).to.be.lt(500000);
    });

    it("should benchmark batch proof submission gas", async function () {
      const batchSize = 10;
      const proofs = [];

      for (let i = 0; i < batchSize; i++) {
        proofs.push({
          proofHash: ethers.keccak256(ethers.toUtf8Bytes(`gas-batch-${i}`)),
          publicInputsHash: ethers.keccak256(
            ethers.toUtf8Bytes(`gas-inputs-${i}`)
          ),
          commitment: ethers.keccak256(
            ethers.toUtf8Bytes(`gas-commitment-${i}`)
          ),
          sourceChainId: CHAIN_IDS.ETHEREUM,
          destChainId: CHAIN_IDS.ARBITRUM,
        });
      }

      const merkleRoot = ethers.keccak256(ethers.toUtf8Bytes("gas-batch-root"));

      const tx = await crossChainProofHub
        .connect(relayer)
        .submitBatch(proofs, merkleRoot, { value: ethers.parseEther("0.01") });

      const receipt = await tx.wait();
      const gasPerProof = receipt.gasUsed / BigInt(batchSize);

      console.log(`    Batch submission total gas: ${receipt.gasUsed}`);
      console.log(`    Gas per proof in batch: ${gasPerProof}`);

      // Gas per proof in batch should be lower than individual submission (~200k)
      expect(gasPerProof).to.be.lt(200000); // Cheaper per proof than individual
    });

    it("should benchmark proof aggregation gas", async function () {
      const numProofs = 8;
      const hashes = [];

      for (let i = 0; i < numProofs; i++) {
        const hash = ethers.keccak256(
          ethers.toUtf8Bytes(`gas-agg-${i}-${Date.now()}`)
        );
        await proofAggregator.registerProof(
          hash,
          ethers.keccak256(ethers.toUtf8Bytes(`gas-agg-inputs-${i}`)),
          CHAIN_IDS.ETHEREUM
        );
        hashes.push(hash);
      }

      const tx = await proofAggregator.createMerkleBatch(hashes);
      const receipt = await tx.wait();

      console.log(
        `    Merkle batch creation gas (${numProofs} proofs): ${receipt.gasUsed}`
      );
      expect(receipt.gasUsed).to.be.lt(600000); // Reasonable gas for 8 proof batch
    });
  });

  /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  function computeMerkleRoot(leaves) {
    if (leaves.length === 0) return ethers.ZeroHash;
    if (leaves.length === 1) return leaves[0];

    const nextLevel = [];
    for (let i = 0; i < leaves.length; i += 2) {
      const left = leaves[i];
      const right = leaves[i + 1] || left;
      const combined =
        left < right
          ? ethers.keccak256(ethers.concat([left, right]))
          : ethers.keccak256(ethers.concat([right, left]));
      nextLevel.push(combined);
    }

    return computeMerkleRoot(nextLevel);
  }
});
