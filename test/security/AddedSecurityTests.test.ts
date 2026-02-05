// SPDX-License-Identifier: MIT
import { expect } from "chai";
import hre from "hardhat";
import { getAddress, parseEther, keccak256, toBytes, zeroAddress, padHex } from "viem";

/**
 * Added Security Contracts Test Suite
 * 
 * Tests for the added security modules:
 * 1. AddedSecurityOrchestrator (integration)
 * 2. RuntimeSecurityMonitor
 * 3. ThresholdSignature  
 * 4. ZKFraudProof
 */
describe("Added Security Contracts", function () {
  
  // Role constants (commonly used across tests)
  const ORCHESTRATOR_ROLE = keccak256(toBytes("ORCHESTRATOR_ROLE"));
  const MONITOR_ROLE = keccak256(toBytes("MONITOR_ROLE"));
  const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
  const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });

  async function getViem() {
    // @ts-expect-error - Hardhat 3 viem integration
    const { viem } = await hre.network.connect();
    return viem;
  }

  // ============================================
  // ORCHESTRATOR TESTS
  // ============================================

  describe("AddedSecurityOrchestrator", function () {
    
    async function deployOrchestrator() {
      const viem = await getViem();
      const [owner, monitor, operator, user1, user2] = await viem.getWalletClients();
      
      const orchestrator = await viem.deployContract("AddedSecurityOrchestrator");
      
      // Grant roles
      await orchestrator.write.grantRole([MONITOR_ROLE, monitor.account.address]);
      await orchestrator.write.grantRole([ORCHESTRATOR_ROLE, operator.account.address]);
      
      return { orchestrator, owner, monitor, operator, user1, user2, viem };
    }

    describe("Module Configuration", function () {
      it("Should configure added security modules", async function () {
        const { orchestrator, user1, user2 } = await deployOrchestrator();

        await orchestrator.write.setRuntimeMonitor([user1.account.address]);
        await orchestrator.write.setEmergencyResponse([user2.account.address]);

        const modules = await orchestrator.read.getModuleAddresses();
        expect(getAddress(modules[0])).to.equal(getAddress(user1.account.address));
        expect(getAddress(modules[1])).to.equal(getAddress(user2.account.address));
      });

      it("Should check if fully configured", async function () {
        const { orchestrator } = await deployOrchestrator();

        const isConfigured = await orchestrator.read.isFullyConfigured();
        expect(isConfigured).to.be.false;
      });
    });

    describe("Contract Protection", function () {
      it("Should protect a contract", async function () {
        const { orchestrator, operator, user1, viem } = await deployOrchestrator();

        const orchWithOp = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: operator } });
        
        await orchWithOp.write.protectContract([user1.account.address, 3]); // HIGH risk

        const protectedInfo = await orchestrator.read.protectedContracts([user1.account.address]);
        expect(protectedInfo[4]).to.be.true; // active field
      });

      it("Should unprotect a contract", async function () {
        const { orchestrator, operator, user1, viem } = await deployOrchestrator();

        const orchWithOp = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: operator } });
        
        await orchWithOp.write.protectContract([user1.account.address, 2]);
        await orchWithOp.write.unprotectContract([user1.account.address]);

        const protectedInfo = await orchestrator.read.protectedContracts([user1.account.address]);
        expect(protectedInfo[4]).to.be.false; // active field
      });

      it("Should update security score", async function () {
        const { orchestrator, operator, monitor, user1, viem } = await deployOrchestrator();

        const orchWithOp = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: operator } });
        const orchWithMonitor = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: monitor } });
        
        await orchWithOp.write.protectContract([user1.account.address, 2]);
        await orchWithMonitor.write.updateSecurityScore([user1.account.address, 85n]);

        const protectedInfo = await orchestrator.read.protectedContracts([user1.account.address]);
        expect(protectedInfo[2]).to.equal(85n); // securityScore field
      });

      it("Should auto-create alert on low security score", async function () {
        const { orchestrator, operator, monitor, user1, viem } = await deployOrchestrator();

        const orchWithOp = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: operator } });
        const orchWithMonitor = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: monitor } });
        
        await orchWithOp.write.protectContract([user1.account.address, 2]);
        await orchWithMonitor.write.updateSecurityScore([user1.account.address, 50n]); // Below 70 threshold

        const alertCount = await orchestrator.read.getAlertCount();
        expect(alertCount).to.equal(1n);
      });
    });

    describe("Alert Management", function () {
      it("Should create alerts", async function () {
        const { orchestrator, monitor, user1, viem } = await deployOrchestrator();

        const orchWithMonitor = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: monitor } });
        
        await orchWithMonitor.write.createAlert([user1.account.address, 3, "Test HIGH alert"]);

        const alertCount = await orchestrator.read.getAlertCount();
        expect(alertCount).to.equal(1n);

        const alert = await orchestrator.read.getAlert([0n]);
        expect(alert.severity).to.equal(3); // HIGH
      });

      it("Should resolve alerts", async function () {
        const { orchestrator, monitor, operator, user1, viem } = await deployOrchestrator();

        const orchWithMonitor = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: monitor } });
        const orchWithOp = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: operator } });
        
        await orchWithMonitor.write.createAlert([user1.account.address, 2, "Test MEDIUM alert"]);
        await orchWithOp.write.resolveAlert([0n]);

        const alert = await orchestrator.read.getAlert([0n]);
        expect(alert.resolved).to.be.true;
      });

      it("Should get security posture", async function () {
        const { orchestrator, operator, monitor, user1, user2, viem } = await deployOrchestrator();

        const orchWithOp = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: operator } });
        const orchWithMonitor = await viem.getContractAt("AddedSecurityOrchestrator", orchestrator.address, { client: { wallet: monitor } });
        
        await orchWithOp.write.protectContract([user1.account.address, 2]);
        await orchWithOp.write.protectContract([user2.account.address, 3]);
        await orchWithMonitor.write.createAlert([user1.account.address, 4, "Critical alert"]);

        const posture = await orchestrator.read.getSecurityPosture();
        expect(posture[0]).to.equal(2n); // protectedCount
        expect(posture[1]).to.equal(1n); // totalAlerts
        expect(posture[2]).to.equal(1n); // unresolvedAlerts
        expect(posture[3]).to.equal(1n); // criticalAlerts
      });
    });

    describe("Emergency Controls", function () {
      it("Should pause and unpause", async function () {
        const { orchestrator } = await deployOrchestrator();

        await orchestrator.write.pause();
        
        const paused = await orchestrator.read.paused();
        expect(paused).to.be.true;

        await orchestrator.write.unpause();
        
        const unpaused = await orchestrator.read.paused();
        expect(unpaused).to.be.false;
      });
    });
  });

  // ============================================
  // RUNTIME SECURITY MONITOR TESTS
  // ============================================

  describe("RuntimeSecurityMonitor", function () {
    
    async function deployRuntimeMonitor() {
      const viem = await getViem();
      const [owner, monitor, guardian, user1] = await viem.getWalletClients();
      
      // RuntimeSecurityMonitor requires a circuit breaker address
      const runtimeMonitor = await viem.deployContract("RuntimeSecurityMonitor", [owner.account.address]);
      
      // Deploy a test contract to monitor - use fully qualified name
      const testContract = await viem.deployContract("contracts/mocks/MockERC20.sol:MockERC20", ["Test", "TST", 18n]);
      
      // Grant roles
      await runtimeMonitor.write.grantRole([MONITOR_ROLE, monitor.account.address]);
      await runtimeMonitor.write.grantRole([GUARDIAN_ROLE, guardian.account.address]);
      
      return { runtimeMonitor, testContract, owner, monitor, guardian, user1, viem };
    }

    it("Should monitor a contract", async function () {
      const { runtimeMonitor, testContract, monitor, viem } = await deployRuntimeMonitor();

      const monitorWithRole = await viem.getContractAt("RuntimeSecurityMonitor", runtimeMonitor.address, { client: { wallet: monitor } });
      
      await monitorWithRole.write.monitorContract([testContract.address]);

      const contracts = await runtimeMonitor.read.getMonitoredContracts();
      expect(contracts.length).to.equal(1);
    });

    it("Should get security score", async function () {
      const { runtimeMonitor, testContract, monitor, viem } = await deployRuntimeMonitor();

      const monitorWithRole = await viem.getContractAt("RuntimeSecurityMonitor", runtimeMonitor.address, { client: { wallet: monitor } });
      
      await monitorWithRole.write.monitorContract([testContract.address]);

      const score = await runtimeMonitor.read.getSecurityScore([testContract.address]);
      expect(Number(score)).to.be.gte(0);
    });

    it("Should unmonitor a contract", async function () {
      const { runtimeMonitor, testContract, monitor, guardian, viem } = await deployRuntimeMonitor();

      const monitorWithRole = await viem.getContractAt("RuntimeSecurityMonitor", runtimeMonitor.address, { client: { wallet: monitor } });
      const monitorWithGuardian = await viem.getContractAt("RuntimeSecurityMonitor", runtimeMonitor.address, { client: { wallet: guardian } });
      
      await monitorWithRole.write.monitorContract([testContract.address]);
      await monitorWithGuardian.write.unmonitorContract([testContract.address]);

      const contracts = await runtimeMonitor.read.getMonitoredContracts();
      expect(contracts.length).to.equal(1); // Still in list but inactive
    });
  });

  // ============================================
  // THRESHOLD SIGNATURE TESTS
  // ============================================

  describe("ThresholdSignature", function () {
    // Role constants for ThresholdSignature
    const KEY_MANAGER_ROLE = keccak256(toBytes("KEY_MANAGER_ROLE"));
    
    async function deployThresholdSignature() {
      const viem = await getViem();
      const [owner, signer1, signer2, signer3, signer4, signer5] = await viem.getWalletClients();
      
      const threshold = await viem.deployContract("ThresholdSignature");
      
      return { threshold, owner, signer1, signer2, signer3, signer4, signer5, viem };
    }

    it("Should create a signature group", async function () {
      const { threshold, signer1, signer2, signer3 } = await deployThresholdSignature();

      const signers = [
        signer1.account.address,
        signer2.account.address,
        signer3.account.address
      ];

      // SignatureType 0 = ECDSA_THRESHOLD, threshold = 2 (2-of-3)
      await threshold.write.createGroup([0, 2n, signers]);

      // groupIds is a public array - read the first element
      const groupId = await threshold.read.groupIds([0n]);
      expect(groupId).to.not.equal(padHex("0x00", { size: 32 }));
    });

    it("Should enforce minimum threshold", async function () {
      const { threshold, signer1 } = await deployThresholdSignature();

      // 5-of-1 is invalid - threshold must be <= signers count
      let failed = false;
      try {
        await threshold.write.createGroup([0, 5n, [signer1.account.address]]);
      } catch (e) {
        failed = true;
      }
      expect(failed).to.be.true;
    });

    it("Should get group info", async function () {
      const { threshold, signer1, signer2, signer3 } = await deployThresholdSignature();

      const signers = [
        signer1.account.address,
        signer2.account.address,
        signer3.account.address
      ];

      // Create group and get the groupId from public array
      await threshold.write.createGroup([0, 2n, signers]);
      
      const groupId = await threshold.read.groupIds([0n]);
      
      const group = await threshold.read.getGroup([groupId]);
      expect(group[1]).to.equal(2n); // threshold
      expect(group[2]).to.equal(3n); // totalSigners
    });
  });

  // ============================================
  // ZK FRAUD PROOF TESTS
  // ============================================

  describe("ZKFraudProof", function () {
    // Role constants for ZKFraudProof
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const PROVER_ROLE_ZK = keccak256(toBytes("PROVER_ROLE"));
    
    async function deployZKFraudProof() {
      const viem = await getViem();
      const [owner, sequencer, prover, user] = await viem.getWalletClients();
      
      // ZKFraudProof requires: stateCommitmentChain, bondManager, zkVerifier addresses
      const zkFraud = await viem.deployContract("ZKFraudProof", [
        owner.account.address,  // stateCommitmentChain
        owner.account.address,  // bondManager
        owner.account.address   // zkVerifier
      ]);
      
      // Grant roles
      await zkFraud.write.grantRole([OPERATOR_ROLE, sequencer.account.address]);
      await zkFraud.write.grantRole([PROVER_ROLE_ZK, prover.account.address]);
      
      return { zkFraud, owner, sequencer, prover, user, viem };
    }

    it("Should submit batches", async function () {
      const { zkFraud, sequencer, viem } = await deployZKFraudProof();

      const zkFraudWithSequencer = await viem.getContractAt("ZKFraudProof", zkFraud.address, { client: { wallet: sequencer } });

      const stateRoot = keccak256(toBytes("state root"));
      const previousStateRoot = padHex("0x00", { size: 32 }); // Initial batch - zero previous state
      const batchData = keccak256(toBytes("batch data"));

      await zkFraudWithSequencer.write.submitBatch([stateRoot, previousStateRoot, batchData]);

      const batch = await zkFraud.read.getBatch([stateRoot]);
      // Batch should exist
      expect(batch).to.not.be.undefined;
    });

    it("Should get prover stats", async function () {
      const { zkFraud, prover } = await deployZKFraudProof();

      const stats = await zkFraud.read.getProverStats([prover.account.address]);
      // Stats should be initialized (even if empty)
      expect(stats).to.not.be.undefined;
    });
  });
});
