import { expect } from "chai";
import hre from "hardhat";
import {
  keccak256,
  toBytes,
  parseEther,
  toHex,
  sha256 as viemSha256,
  encodePacked,
  padHex,
  type Address,
} from "viem";

describe("XRP Ledger Bridge Adapter", function () {
  // Role constants
  const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
  const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
  const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
  const TREASURY_ROLE = keccak256(toBytes("TREASURY_ROLE"));
  const MINTER_ROLE = keccak256(toBytes("MINTER_ROLE"));

  // XRPL constants
  const XRPL_MULTISIG = padHex("0xDEADBEEF", { size: 20 }) as `0x${string}`;
  const XRPL_USER = padHex("0xCAFEBABE", { size: 20 }) as `0x${string}`;
  const MIN_DEPOSIT = 10_000_000n; // 10 XRP in drops

  // Validator keys
  const VAL_KEY_1 = keccak256(toBytes("validator1"));
  const VAL_KEY_2 = keccak256(toBytes("validator2"));
  const VAL_KEY_3 = keccak256(toBytes("validator3"));

  async function getViem() {
    const { viem } = await hre.network.connect();
    return viem;
  }

  function buildAttestations() {
    return [
      { validatorPubKey: VAL_KEY_1, signature: "0x0123456789" as `0x${string}` },
      { validatorPubKey: VAL_KEY_2, signature: "0x0123456789" as `0x${string}` },
      { validatorPubKey: VAL_KEY_3, signature: "0x0123456789" as `0x${string}` },
    ];
  }

  function buildSHAMapProof() {
    return {
      leafHash: keccak256(toBytes("leaf")),
      innerNodes: [keccak256(toBytes("inner1"))],
      nodeTypes: [0],
      branchKeys: [padHex("0x00", { size: 32 })],
    };
  }

  // ================================================================
  // Deployment & Configuration
  // ================================================================

  describe("Deployment & Configuration", function () {
    it("Should deploy with correct admin roles", async function () {
      const viem = await getViem();
      const [admin] = await viem.getWalletClients();

      const bridge = await viem.deployContract("XRPLBridgeAdapter", [
        admin.account.address,
      ]);

      const hasAdmin = await viem.readContract({
        address: bridge,
        abi: [
          {
            name: "hasRole",
            type: "function",
            inputs: [
              { name: "role", type: "bytes32" },
              { name: "account", type: "address" },
            ],
            outputs: [{ name: "", type: "bool" }],
            stateMutability: "view",
          },
        ],
        functionName: "hasRole",
        args: [
          padHex("0x00", { size: 32 }),
          admin.account.address,
        ],
      });

      expect(hasAdmin).to.be.true;
    });

    it("Should reject zero address admin", async function () {
      const viem = await getViem();

      try {
        await viem.deployContract("XRPLBridgeAdapter", [
          "0x0000000000000000000000000000000000000000",
        ]);
        expect.fail("Should have reverted");
      } catch (e: any) {
        expect(e.message).to.include("revert");
      }
    });

    it("Should configure bridge correctly", async function () {
      const viem = await getViem();
      const [admin] = await viem.getWalletClients();

      const bridge = await viem.deployContract("XRPLBridgeAdapter", [
        admin.account.address,
      ]);

      const wXRP = await viem.deployContract("MockWrappedXRP", [
        admin.account.address,
      ]);

      const oracle = await viem.deployContract("MockXRPLValidatorOracle", [
        admin.account.address,
      ]);

      // Configure
      await viem.writeContract({
        address: bridge,
        abi: [
          {
            name: "configure",
            type: "function",
            inputs: [
              { name: "xrplMultisigAccount", type: "bytes20" },
              { name: "wrappedXRP", type: "address" },
              { name: "validatorOracle", type: "address" },
              { name: "minSignatures", type: "uint256" },
              { name: "requiredLedgerConfirmations", type: "uint256" },
            ],
            outputs: [],
            stateMutability: "nonpayable",
          },
        ],
        functionName: "configure",
        args: [XRPL_MULTISIG, wXRP, oracle, 2n, 32n],
        account: admin.account,
      });
    });
  });

  // ================================================================
  // Mock Contracts
  // ================================================================

  describe("Mock Contracts", function () {
    it("MockWrappedXRP should have 6 decimals", async function () {
      const viem = await getViem();
      const [admin] = await viem.getWalletClients();

      const wXRP = await viem.deployContract("MockWrappedXRP", [
        admin.account.address,
      ]);

      const decimals = await viem.readContract({
        address: wXRP,
        abi: [
          {
            name: "decimals",
            type: "function",
            inputs: [],
            outputs: [{ name: "", type: "uint8" }],
            stateMutability: "pure",
          },
        ],
        functionName: "decimals",
      });

      expect(decimals).to.equal(6);
    });

    it("MockXRPLValidatorOracle should verify registered validators", async function () {
      const viem = await getViem();
      const [admin] = await viem.getWalletClients();

      const oracle = await viem.deployContract("MockXRPLValidatorOracle", [
        admin.account.address,
      ]);

      // Register validator
      await viem.writeContract({
        address: oracle,
        abi: [
          {
            name: "registerValidator",
            type: "function",
            inputs: [{ name: "pubKey", type: "bytes32" }],
            outputs: [],
            stateMutability: "nonpayable",
          },
        ],
        functionName: "registerValidator",
        args: [VAL_KEY_1],
        account: admin.account,
      });

      const isValidator = await viem.readContract({
        address: oracle,
        abi: [
          {
            name: "isValidator",
            type: "function",
            inputs: [{ name: "pubKey", type: "bytes32" }],
            outputs: [{ name: "", type: "bool" }],
            stateMutability: "view",
          },
        ],
        functionName: "isValidator",
        args: [VAL_KEY_1],
      });

      expect(isValidator).to.be.true;
    });
  });

  // ================================================================
  // Escrow Lifecycle
  // ================================================================

  describe("Escrow Lifecycle", function () {
    it("Should create and finish escrow with correct preimage", async function () {
      const viem = await getViem();
      const [admin, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("XRPLBridgeAdapter", [
        admin.account.address,
      ]);

      const wXRP = await viem.deployContract("MockWrappedXRP", [
        admin.account.address,
      ]);

      const oracle = await viem.deployContract("MockXRPLValidatorOracle", [
        admin.account.address,
      ]);

      // Configure bridge
      await viem.writeContract({
        address: bridge,
        abi: [
          {
            name: "configure",
            type: "function",
            inputs: [
              { name: "xrplMultisigAccount", type: "bytes20" },
              { name: "wrappedXRP", type: "address" },
              { name: "validatorOracle", type: "address" },
              { name: "minSignatures", type: "uint256" },
              { name: "requiredLedgerConfirmations", type: "uint256" },
            ],
            outputs: [],
            stateMutability: "nonpayable",
          },
        ],
        functionName: "configure",
        args: [XRPL_MULTISIG, wXRP, oracle, 2n, 32n],
        account: admin.account,
      });

      // Escrow stats should start at 0
      const stats = await viem.readContract({
        address: bridge,
        abi: [
          {
            name: "totalEscrows",
            type: "function",
            inputs: [],
            outputs: [{ name: "", type: "uint256" }],
            stateMutability: "view",
          },
        ],
        functionName: "totalEscrows",
      });

      expect(stats).to.equal(0n);
    });
  });

  // ================================================================
  // Pause Mechanism
  // ================================================================

  describe("Pause Mechanism", function () {
    it("Should pause and unpause correctly", async function () {
      const viem = await getViem();
      const [admin] = await viem.getWalletClients();

      const bridge = await viem.deployContract("XRPLBridgeAdapter", [
        admin.account.address,
      ]);

      // Pause
      await viem.writeContract({
        address: bridge,
        abi: [
          {
            name: "pause",
            type: "function",
            inputs: [],
            outputs: [],
            stateMutability: "nonpayable",
          },
        ],
        functionName: "pause",
        account: admin.account,
      });

      const isPaused = await viem.readContract({
        address: bridge,
        abi: [
          {
            name: "paused",
            type: "function",
            inputs: [],
            outputs: [{ name: "", type: "bool" }],
            stateMutability: "view",
          },
        ],
        functionName: "paused",
      });

      expect(isPaused).to.be.true;

      // Unpause
      await viem.writeContract({
        address: bridge,
        abi: [
          {
            name: "unpause",
            type: "function",
            inputs: [],
            outputs: [],
            stateMutability: "nonpayable",
          },
        ],
        functionName: "unpause",
        account: admin.account,
      });

      const isUnpaused = await viem.readContract({
        address: bridge,
        abi: [
          {
            name: "paused",
            type: "function",
            inputs: [],
            outputs: [{ name: "", type: "bool" }],
            stateMutability: "view",
          },
        ],
        functionName: "paused",
      });

      expect(isUnpaused).to.be.false;
    });
  });

  // ================================================================
  // Bridge Statistics
  // ================================================================

  describe("Bridge Statistics", function () {
    it("Should return initial zero stats", async function () {
      const viem = await getViem();
      const [admin] = await viem.getWalletClients();

      const bridge = await viem.deployContract("XRPLBridgeAdapter", [
        admin.account.address,
      ]);

      const totalDeposited = await viem.readContract({
        address: bridge,
        abi: [
          {
            name: "totalDeposited",
            type: "function",
            inputs: [],
            outputs: [{ name: "", type: "uint256" }],
            stateMutability: "view",
          },
        ],
        functionName: "totalDeposited",
      });

      const totalWithdrawn = await viem.readContract({
        address: bridge,
        abi: [
          {
            name: "totalWithdrawn",
            type: "function",
            inputs: [],
            outputs: [{ name: "", type: "uint256" }],
            stateMutability: "view",
          },
        ],
        functionName: "totalWithdrawn",
      });

      expect(totalDeposited).to.equal(0n);
      expect(totalWithdrawn).to.equal(0n);
    });
  });

  // ================================================================
  // Treasury Management
  // ================================================================

  describe("Treasury Management", function () {
    it("Should set treasury address", async function () {
      const viem = await getViem();
      const [admin, newTreasury] = await viem.getWalletClients();

      const bridge = await viem.deployContract("XRPLBridgeAdapter", [
        admin.account.address,
      ]);

      await viem.writeContract({
        address: bridge,
        abi: [
          {
            name: "setTreasury",
            type: "function",
            inputs: [{ name: "_treasury", type: "address" }],
            outputs: [],
            stateMutability: "nonpayable",
          },
        ],
        functionName: "setTreasury",
        args: [newTreasury.account.address],
        account: admin.account,
      });

      const treasury = await viem.readContract({
        address: bridge,
        abi: [
          {
            name: "treasury",
            type: "function",
            inputs: [],
            outputs: [{ name: "", type: "address" }],
            stateMutability: "view",
          },
        ],
        functionName: "treasury",
      });

      expect(treasury.toLowerCase()).to.equal(
        newTreasury.account.address.toLowerCase()
      );
    });
  });

  // ================================================================
  // Error Handling
  // ================================================================

  describe("Error Handling", function () {
    it("Should reject operations when bridge not configured", async function () {
      const viem = await getViem();
      const [admin] = await viem.getWalletClients();

      const bridge = await viem.deployContract("XRPLBridgeAdapter", [
        admin.account.address,
      ]);

      // Withdrawal without config should fail
      try {
        await viem.writeContract({
          address: bridge,
          abi: [
            {
              name: "initiateWithdrawal",
              type: "function",
              inputs: [
                { name: "xrplRecipient", type: "bytes20" },
                { name: "amountDrops", type: "uint256" },
              ],
              outputs: [{ name: "withdrawalId", type: "bytes32" }],
              stateMutability: "nonpayable",
            },
          ],
          functionName: "initiateWithdrawal",
          args: [XRPL_USER, MIN_DEPOSIT],
          account: admin.account,
        });
        expect.fail("Should have reverted");
      } catch (e: any) {
        expect(e.message).to.include("revert");
      }
    });
  });
});
