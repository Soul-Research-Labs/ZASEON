import { expect } from "chai";
import { keccak256, concat, toHex, Hex, getAddress, slice } from "viem";
import {
  StealthAddressClient,
  StealthScheme,
} from "../src/privacy/StealthAddressClient";

describe("StealthAddressClient", () => {
  const MOCK_ADDRESS = ("0x" + "ab".repeat(20)) as Hex;

  /**
   * Create a client with stubbed public/wallet clients.
   * registerMetaAddress / announcePayment stubs return a fake tx hash.
   */
  const makeClient = (opts?: {
    withWallet?: boolean;
    readStubs?: Record<string, (...args: any[]) => any>;
  }) => {
    const readStubs = opts?.readStubs ?? {};
    const publicClient = {
      getLogs: async () => [],
    } as any;

    const walletClient = opts?.withWallet
      ? { writeContract: async () => "0xdeadbeef" as Hex }
      : undefined;

    return new StealthAddressClient(
      MOCK_ADDRESS,
      publicClient as any,
      walletClient as any,
    );
  };

  // ================================================================
  // Static Helpers
  // ================================================================

  describe("generateMetaAddress()", () => {
    it("should return spending and viewing keypairs", () => {
      const result = StealthAddressClient.generateMetaAddress();
      expect(result.spendingPrivKey).to.match(/^0x[0-9a-f]{64}$/i);
      expect(result.viewingPrivKey).to.match(/^0x[0-9a-f]{64}$/i);
      expect(result.spendingPubKey).to.match(/^0x/);
      expect(result.viewingPubKey).to.match(/^0x/);
    });

    it("should return different keys each time", () => {
      const a = StealthAddressClient.generateMetaAddress();
      const b = StealthAddressClient.generateMetaAddress();
      expect(a.spendingPrivKey).to.not.equal(b.spendingPrivKey);
      expect(a.viewingPrivKey).to.not.equal(b.viewingPrivKey);
    });

    it("should accept scheme parameter", () => {
      const result = StealthAddressClient.generateMetaAddress(
        StealthScheme.ED25519,
      );
      expect(result.spendingPrivKey).to.match(/^0x/);
    });
  });

  describe("computeStealthId()", () => {
    it("should return keccak256 of concatenated keys", () => {
      const spending = "0xaabb" as Hex;
      const viewing = "0xccdd" as Hex;
      const expected = keccak256(concat([spending, viewing]));
      const result = StealthAddressClient.computeStealthId(spending, viewing);
      expect(result).to.equal(expected);
    });

    it("should produce different IDs for different keys", () => {
      const id1 = StealthAddressClient.computeStealthId(
        "0x01" as Hex,
        "0x02" as Hex,
      );
      const id2 = StealthAddressClient.computeStealthId(
        "0x03" as Hex,
        "0x04" as Hex,
      );
      expect(id1).to.not.equal(id2);
    });

    it("should be deterministic", () => {
      const a = StealthAddressClient.computeStealthId(
        "0xaa" as Hex,
        "0xbb" as Hex,
      );
      const b = StealthAddressClient.computeStealthId(
        "0xaa" as Hex,
        "0xbb" as Hex,
      );
      expect(a).to.equal(b);
    });
  });

  describe("deriveStealthPrivateKey()", () => {
    it("should derive a valid private key", () => {
      const keys = StealthAddressClient.generateMetaAddress();
      const ephemeralPriv = toHex(new Uint8Array(32).fill(0x42)) as Hex;
      const result = StealthAddressClient.deriveStealthPrivateKey(
        keys.spendingPrivKey,
        keys.viewingPrivKey,
        ("0x04" + "aa".repeat(64)) as Hex, // mock ephemeral pub key
      );
      expect(result).to.match(/^0x[0-9a-f]{64}$/i);
    });

    it("should be deterministic for same inputs", () => {
      const spending = ("0x" + "11".repeat(32)) as Hex;
      const viewing = ("0x" + "22".repeat(32)) as Hex;
      const ephemeral = ("0x" + "33".repeat(33)) as Hex;

      const a = StealthAddressClient.deriveStealthPrivateKey(
        spending,
        viewing,
        ephemeral,
      );
      const b = StealthAddressClient.deriveStealthPrivateKey(
        spending,
        viewing,
        ephemeral,
      );
      expect(a).to.equal(b);
    });

    it("should produce different keys for different inputs", () => {
      const spending = ("0x" + "11".repeat(32)) as Hex;
      const viewing = ("0x" + "22".repeat(32)) as Hex;
      const ephA = ("0x" + "aa".repeat(33)) as Hex;
      const ephB = ("0x" + "bb".repeat(33)) as Hex;

      const keyA = StealthAddressClient.deriveStealthPrivateKey(
        spending,
        viewing,
        ephA,
      );
      const keyB = StealthAddressClient.deriveStealthPrivateKey(
        spending,
        viewing,
        ephB,
      );
      expect(keyA).to.not.equal(keyB);
    });
  });

  // ================================================================
  // Instance Methods — Validation
  // ================================================================

  describe("registerMetaAddress()", () => {
    it("should throw without wallet client", async () => {
      const client = makeClient({ withWallet: false });
      try {
        await client.registerMetaAddress(
          ("0x" + "aa".repeat(33)) as Hex,
          ("0x" + "bb".repeat(33)) as Hex,
        );
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });
  });

  describe("announcePayment()", () => {
    it("should throw without wallet client", async () => {
      const client = makeClient({ withWallet: false });
      try {
        await client.announcePayment(
          "0x" + "cc".repeat(20),
          ("0x" + "dd".repeat(33)) as Hex,
        );
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });
  });

  // ================================================================
  // Stealth Scheme Enum
  // ================================================================

  describe("StealthScheme enum", () => {
    it("should have expected values", () => {
      expect(StealthScheme.SECP256K1).to.equal(0);
      expect(StealthScheme.ED25519).to.equal(1);
      expect(StealthScheme.BLS12_381).to.equal(2);
      expect(StealthScheme.BABYJUBJUB).to.equal(3);
    });
  });
});
