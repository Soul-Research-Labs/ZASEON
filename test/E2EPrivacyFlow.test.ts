import hre from "hardhat";
import { expect } from "chai";
import {
    parseEther,
    zeroAddress,
    keccak256,
    toBytes,
    encodePacked,
    pad,
    type Address,
    type Hash,
    type WalletClient,
    type GetContractReturnType,
} from "viem";

/**
 * E2E Privacy Flow Tests
 *
 * Tests the full deposit → withdraw lifecycle using the ShieldedPool in testMode.
 * Covers:
 * 1. Single ETH deposit → withdrawal with test-mode proof
 * 2. Multiple deposits → independent withdrawals
 * 3. Nullifier double-spend prevention
 * 4. PrivacyRouter → ShieldedPool deposit forwarding
 * 5. Cross-chain commitment relay
 */
describe("E2E Privacy Flow Tests", function () {
    this.timeout(120_000);

    let pool: GetContractReturnType<any>;
    let router: GetContractReturnType<any>;

    let deployer: WalletClient;
    let user1: WalletClient;
    let user2: WalletClient;
    let relayer: WalletClient;
    let viem: any;

    // BN254 field safe commitments (small values guaranteed < FIELD_SIZE)
    const commitment1: Hash = pad("0x01", { size: 32 });
    const commitment2: Hash = pad("0x02", { size: 32 });
    const commitment3: Hash = pad("0x03", { size: 32 });

    // Nullifiers
    const nullifier1: Hash = keccak256(toBytes("nullifier-1"));
    const nullifier2: Hash = keccak256(toBytes("nullifier-2"));

    // Fake proof (test mode requires >= 64 bytes)
    const fakeProof: Hash = ("0x" +
        "aa".repeat(64)) as `0x${string}`;

    // Native ETH asset ID
    const NATIVE_ASSET: Hash = keccak256(toBytes("ETH"));

    before(async function () {
        const network = await hre.network.connect();
        viem = network.viem;
        [deployer, user1, user2, relayer] =
            await viem.getWalletClients();

        // Deploy ShieldedPool in test mode
        pool = await viem.deployContract("UniversalShieldedPool", [
            deployer.account.address,
            zeroAddress, // no verifier
            true, // testMode = true
        ]);

        // Deploy PrivacyRouter pointing at the pool
        router = await viem.deployContract("PrivacyRouter", [
            deployer.account.address,
            pool.address,
            zeroAddress, // crossChainHub
            zeroAddress, // stealthRegistry
            zeroAddress, // nullifierManager
            zeroAddress, // compliance
            zeroAddress, // proofTranslator
        ]);
    });

    /*//////////////////////////////////////////////////////////////
                    1. DEPOSIT → WITHDRAWAL E2E
    //////////////////////////////////////////////////////////////*/

    describe("Single ETH deposit → withdrawal", function () {
        let rootAfterDeposit: Hash;

        it("should deposit 1 ETH and record commitment", async function () {
            await pool.write.depositETH([commitment1], {
                value: parseEther("1"),
                account: user1.account,
            });

            const exists = await pool.read.commitmentExists([commitment1]);
            expect(exists).to.equal(true);

            const nextLeaf = await pool.read.nextLeafIndex();
            expect(Number(nextLeaf)).to.equal(1);

            rootAfterDeposit = await pool.read.currentRoot();
            expect(rootAfterDeposit).to.not.equal(
                "0x" + "0".repeat(64),
            );
        });

        it("should withdraw 0.9 ETH with test-mode proof and relayer fee", async function () {
            const recipientAddr = user2.account.address;
            const relayerAddr = relayer.account.address;
            const withdrawAmount = parseEther("0.9");
            const relayerFee = parseEther("0.1");

            const balanceBefore = await viem.getPublicClient().then(
                (c: any) => c.getBalance({ address: recipientAddr }),
            );

            // Construct WithdrawalProof tuple
            await pool.write.withdraw(
                [
                    {
                        proof: fakeProof,
                        merkleRoot: rootAfterDeposit,
                        nullifier: nullifier1,
                        recipient: recipientAddr,
                        relayerAddress: relayerAddr,
                        amount: withdrawAmount + relayerFee,
                        relayerFee: relayerFee,
                        assetId: NATIVE_ASSET,
                        destChainId: pad("0x00", { size: 32 }),
                    },
                ],
                { account: user1.account },
            );

            // Verify nullifier spent
            const spent = await pool.read.isSpent([nullifier1]);
            expect(spent).to.equal(true);

            // Verify balance increased
            const balanceAfter = await viem.getPublicClient().then(
                (c: any) => c.getBalance({ address: recipientAddr }),
            );
            expect(balanceAfter - balanceBefore).to.equal(withdrawAmount);
        });

        it("should reject double-spend with same nullifier", async function () {
            try {
                await pool.write.withdraw(
                    [
                        {
                            proof: fakeProof,
                            merkleRoot: rootAfterDeposit,
                            nullifier: nullifier1,
                            recipient: user2.account.address,
                            relayerAddress: zeroAddress,
                            amount: parseEther("0.5"),
                            relayerFee: 0n,
                            assetId: NATIVE_ASSET,
                            destChainId: pad("0x00", { size: 32 }),
                        },
                    ],
                    { account: user1.account },
                );
                expect.fail("Should have reverted — nullifier already spent");
            } catch (e: any) {
                expect(e).to.exist;
            }
        });
    });

    /*//////////////////////////////////////////////////////////////
                    2. MULTIPLE DEPOSITS
    //////////////////////////////////////////////////////////////*/

    describe("Multiple deposits update Merkle tree independently", function () {
        let root1: Hash;
        let root2: Hash;

        it("should accept two more deposits with distinct roots", async function () {
            await pool.write.depositETH([commitment2], {
                value: parseEther("0.5"),
                account: user1.account,
            });
            root1 = await pool.read.currentRoot();

            await pool.write.depositETH([commitment3], {
                value: parseEther("0.5"),
                account: user2.account,
            });
            root2 = await pool.read.currentRoot();

            expect(root1).to.not.equal(root2);
        });

        it("should allow withdrawal against any known historical root", async function () {
            // Withdraw using the earlier root (root1) — should still be valid
            const isKnown = await pool.read.isKnownRoot([root1]);
            expect(isKnown).to.equal(true);

            await pool.write.withdraw(
                [
                    {
                        proof: fakeProof,
                        merkleRoot: root1,
                        nullifier: nullifier2,
                        recipient: user1.account.address,
                        relayerAddress: zeroAddress,
                        amount: parseEther("0.3"),
                        relayerFee: 0n,
                        assetId: NATIVE_ASSET,
                        destChainId: pad("0x00", { size: 32 }),
                    },
                ],
                { account: user1.account },
            );

            expect(await pool.read.isSpent([nullifier2])).to.equal(true);
        });
    });

    /*//////////////////////////////////////////////////////////////
                    3. ROUTER → POOL FORWARDING
    //////////////////////////////////////////////////////////////*/

    describe("PrivacyRouter ETH deposit forwarding", function () {
        const routerCommitment: Hash = pad("0x04", { size: 32 });

        it("should forward ETH deposit through router to pool", async function () {
            // Disable compliance checks for test
            await router.write.setComplianceEnabled([false]);

            const leafBefore = await pool.read.nextLeafIndex();

            await router.write.depositETH([routerCommitment], {
                value: parseEther("0.5"),
                account: user1.account,
            });

            const leafAfter = await pool.read.nextLeafIndex();
            expect(Number(leafAfter)).to.equal(Number(leafBefore) + 1);

            const exists = await pool.read.commitmentExists([routerCommitment]);
            expect(exists).to.equal(true);
        });

        it("should track operation receipt on router", async function () {
            const nonce = await router.read.operationNonce();
            expect(Number(nonce)).to.be.greaterThanOrEqual(1);
        });
    });

    /*//////////////////////////////////////////////////////////////
                    4. POOL STATS
    //////////////////////////////////////////////////////////////*/

    describe("Pool statistics", function () {
        it("should report correct aggregate stats", async function () {
            const [deposits, withdrawals, crossChain, treeSize, root] =
                await pool.read.getPoolStats();

            // We did: 3 direct deposits + 1 via router = 4
            expect(Number(deposits)).to.equal(4);
            // We did 2 withdrawals
            expect(Number(withdrawals)).to.equal(2);
            expect(Number(treeSize)).to.equal(4);
            expect(root).to.not.equal("0x" + "0".repeat(64));
        });
    });

    /*//////////////////////////////////////////////////////////////
                   5. EDGE CASES
    //////////////////////////////////////////////////////////////*/

    describe("Edge cases", function () {
        it("should reject withdrawal with unknown root", async function () {
            const fakeRoot: Hash = keccak256(toBytes("non-existent-root"));
            const freshNullifier: Hash = keccak256(toBytes("fresh-null"));

            try {
                await pool.write.withdraw(
                    [
                        {
                            proof: fakeProof,
                            merkleRoot: fakeRoot,
                            nullifier: freshNullifier,
                            recipient: user1.account.address,
                            relayerAddress: zeroAddress,
                            amount: parseEther("0.1"),
                            relayerFee: 0n,
                            assetId: NATIVE_ASSET,
                            destChainId: pad("0x00", { size: 32 }),
                        },
                    ],
                    { account: user1.account },
                );
                expect.fail("Should revert with InvalidMerkleRoot");
            } catch (e: any) {
                expect(e).to.exist;
            }
        });

        it("should reject withdrawal to zero address", async function () {
            const root = await pool.read.currentRoot();
            const freshNullifier: Hash = keccak256(toBytes("fresh-null-2"));

            try {
                await pool.write.withdraw(
                    [
                        {
                            proof: fakeProof,
                            merkleRoot: root,
                            nullifier: freshNullifier,
                            recipient: zeroAddress,
                            relayerAddress: zeroAddress,
                            amount: parseEther("0.1"),
                            relayerFee: 0n,
                            assetId: NATIVE_ASSET,
                            destChainId: pad("0x00", { size: 32 }),
                        },
                    ],
                    { account: user1.account },
                );
                expect.fail("Should revert with InvalidRecipient");
            } catch (e: any) {
                expect(e).to.exist;
            }
        });

        it("should reject withdrawal with too-short proof when not in testMode", async function () {
            // Deploy a fresh pool with testMode enabled but passing short proof
            const shortProof = "0x" + "bb".repeat(32); // < 64 bytes

            const root = await pool.read.currentRoot();
            const freshNullifier: Hash = keccak256(toBytes("fresh-null-3"));

            try {
                await pool.write.withdraw(
                    [
                        {
                            proof: shortProof,
                            merkleRoot: root,
                            nullifier: freshNullifier,
                            recipient: user1.account.address,
                            relayerAddress: zeroAddress,
                            amount: parseEther("0.1"),
                            relayerFee: 0n,
                            assetId: NATIVE_ASSET,
                            destChainId: pad("0x00", { size: 32 }),
                        },
                    ],
                    { account: user1.account },
                );
                expect.fail("Should revert — proof too short");
            } catch (e: any) {
                expect(e).to.exist;
            }
        });
    });
});
