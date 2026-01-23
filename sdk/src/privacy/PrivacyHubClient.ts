/**
 * @title Cross-Chain Privacy Hub Client
 * @description TypeScript SDK for unified cross-chain privacy operations
 */

import { ethers, Contract, Wallet, Provider, keccak256, toBeHex, getBytes, hexlify } from 'ethers';
import { StealthAddressClient, StealthMetaAddress, StealthAddressResult, StealthScheme } from './StealthAddressClient';
import { RingCTClient, PedersenCommitment, RingMember, CLSAGSignature } from './RingCTClient';
import { NullifierClient, ChainDomain, CHAIN_DOMAINS, CrossDomainNullifier } from './NullifierClient';

// Transfer status enum
export enum TransferStatus {
    NONE = 0,
    PENDING = 1,
    RELAYED = 2,
    COMPLETED = 3,
    FAILED = 4,
    REFUNDED = 5
}

// Private transfer structure
export interface PrivateTransfer {
    transferId: string;
    sourceDomain: ChainDomain;
    targetDomain: ChainDomain;
    commitment: PedersenCommitment;
    nullifier: string;
    stealthAddress: string;
    status: TransferStatus;
    timestamp: number;
}

// Bridge adapter info
export interface BridgeAdapter {
    chainId: number;
    adapterAddress: string;
    name: string;
    isActive: boolean;
    supportedFeatures: string[];
}

// Privacy hub configuration
export interface PrivacyHubConfig {
    hubAddress: string;
    stealthRegistryAddress: string;
    ringCTAddress: string;
    nullifierManagerAddress: string;
}

// Transfer initiation parameters
export interface TransferParams {
    targetChainId: number;
    recipientStealthId: string;
    amount: bigint;
    fee: bigint;
    useRingCT: boolean;
    ringSize?: number;
}

// ABI for CrossChainPrivacyHub
const PRIVACY_HUB_ABI = [
    'function registerBridge(uint256 chainId, address adapter, string name) external',
    'function initiatePrivateTransfer(uint256 targetChainId, address recipient, uint256 amount, bytes32 commitment, bytes32 nullifier, bytes proof) external payable returns (bytes32)',
    'function relayPrivateTransfer(bytes32 transferId, bytes relayProof) external',
    'function completePrivateTransfer(bytes32 transferId, bytes completionProof) external',
    'function refundTransfer(bytes32 transferId) external',
    'function getTransferStatus(bytes32 transferId) external view returns (uint8)',
    'function getTransferDetails(bytes32 transferId) external view returns (tuple(address sender, uint256 sourceChain, uint256 targetChain, bytes32 commitment, bytes32 nullifier, uint8 status, uint256 timestamp))',
    'function isBridgeRegistered(uint256 chainId) external view returns (bool)',
    'function getBridgeAdapter(uint256 chainId) external view returns (address)',
    'function supportedChains() external view returns (uint256[])',
    'event PrivateTransferInitiated(bytes32 indexed transferId, uint256 sourceChain, uint256 targetChain, bytes32 commitment)',
    'event PrivateTransferRelayed(bytes32 indexed transferId, address relayer)',
    'event PrivateTransferCompleted(bytes32 indexed transferId)',
    'event PrivateTransferFailed(bytes32 indexed transferId, string reason)',
    'event PrivateTransferRefunded(bytes32 indexed transferId)'
];

export class PrivacyHubClient {
    private hubContract: Contract;
    private stealthClient: StealthAddressClient;
    private ringCTClient: RingCTClient;
    private nullifierClient: NullifierClient;
    private provider: Provider;
    private signer?: Wallet;
    private config: PrivacyHubConfig;

    constructor(
        config: PrivacyHubConfig,
        provider: Provider,
        signer?: Wallet
    ) {
        this.config = config;
        this.provider = provider;
        this.signer = signer;

        this.hubContract = new Contract(
            config.hubAddress,
            PRIVACY_HUB_ABI,
            signer || provider
        );

        this.stealthClient = new StealthAddressClient(
            config.stealthRegistryAddress,
            provider,
            signer
        );

        this.ringCTClient = new RingCTClient(
            config.ringCTAddress,
            provider,
            signer
        );

        this.nullifierClient = new NullifierClient(
            config.nullifierManagerAddress,
            provider,
            signer
        );
    }

    // =========================================================================
    // UNIFIED PRIVACY OPERATIONS
    // =========================================================================

    /**
     * Perform a complete private cross-chain transfer
     */
    async privateTransfer(params: TransferParams): Promise<{
        transferId: string;
        stealthAddress: StealthAddressResult;
        commitment: PedersenCommitment;
        nullifier: string;
        txHash: string;
    }> {
        if (!this.signer) throw new Error('Signer required');

        // 1. Compute stealth address for recipient
        const stealthResult = await this.stealthClient.computeStealthAddress(params.recipientStealthId);

        // 2. Create commitment for amount
        const commitment = await this.ringCTClient.createCommitment(params.amount);

        // 3. Derive nullifier
        const secret = hexlify(ethers.randomBytes(32));
        const nullifier = NullifierClient.deriveNullifier(
            secret,
            commitment.commitment,
            await this.provider.getNetwork().then(n => Number(n.chainId))
        );

        // 4. Generate ZK proof (simplified - in production use actual ZK circuit)
        const proof = keccak256(ethers.concat([
            getBytes(commitment.commitment),
            getBytes(nullifier),
            getBytes(stealthResult.stealthAddress),
            toBeHex(params.amount, 32)
        ]));

        // 5. Initiate transfer
        const tx = await this.hubContract.initiatePrivateTransfer(
            params.targetChainId,
            stealthResult.stealthAddress,
            params.amount,
            commitment.commitment,
            nullifier,
            proof,
            { value: params.fee }
        );

        const receipt = await tx.wait();

        // Extract transfer ID from event
        const event = receipt.logs.find(
            (log: ethers.Log) => {
                try {
                    const parsed = this.hubContract.interface.parseLog({
                        topics: log.topics as string[],
                        data: log.data
                    });
                    return parsed?.name === 'PrivateTransferInitiated';
                } catch {
                    return false;
                }
            }
        );

        const transferId = event 
            ? this.hubContract.interface.parseLog({
                topics: event.topics as string[],
                data: event.data
            })?.args?.transferId
            : keccak256(ethers.concat([tx.hash, toBeHex(0, 32)]));

        // 6. Announce stealth payment
        await this.stealthClient.announcePayment(
            stealthResult.stealthAddress,
            stealthResult.ephemeralPubKey,
            ethers.AbiCoder.defaultAbiCoder().encode(
                ['bytes32', 'uint256'],
                [transferId, params.targetChainId]
            )
        );

        return {
            transferId,
            stealthAddress: stealthResult,
            commitment,
            nullifier,
            txHash: receipt.hash
        };
    }

    /**
     * Perform a RingCT shielded transfer
     */
    async ringCTTransfer(
        inputCommitments: PedersenCommitment[],
        recipientStealthId: string,
        amount: bigint,
        fee: bigint,
        ring: RingMember[],
        signerIndex: number,
        privateKey: string
    ): Promise<{
        txHash: string;
        outputCommitments: PedersenCommitment[];
        stealthAddress: StealthAddressResult;
    }> {
        if (!this.signer) throw new Error('Signer required');

        // Calculate change
        const totalInput = inputCommitments.reduce((sum, c) => sum + c.amount, 0n);
        const change = totalInput - amount - fee;

        if (change < 0n) {
            throw new Error('Insufficient input amount');
        }

        // Get stealth address for recipient
        const stealthResult = await this.stealthClient.computeStealthAddress(recipientStealthId);

        // Build RingCT transaction
        const ringCTTx = await this.ringCTClient.buildTransfer(
            inputCommitments,
            amount,
            change,
            fee,
            ring,
            signerIndex,
            privateKey
        );

        // Submit transaction
        const txHash = await this.ringCTClient.submitTransaction(
            inputCommitments,
            ringCTTx.outputs,
            fee,
            ring,
            signerIndex,
            privateKey
        );

        return {
            txHash,
            outputCommitments: ringCTTx.outputs,
            stealthAddress: stealthResult
        };
    }

    // =========================================================================
    // CROSS-DOMAIN NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * Transfer nullifier to another domain
     */
    async transferNullifierCrossDomain(
        nullifier: string,
        sourceDomain: ChainDomain,
        targetDomain: ChainDomain
    ): Promise<CrossDomainNullifier> {
        // Register in source domain if not already
        const consumed = await this.nullifierClient.isNullifierConsumed(nullifier, sourceDomain.chainId);
        if (!consumed) {
            await this.nullifierClient.registerNullifier(nullifier, sourceDomain.chainId);
        }

        // Derive cross-domain nullifier
        return await this.nullifierClient.deriveCrossDomainNullifier(
            nullifier,
            sourceDomain.chainId,
            targetDomain.chainId
        );
    }

    /**
     * Verify nullifier hasn't been used in any domain
     */
    async verifyNullifierGloballyUnused(nullifier: string): Promise<{
        unused: boolean;
        usedInDomains: number[];
    }> {
        const domains = Object.values(CHAIN_DOMAINS);
        const usedInDomains: number[] = [];

        await Promise.all(
            domains.map(async (domain) => {
                const registered = await this.nullifierClient.isDomainRegistered(domain.chainId);
                if (registered) {
                    const consumed = await this.nullifierClient.isNullifierConsumed(nullifier, domain.chainId);
                    if (consumed) {
                        usedInDomains.push(domain.chainId);
                    }
                }
            })
        );

        return {
            unused: usedInDomains.length === 0,
            usedInDomains
        };
    }

    // =========================================================================
    // STEALTH ADDRESS OPERATIONS
    // =========================================================================

    /**
     * Setup stealth receiving for a user
     */
    async setupStealthReceiving(scheme: StealthScheme = StealthScheme.SECP256K1): Promise<{
        stealthId: string;
        spendingPrivKey: string;
        viewingPrivKey: string;
        txHash: string;
    }> {
        const keys = StealthAddressClient.generateMetaAddress(scheme);

        const result = await this.stealthClient.registerMetaAddress(
            keys.spendingPubKey,
            keys.viewingPubKey,
            scheme
        );

        return {
            stealthId: result.stealthId,
            spendingPrivKey: keys.spendingPrivKey,
            viewingPrivKey: keys.viewingPrivKey,
            txHash: result.txHash
        };
    }

    /**
     * Scan for incoming stealth payments
     */
    async scanForPayments(
        viewingPrivKey: string,
        spendingPubKey: string,
        fromBlock: number,
        toBlock?: number
    ) {
        return await this.stealthClient.scanAnnouncements(
            viewingPrivKey,
            spendingPubKey,
            fromBlock,
            toBlock
        );
    }

    // =========================================================================
    // TRANSFER STATUS OPERATIONS
    // =========================================================================

    /**
     * Get transfer status
     */
    async getTransferStatus(transferId: string): Promise<TransferStatus> {
        const status = await this.hubContract.getTransferStatus(transferId);
        return status as TransferStatus;
    }

    /**
     * Get full transfer details
     */
    async getTransferDetails(transferId: string): Promise<PrivateTransfer | null> {
        try {
            const details = await this.hubContract.getTransferDetails(transferId);
            
            return {
                transferId,
                sourceDomain: { chainId: Number(details.sourceChain), domainTag: '', name: '' },
                targetDomain: { chainId: Number(details.targetChain), domainTag: '', name: '' },
                commitment: {
                    commitment: details.commitment,
                    amount: 0n, // Hidden
                    blindingFactor: ''
                },
                nullifier: details.nullifier,
                stealthAddress: '',
                status: details.status as TransferStatus,
                timestamp: Number(details.timestamp)
            };
        } catch {
            return null;
        }
    }

    /**
     * Relay a pending transfer
     */
    async relayTransfer(transferId: string, relayProof: string): Promise<string> {
        if (!this.signer) throw new Error('Signer required');

        const tx = await this.hubContract.relayPrivateTransfer(transferId, relayProof);
        const receipt = await tx.wait();
        return receipt.hash;
    }

    /**
     * Complete a relayed transfer
     */
    async completeTransfer(transferId: string, completionProof: string): Promise<string> {
        if (!this.signer) throw new Error('Signer required');

        const tx = await this.hubContract.completePrivateTransfer(transferId, completionProof);
        const receipt = await tx.wait();
        return receipt.hash;
    }

    /**
     * Refund a failed transfer
     */
    async refundTransfer(transferId: string): Promise<string> {
        if (!this.signer) throw new Error('Signer required');

        const tx = await this.hubContract.refundTransfer(transferId);
        const receipt = await tx.wait();
        return receipt.hash;
    }

    // =========================================================================
    // BRIDGE MANAGEMENT
    // =========================================================================

    /**
     * Check if a chain is supported
     */
    async isChainSupported(chainId: number): Promise<boolean> {
        return await this.hubContract.isBridgeRegistered(chainId);
    }

    /**
     * Get supported chains
     */
    async getSupportedChains(): Promise<number[]> {
        const chains = await this.hubContract.supportedChains();
        return chains.map((c: bigint) => Number(c));
    }

    /**
     * Get bridge adapter for a chain
     */
    async getBridgeAdapter(chainId: number): Promise<string> {
        return await this.hubContract.getBridgeAdapter(chainId);
    }

    // =========================================================================
    // EVENT LISTENERS
    // =========================================================================

    /**
     * Listen for transfer events
     */
    onTransferInitiated(
        callback: (transferId: string, sourceChain: number, targetChain: number, commitment: string) => void
    ): () => void {
        const filter = this.hubContract.filters.PrivateTransferInitiated();

        const handler = (transferId: string, sourceChain: bigint, targetChain: bigint, commitment: string) => {
            callback(transferId, Number(sourceChain), Number(targetChain), commitment);
        };

        this.hubContract.on(filter, handler);
        return () => this.hubContract.off(filter, handler);
    }

    onTransferCompleted(
        callback: (transferId: string) => void
    ): () => void {
        const filter = this.hubContract.filters.PrivateTransferCompleted();
        this.hubContract.on(filter, callback);
        return () => this.hubContract.off(filter, callback);
    }

    onTransferFailed(
        callback: (transferId: string, reason: string) => void
    ): () => void {
        const filter = this.hubContract.filters.PrivateTransferFailed();
        this.hubContract.on(filter, callback);
        return () => this.hubContract.off(filter, callback);
    }

    // =========================================================================
    // GETTERS
    // =========================================================================

    get stealth(): StealthAddressClient {
        return this.stealthClient;
    }

    get ringCT(): RingCTClient {
        return this.ringCTClient;
    }

    get nullifier(): NullifierClient {
        return this.nullifierClient;
    }
}

export default PrivacyHubClient;
