/**
 * Soul SDK - Bridge Adapters Module
 *
 * Provides TypeScript interfaces and implementations for supported L2 bridge adapters.
 * All adapters target EVM-compatible L2 networks.
 */

export * as ArbitrumBridge from "./arbitrum";
export * as BaseBridge from "./base";
export * as EthereumBridge from "./ethereum";
export * as HyperlaneBridge from "./hyperlane";
export * as L2Adapters from "./l2-adapters";
export * as LayerZeroBridge from "./layerzero";
export * as LineaBridge from "./linea";
export * from "./optimism";
export * as PolygonZkEvmBridge from "./polygon-zkevm";
export * as ScrollBridge from "./scroll";
export * as ZkSyncBridge from "./zksync";

import {
    type PublicClient,
    type WalletClient,
} from "viem";

// ============================================
// Types & Interfaces
// ============================================

export interface BridgeTransferParams {
  targetChainId: number;
  recipient: string;
  amount: bigint;
  proof?: Uint8Array;
  data?: string;
}

export interface BridgeTransferResult {
  transferId: string;
  txHash: string;
  estimatedArrival: number;
  fees: BridgeFees;
}

export interface BridgeFees {
  protocolFee: bigint;
  relayerFee: bigint;
  gasFee: bigint;
  total: bigint;
}

export interface BridgeStatus {
  state: "pending" | "relaying" | "confirming" | "completed" | "failed" | "refunded";
  sourceChainId: number;
  targetChainId: number;
  sourceTx?: string;
  targetTx?: string;
  confirmations: number;
  requiredConfirmations: number;
  estimatedCompletion?: number;
  error?: string;
}

export interface BridgeAdapterConfig {
  name: string;
  chainId: number;
  nativeToken: string;
  finality: number;
  maxAmount: bigint;
  minAmount: bigint;
}

// ============================================
// Base Bridge Adapter
// ============================================

export abstract class BaseBridgeAdapter {
  protected publicClient: PublicClient;
  protected walletClient?: WalletClient;

  constructor(
    public readonly config: BridgeAdapterConfig,
    publicClient: PublicClient,
    walletClient?: WalletClient
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
  }

  abstract bridgeTransfer(params: BridgeTransferParams): Promise<BridgeTransferResult>;
  abstract completeBridge(transferId: string, proof: Uint8Array): Promise<string>;
  abstract getStatus(transferId: string): Promise<BridgeStatus>;
  abstract estimateFees(amount: bigint, targetChainId: number): Promise<BridgeFees>;

  validateAmount(amount: bigint): void {
    if (amount < this.config.minAmount) {
      throw new Error("Amount below minimum");
    }
    if (amount > this.config.maxAmount) {
      throw new Error("Amount exceeds maximum");
    }
  }
}

// ============================================
// Supported Chains
// ============================================

export type SupportedChain =
  | "arbitrum"
  | "base"
  | "ethereum"
  | "linea"
  | "optimism"
  | "polygon-zkevm"
  | "scroll"
  | "zksync";

// ============================================
// Bridge Factory
// ============================================

export interface BridgeAddresses {
  [key: string]: string;
}

export class BridgeFactory {
  static createAdapter(
    chain: SupportedChain,
    publicClient: PublicClient,
    walletClient?: WalletClient,
    _addresses?: BridgeAddresses,
  ): BaseBridgeAdapter {
    throw new Error(
      `Bridge adapter for chain "${chain}" is not yet implemented. ` +
      `Available chains: arbitrum, base, ethereum, linea, optimism, polygon-zkevm, scroll, zksync`
    );
  }
}
