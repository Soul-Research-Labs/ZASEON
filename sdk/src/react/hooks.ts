/**
 * @module @soul/sdk/react
 * @description React hooks for Soul Protocol integration.
 * @dev These hooks provide ergonomic React bindings around the core SDK client.
 *
 * Usage:
 * ```tsx
 * import { useSoulPrivacy, useSoulBridge, useSoulProver } from '@soul/sdk/react';
 *
 * function MyComponent() {
 *   const { shield, unshield, isShielding } = useSoulPrivacy(config);
 *   const { bridge, status, isBridging } = useSoulBridge(config);
 *   const { prove, isProving } = useSoulProver(config);
 * }
 * ```
 */

import type { ReactNode } from "react";

// ─── Types ──────────────────────────────────────────────────

/** Configuration for Soul SDK hooks */
export interface SoulConfig {
  /** RPC URL or viem transport */
  rpcUrl: string;
  /** Chain ID */
  chainId: number;
  /** Private key or signer (optional, for write operations) */
  signer?: unknown;
  /** Enable development mode (placeholder proofs) */
  devMode?: boolean;
}

/** Hook state for async operations */
export interface AsyncState<T = unknown> {
  data: T | null;
  error: Error | null;
  isLoading: boolean;
}

/** Privacy hook return type */
export interface UseSoulPrivacyReturn {
  /** Shield (deposit) assets into the shielded pool */
  shield: (params: {
    asset: string;
    amount: bigint;
    commitment: string;
  }) => Promise<string>;
  /** Unshield (withdraw) assets from the shielded pool */
  unshield: (params: {
    nullifier: string;
    proof: Uint8Array;
    recipient: string;
    amount: bigint;
  }) => Promise<string>;
  /** Whether a shield operation is in progress */
  isShielding: boolean;
  /** Whether an unshield operation is in progress */
  isUnshielding: boolean;
  /** Last error */
  error: Error | null;
}

/** Bridge hook return type */
export interface UseSoulBridgeReturn {
  /** Bridge assets cross-chain */
  bridge: (params: {
    destChainId: number;
    asset: string;
    amount: bigint;
    proof?: Uint8Array;
  }) => Promise<string>;
  /** Check bridge transfer status */
  status: (txHash: string) => Promise<string>;
  /** Whether a bridge operation is in progress */
  isBridging: boolean;
  /** Last error */
  error: Error | null;
}

/** Prover hook return type */
export interface UseSoulProverReturn {
  /** Generate a ZK proof */
  prove: (
    circuit: string,
    inputs: Record<string, unknown>,
  ) => Promise<Uint8Array>;
  /** Whether proof generation is in progress */
  isProving: boolean;
  /** Last error */
  error: Error | null;
}

// ─── Hooks ──────────────────────────────────────────────────

/**
 * Hook for interacting with Soul Protocol's shielded pool.
 * Provides shield (deposit) and unshield (withdraw) operations.
 *
 * @param config - Soul SDK configuration
 * @returns Privacy operation methods and loading states
 */
export function useSoulPrivacy(_config: SoulConfig): UseSoulPrivacyReturn {
  // TODO: Implement using React useState/useCallback with SoulSDK privacy client
  return {
    shield: async () => {
      throw new Error(
        "useSoulPrivacy: not yet implemented — install @soul/sdk and configure provider",
      );
    },
    unshield: async () => {
      throw new Error("useSoulPrivacy: not yet implemented");
    },
    isShielding: false,
    isUnshielding: false,
    error: null,
  };
}

/**
 * Hook for cross-chain bridging via Soul Protocol.
 * Supports multiple bridge adapters (LayerZero, Hyperlane, native L2).
 *
 * @param config - Soul SDK configuration
 * @returns Bridge operation methods and loading states
 */
export function useSoulBridge(_config: SoulConfig): UseSoulBridgeReturn {
  // TODO: Implement using React useState/useCallback with SoulSDK bridge client
  return {
    bridge: async () => {
      throw new Error(
        "useSoulBridge: not yet implemented — install @soul/sdk and configure provider",
      );
    },
    status: async () => {
      throw new Error("useSoulBridge: not yet implemented");
    },
    isBridging: false,
    error: null,
  };
}

/**
 * Hook for generating ZK proofs using Noir circuits.
 * Uses the NoirProver with optional WASM backend.
 *
 * @param config - Soul SDK configuration
 * @returns Prover methods and loading states
 */
export function useSoulProver(_config: SoulConfig): UseSoulProverReturn {
  // TODO: Implement using React useState/useCallback with NoirProver
  return {
    prove: async () => {
      throw new Error(
        "useSoulProver: not yet implemented — install @soul/sdk and configure provider",
      );
    },
    isProving: false,
    error: null,
  };
}

// Re-export types for consumers
export type { ReactNode };
