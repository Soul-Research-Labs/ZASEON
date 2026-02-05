/**
 * GKR Module - Soul Protocol SDK
 * ===============================
 * 
 * GKR (Goldwasser-Kalai-Rothblum) proving system integration
 * with Hekate-Groestl hash function optimization.
 * 
 * Features:
 * - Sumcheck protocol with Gruen's trick (3 values vs 5 per round)
 * - Batch linear sumcheck for partial rounds
 * - Hekate-Groestl hash integration for GKR recursion
 * - ~15x theoretical overhead (vs ~100x for STARKs)
 * 
 * Reference: https://vitalik.eth.limo/general/2025/10/19/gkr.html
 */

export {
  // Core classes
  GKRProver,
  GKRVerifier,
  
  // Constants
  KOALABEAR_PRIME,
  EXTENSION_DEGREE,
  MAX_ROUNDS,
  STATE_SIZE,
  HEKATE_ROUNDS,
  
  // Types
  type FieldElement,
  type ExtensionFieldElement,
  type MultilinearEval,
  type SumcheckRoundProof,
  type SumcheckProof,
  type LayerProof,
  type GKRProof,
  type GKRProverConfig,
  
  // Field arithmetic
  fieldAdd,
  fieldSub,
  fieldMul,
  fieldPow,
  fieldInv,
  fieldDiv,
  
  // Gruen's trick
  generateHalfWeights,
  generateWeights,
  hsumToSum,
  
  // Lagrange interpolation
  deg3LagrangeWeights,
  deg4LagrangeWeights,
  
  // Sumcheck
  sumcheckRoundOptimized,
  
  // Hekate-Groestl
  hekateSBox,
  hekateHashPair,
} from './prover.js';
