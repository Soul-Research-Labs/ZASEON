import { PILSDK } from "./client/PILSDK";
import { CryptoModule } from "./utils/crypto";
import ProofTranslator, {
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  translateForChain,
  createVerifyCalldata,
  createBatchProofData,
  CURVE_PARAMS,
  CHAIN_CONFIGS,
} from "./proof-translator/ProofTranslator";
import {
  EVMChainAdapter,
  EVMBLS12381Adapter,
  CosmosChainAdapter,
  SubstrateChainAdapter,
  createChainAdapter,
  MultiChainProofManager,
} from "./proof-translator/adapters/ChainAdapter";

export {
  // Core SDK
  PILSDK,
  CryptoModule,

  // Proof Translator
  ProofTranslator,
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  translateForChain,
  createVerifyCalldata,
  createBatchProofData,
  CURVE_PARAMS,
  CHAIN_CONFIGS,

  // Chain Adapters
  EVMChainAdapter,
  EVMBLS12381Adapter,
  CosmosChainAdapter,
  SubstrateChainAdapter,
  createChainAdapter,
  MultiChainProofManager,
};
