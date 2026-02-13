#!/bin/bash
# Generate stub verifiers for circuits where bb write_solidity_verifier fails
# These stubs implement IVerifier and revert with a clear message
# They should be replaced with real verifiers when bb is updated to a stable release

GENERATED_DIR="contracts/verifiers/generated"

CIRCUITS="accredited_investor aggregator balance_proof compliance_proof encrypted_transfer merkle_proof pedersen_commitment policy_bound_proof ring_signature sanctions_check shielded_pool swap_proof"

for circuit_name in $CIRCUITS; do
  # Convert snake_case to CamelCase
  contract_name=$(echo "$circuit_name" | awk -F_ '{for(i=1;i<=NF;i++) printf "%s", toupper(substr($i,1,1)) substr($i,2)}')
  verifier_name="${contract_name}Verifier"
  file_name="${verifier_name}.sol"
  target_path="${GENERATED_DIR}/${file_name}"

  # Skip if already exists (real verifier)
  if [ -f "$target_path" ]; then
    echo "SKIP: $file_name already exists"
    continue
  fi

  cat > "$target_path" << EOF
// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec
// @notice STUB VERIFIER — replace with real bb-generated verifier when
//         barretenberg fixes the on_curve assertion (bb >= 3.1.0).
//         Circuit compiles and VK exists at noir/target/${circuit_name}_vk/vk.
pragma solidity ^0.8.24;

interface IVerifier {
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external returns (bool);
}

contract ${verifier_name} is IVerifier {
    error StubVerifierNotDeployed();

    function verify(bytes calldata, bytes32[] calldata) external pure override returns (bool) {
        revert StubVerifierNotDeployed();
    }
}
EOF
  echo "Generated stub: $file_name"
done

echo "Done."
