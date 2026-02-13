#!/bin/bash

BB="$HOME/.bb/bb"
GENERATED_DIR="contracts/verifiers/generated"
mkdir -p "$GENERATED_DIR"

CIRCUITS="accredited_investor aggregator balance_proof compliance_proof encrypted_transfer merkle_proof pedersen_commitment policy_bound_proof ring_signature sanctions_check shielded_pool swap_proof"

for circuit_name in $CIRCUITS; do
  circuit_json="noir/target/${circuit_name}.json"
  if [ -f "$circuit_json" ]; then
    vk_file="noir/target/${circuit_name}_vk"
    sol_file="noir/target/${circuit_name}_verifier.sol"
    echo "Processing: $circuit_name"
    "$BB" write_vk -b "$circuit_json" -o "$vk_file"
    "$BB" write_solidity_verifier -k "$vk_file/vk" -o "$sol_file" -t evm || {
      echo "  -> evm target failed, trying without target..."
      "$BB" write_solidity_verifier -k "$vk_file/vk" -o "$sol_file" || true
    }
    if [ -f "$sol_file" ]; then
      target_contract_name=$(echo "$circuit_name" | awk -F_ '{for(i=1;i<=NF;i++) printf "%s", toupper(substr($i,1,1)) substr($i,2)}')"Verifier"
      target_file_name="${target_contract_name}.sol"
      sed "s/UltraVerifier/$target_contract_name/g" "$sol_file" > "$GENERATED_DIR/$target_file_name"
      echo "  -> Generated $target_file_name"
    else
      echo "  -> FAILED to generate $sol_file"
    fi
  else
    echo "  -> NOT FOUND: $circuit_json"
  fi
done

echo "Done. Generated verifiers:"
ls -1 "$GENERATED_DIR"
