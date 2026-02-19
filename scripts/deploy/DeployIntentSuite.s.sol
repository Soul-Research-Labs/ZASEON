// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IntentSettlementLayer} from "../../contracts/core/IntentSettlementLayer.sol";
import {InstantRelayerRewards} from "../../contracts/relayer/InstantRelayerRewards.sol";
import {InstantSettlementGuarantee} from "../../contracts/core/InstantSettlementGuarantee.sol";

/**
 * @title DeployIntentSuite
 * @notice Deploys the Phase 3 Intent Architecture & Solver Network suite:
 *         IntentSettlementLayer, InstantRelayerRewards, InstantSettlementGuarantee
 * @dev Usage:
 *   forge script scripts/deploy/DeployIntentSuite.s.sol:DeployIntentSuite \
 *     --rpc-url $RPC_URL --broadcast --verify
 *
 *   Environment variables:
 *     DEPLOYER_PRIVATE_KEY   - Deployer private key
 *     INTENT_ADMIN           - Admin address (defaults to deployer)
 *     INTENT_VERIFIER        - Optional IProofVerifier address (defaults to address(0))
 *     SUPPORTED_CHAINS       - Comma-separated chain IDs to enable (defaults to "1,42161,10,8453")
 */
contract DeployIntentSuite is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);
        address admin = vm.envOr("INTENT_ADMIN", deployer);
        address verifier = vm.envOr("INTENT_VERIFIER", address(0));

        console.log("=== Soul Protocol Intent Suite Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Admin:", admin);
        console.log("Verifier:", verifier);
        console.log("Chain ID:", block.chainid);
        console.log("");

        vm.startBroadcast(deployerPk);

        // 1. Deploy IntentSettlementLayer
        IntentSettlementLayer intentLayer = new IntentSettlementLayer(
            admin,
            verifier
        );
        console.log("IntentSettlementLayer:", address(intentLayer));

        // 2. Configure supported chains
        intentLayer.setSupportedChain(1, true); // Ethereum
        intentLayer.setSupportedChain(42161, true); // Arbitrum
        intentLayer.setSupportedChain(10, true); // Optimism
        intentLayer.setSupportedChain(8453, true); // Base
        intentLayer.setSupportedChain(324, true); // zkSync
        intentLayer.setSupportedChain(534352, true); // Scroll
        intentLayer.setSupportedChain(59144, true); // Linea
        intentLayer.setSupportedChain(1101, true); // Polygon zkEVM
        console.log("  Configured 8 supported chains");

        // 3. Deploy InstantRelayerRewards
        InstantRelayerRewards relayerRewards = new InstantRelayerRewards(admin);
        console.log("InstantRelayerRewards:", address(relayerRewards));

        // 4. Deploy InstantSettlementGuarantee (linked to IntentSettlementLayer)
        InstantSettlementGuarantee guarantee = new InstantSettlementGuarantee(
            admin,
            address(intentLayer)
        );
        console.log("InstantSettlementGuarantee:", address(guarantee));

        vm.stopBroadcast();

        // Save deployment addresses
        string memory json = string.concat(
            "{\n",
            '  "chainId": ',
            vm.toString(block.chainid),
            ",\n",
            '  "deployer": "',
            vm.toString(deployer),
            '",\n',
            '  "admin": "',
            vm.toString(admin),
            '",\n',
            '  "contracts": {\n',
            '    "IntentSettlementLayer": "',
            vm.toString(address(intentLayer)),
            '",\n',
            '    "InstantRelayerRewards": "',
            vm.toString(address(relayerRewards)),
            '",\n',
            '    "InstantSettlementGuarantee": "',
            vm.toString(address(guarantee)),
            '"\n',
            "  }\n",
            "}"
        );

        string memory outPath = string.concat(
            "deployments/intent-suite-",
            vm.toString(block.chainid),
            ".json"
        );
        vm.writeFile(outPath, json);
        console.log("\nDeployment saved to:", outPath);
    }
}

/**
 * @title DeployIntentSuiteTestnet
 * @notice Testnet variant with deployer as all roles for testing
 */
contract DeployIntentSuiteTestnet is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);

        console.log("=== Testnet Intent Suite Deployment ===");
        console.log("Deployer:", deployer);

        vm.startBroadcast(deployerPk);

        // Deploy with no verifier (testnet)
        IntentSettlementLayer intentLayer = new IntentSettlementLayer(
            deployer,
            address(0)
        );

        // Configure testnet chains
        intentLayer.setSupportedChain(block.chainid, true);
        intentLayer.setSupportedChain(11155111, true); // Sepolia
        intentLayer.setSupportedChain(421614, true); // Arbitrum Sepolia
        intentLayer.setSupportedChain(84532, true); // Base Sepolia

        InstantRelayerRewards relayerRewards = new InstantRelayerRewards(
            deployer
        );

        InstantSettlementGuarantee guarantee = new InstantSettlementGuarantee(
            deployer,
            address(intentLayer)
        );

        // Grant deployer all roles for testing
        intentLayer.grantRole(intentLayer.CHALLENGER_ROLE(), deployer);
        guarantee.grantRole(guarantee.SETTLEMENT_ROLE(), deployer);

        console.log("IntentSettlementLayer:", address(intentLayer));
        console.log("InstantRelayerRewards:", address(relayerRewards));
        console.log("InstantSettlementGuarantee:", address(guarantee));

        vm.stopBroadcast();
    }
}
