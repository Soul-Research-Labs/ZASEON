// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {SelectiveDisclosureManager} from "../../contracts/compliance/SelectiveDisclosureManager.sol";
import {ConfigurablePrivacyLevels} from "../../contracts/compliance/ConfigurablePrivacyLevels.sol";
import {ComplianceReportingModule} from "../../contracts/compliance/ComplianceReportingModule.sol";

/**
 * @title DeployComplianceSuite
 * @notice Deploys the full Tachyon-inspired compliance suite:
 *         SelectiveDisclosureManager, ConfigurablePrivacyLevels, ComplianceReportingModule
 * @dev Usage:
 *   forge script scripts/deploy/DeployComplianceSuite.s.sol:DeployComplianceSuite \
 *     --rpc-url $RPC_URL --broadcast --verify
 *
 *   Environment variables:
 *     DEPLOYER_PRIVATE_KEY   - Deployer private key
 *     COMPLIANCE_ADMIN       - Admin address (defaults to deployer)
 *     COMPLIANCE_VERIFIER    - Optional IProofVerifier address (defaults to address(0))
 */
contract DeployComplianceSuite is Script {
    function run() external {
        // Read config
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);
        address admin = vm.envOr("COMPLIANCE_ADMIN", deployer);
        address verifier = vm.envOr("COMPLIANCE_VERIFIER", address(0));

        console.log("=== Soul Protocol Compliance Suite Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Admin:", admin);
        console.log("Verifier:", verifier);
        console.log("Chain ID:", block.chainid);
        console.log("");

        vm.startBroadcast(deployerPk);

        // 1. Deploy SelectiveDisclosureManager
        SelectiveDisclosureManager sdm = new SelectiveDisclosureManager(
            admin,
            verifier
        );
        console.log("SelectiveDisclosureManager:", address(sdm));

        // 2. Deploy ConfigurablePrivacyLevels
        ConfigurablePrivacyLevels cpl = new ConfigurablePrivacyLevels(admin);
        console.log("ConfigurablePrivacyLevels:", address(cpl));

        // 3. Deploy ComplianceReportingModule
        ComplianceReportingModule crm = new ComplianceReportingModule(
            admin,
            verifier
        );
        console.log("ComplianceReportingModule:", address(crm));

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
            '    "SelectiveDisclosureManager": "',
            vm.toString(address(sdm)),
            '",\n',
            '    "ConfigurablePrivacyLevels": "',
            vm.toString(address(cpl)),
            '",\n',
            '    "ComplianceReportingModule": "',
            vm.toString(address(crm)),
            '"\n',
            "  }\n",
            "}"
        );

        string memory outPath = string.concat(
            "deployments/compliance-",
            vm.toString(block.chainid),
            ".json"
        );
        vm.writeFile(outPath, json);
        console.log("\nDeployment saved to:", outPath);
    }
}

/**
 * @title DeployComplianceSuiteTestnet
 * @notice Testnet variant with default test addresses and auditor/regulator setup
 */
contract DeployComplianceSuiteTestnet is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);

        console.log("=== Testnet Compliance Suite Deployment ===");
        console.log("Deployer:", deployer);

        vm.startBroadcast(deployerPk);

        // Deploy with no verifier (testnet)
        SelectiveDisclosureManager sdm = new SelectiveDisclosureManager(
            deployer,
            address(0)
        );
        ConfigurablePrivacyLevels cpl = new ConfigurablePrivacyLevels(deployer);
        ComplianceReportingModule crm = new ComplianceReportingModule(
            deployer,
            address(0)
        );

        console.log("SelectiveDisclosureManager:", address(sdm));
        console.log("ConfigurablePrivacyLevels:", address(cpl));
        console.log("ComplianceReportingModule:", address(crm));

        // Setup test auditor/regulator (deployer acts as all roles for testing)
        sdm.authorizeAuditor(deployer);
        sdm.authorizeRegulator(deployer);

        vm.stopBroadcast();
    }
}
