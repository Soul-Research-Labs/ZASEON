/**
 * Monitoring Config Populator
 *
 * Reads deployment addresses from deployments/ and populates
 * monitoring configs (defender + tenderly) with actual addresses.
 *
 * Usage:
 *   npx ts-node scripts/populateMonitoring.ts --network mainnet
 *   npx ts-node scripts/populateMonitoring.ts --network sepolia
 */

import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve } from "path";

// Contract → monitoring category mapping
const CONTRACT_MONITORS: Record<string, string[]> = {
    UniversalShieldedPool: [
        "critical_events",
        "double_spend_detection",
        "large_transfers",
        "admin_actions",
    ],
    UniversalShieldedPoolUpgradeable: [
        "critical_events",
        "double_spend_detection",
        "large_transfers",
        "admin_actions",
    ],
    PrivacyRouter: ["critical_events", "admin_actions"],
    PrivacyRouterUpgradeable: ["critical_events", "admin_actions"],
    CrossChainPrivacyHub: [
        "critical_events",
        "cross_chain_messages",
        "proof_failures",
        "admin_actions",
    ],
    CrossChainCommitmentRelay: [
        "cross_chain_messages",
        "admin_actions",
    ],
    CrossChainProofHubV3: [
        "critical_events",
        "cross_chain_messages",
        "proof_failures",
    ],
    NullifierRegistryV3: [
        "double_spend_detection",
        "admin_actions",
    ],
    RelayerFeeMarket: ["relayer_slashing", "admin_actions"],
    CrossChainSanctionsOracle: ["admin_actions"],
};

interface DeploymentFile {
    [contractName: string]: {
        address: string;
        [key: string]: any;
    };
}

function loadDeployments(network: string): DeploymentFile {
    const patterns = [
        `deployments/${network}.json`,
        `deployments/localhost-31337.json`,
        `deployments/undefined-31337.json`,
    ];

    for (const pat of patterns) {
        const full = resolve(process.cwd(), pat);
        if (existsSync(full)) {
            console.log(`Loading deployments from ${pat}`);
            return JSON.parse(readFileSync(full, "utf8"));
        }
    }

    console.warn("No deployment file found. Using placeholder addresses.");
    return {};
}

function populateDefender(deployments: DeploymentFile) {
    const configPath = resolve(process.cwd(), "monitoring/defender.config.json");
    if (!existsSync(configPath)) {
        console.warn("defender.config.json not found, skipping");
        return;
    }

    const config = JSON.parse(readFileSync(configPath, "utf8"));

    // Build address → monitor mapping
    for (const [contractName, monitors] of Object.entries(CONTRACT_MONITORS)) {
        const deployed = deployments[contractName];
        if (!deployed?.address) continue;

        for (const monitorName of monitors) {
            if (config.monitors?.[monitorName]) {
                const addrList: string[] = config.monitors[monitorName].addresses || [];
                if (!addrList.includes(deployed.address)) {
                    addrList.push(deployed.address);
                }
                config.monitors[monitorName].addresses = addrList;
            }
        }
    }

    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
    console.log("Updated monitoring/defender.config.json");
}

function populateTenderly(deployments: DeploymentFile) {
    const configPath = resolve(process.cwd(), "monitoring/tenderly.config.json");
    if (!existsSync(configPath)) {
        console.warn("tenderly.config.json not found, skipping");
        return;
    }

    const config = JSON.parse(readFileSync(configPath, "utf8"));

    // Build contract list for each network
    const contracts = Object.entries(deployments)
        .filter(([_, v]) => v.address)
        .map(([name, v]) => ({
            name,
            address: v.address,
        }));

    // Populate all networks with the same contracts
    // (in production, filter by chainId)
    for (const networkKey of Object.keys(config.networks || {})) {
        config.networks[networkKey].contracts = contracts;
    }

    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
    console.log("Updated monitoring/tenderly.config.json");
}

// Main
const network = process.argv.includes("--network")
    ? process.argv[process.argv.indexOf("--network") + 1]
    : "localhost";

console.log(`Populating monitoring configs for network: ${network}`);

const deployments = loadDeployments(network);
populateDefender(deployments);
populateTenderly(deployments);

console.log("Done. Remember to add real addresses after mainnet deployment.");
