// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

/**
 * @title ForkTestBase
 * @notice Reusable base contract for fork-based cross-chain integration tests.
 * @dev Provides common utilities for multi-chain fork testing:
 *   - Dual-mode: real forks (FORK_TESTS=true) or local simulation (vm.chainId)
 *   - Chain registry with canonical chain IDs and RPC env var resolution
 *   - Fork switching helpers with automatic chain ID tracking
 *   - Pre-funded test accounts (admin, relayer, user, attacker)
 *   - EIP-712 domain separator helpers for cross-chain uniqueness testing
 *
 * Usage:
 *   contract MyForkTest is ForkTestBase {
 *       function setUp() public override {
 *           super.setUp();
 *           _registerChain(L2Chain.Arbitrum);
 *           _registerChain(L2Chain.Optimism);
 *           _initForks();
 *           // Deploy contracts per chain...
 *       }
 *   }
 *
 * Run (local):  forge test --match-contract MyForkTest -vvv
 * Run (forks):  FORK_TESTS=true forge test --match-contract MyForkTest -vvv
 */
abstract contract ForkTestBase is Test {
    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum L2Chain {
        Mainnet,
        Arbitrum,
        Optimism,
        Base,
        ZkSync,
        Scroll,
        Linea,
        PolygonZkEVM,
        Sepolia,
        ArbitrumSepolia,
        BaseSepolia,
        OptimismSepolia,
        ScrollSepolia,
        LineaSepolia,
        ZkSyncSepolia,
        PolygonAmoy
    }

    /*//////////////////////////////////////////////////////////////
                             STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct ChainConfig {
        uint256 chainId;
        string rpcEnvVar; // e.g. "ARBITRUM_RPC_URL"
        string label;
        uint256 forkId; // Set after _initForks()
        bool registered;
    }

    /*//////////////////////////////////////////////////////////////
                           CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant ADMIN_INITIAL_BALANCE = 100 ether;
    uint256 constant RELAYER_INITIAL_BALANCE = 50 ether;
    uint256 constant USER_INITIAL_BALANCE = 10 ether;
    uint256 constant ATTACKER_INITIAL_BALANCE = 10 ether;

    /*//////////////////////////////////////////////////////////////
                             STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice True if running against real RPC forks
    bool public useForks;

    /// @notice Currently active chain (for local simulation tracking)
    L2Chain public activeChain;

    /// @notice Configuration for each chain
    mapping(L2Chain => ChainConfig) public chainConfigs;

    /// @notice List of registered chains for iteration
    L2Chain[] public registeredChains;

    /// @notice Pre-funded test accounts
    address public admin;
    address public relayer;
    address public user;
    address public attacker;

    /*//////////////////////////////////////////////////////////////
                           MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Switch to a specific chain for the duration of a block
    modifier onChain(L2Chain chain) {
        _switchToChain(chain);
        _;
    }

    /*//////////////////////////////////////////////////////////////
                             SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        // Create named accounts
        admin = makeAddr("admin");
        relayer = makeAddr("relayer");
        user = makeAddr("user");
        attacker = makeAddr("attacker");

        // Fund accounts
        vm.deal(admin, ADMIN_INITIAL_BALANCE);
        vm.deal(relayer, RELAYER_INITIAL_BALANCE);
        vm.deal(user, USER_INITIAL_BALANCE);
        vm.deal(attacker, ATTACKER_INITIAL_BALANCE);

        // Check fork mode
        useForks = vm.envOr("FORK_TESTS", false);

        // Initialize chain configurations (not yet registered)
        _initChainConfigs();
    }

    /*//////////////////////////////////////////////////////////////
                        CHAIN REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a chain for use in tests. Call before _initForks().
    function _registerChain(L2Chain chain) internal {
        require(
            !chainConfigs[chain].registered,
            "ForkTestBase: chain already registered"
        );
        chainConfigs[chain].registered = true;
        registeredChains.push(chain);
    }

    /// @notice Initialize forks for all registered chains. Call after _registerChain().
    function _initForks() internal {
        if (useForks) {
            for (uint256 i = 0; i < registeredChains.length; i++) {
                L2Chain chain = registeredChains[i];
                ChainConfig storage config = chainConfigs[chain];
                string memory rpcUrl = vm.envString(config.rpcEnvVar);
                config.forkId = vm.createFork(rpcUrl);
            }
        }

        // Activate first registered chain
        if (registeredChains.length > 0) {
            _switchToChain(registeredChains[0]);
        }
    }

    /// @notice Initialize forks pinned to specific block numbers for reproducibility.
    function _initForksAtBlock(uint256[] memory blockNumbers) internal {
        require(
            blockNumbers.length == registeredChains.length,
            "ForkTestBase: block count mismatch"
        );

        if (useForks) {
            for (uint256 i = 0; i < registeredChains.length; i++) {
                L2Chain chain = registeredChains[i];
                ChainConfig storage config = chainConfigs[chain];
                string memory rpcUrl = vm.envString(config.rpcEnvVar);
                config.forkId = vm.createFork(rpcUrl, blockNumbers[i]);
            }
        }

        if (registeredChains.length > 0) {
            _switchToChain(registeredChains[0]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                       CHAIN SWITCHING
    //////////////////////////////////////////////////////////////*/

    /// @notice Switch execution context to a specific chain
    function _switchToChain(L2Chain chain) internal {
        ChainConfig storage config = chainConfigs[chain];
        require(config.registered, "ForkTestBase: chain not registered");

        if (useForks) {
            vm.selectFork(config.forkId);
        } else {
            vm.chainId(config.chainId);
        }
        activeChain = chain;
    }

    /// @notice Get the chain ID of a registered chain
    function _chainId(L2Chain chain) internal view returns (uint256) {
        return chainConfigs[chain].chainId;
    }

    /// @notice Get the label of a registered chain
    function _chainLabel(L2Chain chain) internal view returns (string memory) {
        return chainConfigs[chain].label;
    }

    /// @notice Get the number of registered chains
    function _chainCount() internal view returns (uint256) {
        return registeredChains.length;
    }

    /*//////////////////////////////////////////////////////////////
                         DEPLOY HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy a contract on a specific chain. Override in subclasses.
    /// @dev Use onChain(chain) modifier or _switchToChain() before deploying.
    /// @param chain The target chain for deployment
    function _deployOnChain(L2Chain chain) internal virtual;

    /// @notice Deploy contracts on all registered chains
    function _deployOnAllChains() internal {
        for (uint256 i = 0; i < registeredChains.length; i++) {
            _switchToChain(registeredChains[i]);
            _deployOnChain(registeredChains[i]);
        }
        // Switch back to first chain
        if (registeredChains.length > 0) {
            _switchToChain(registeredChains[0]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute an EIP-712 domain separator for a given chain
    /// @param name Protocol name
    /// @param version Protocol version
    /// @param chainId Chain identifier
    /// @param verifyingContract Contract address
    function _domainSeparator(
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256(
                        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                    ),
                    keccak256(bytes(name)),
                    keccak256(bytes(version)),
                    chainId,
                    verifyingContract
                )
            );
    }

    /// @notice Assert that a value differs across all registered chains.
    ///         Useful for verifying chain-specific derivation (nullifiers, hashes, etc.)
    /// @param values Array of values, one per registered chain (same order as registeredChains)
    function _assertAllUnique(bytes32[] memory values) internal pure {
        for (uint256 i = 0; i < values.length; i++) {
            for (uint256 j = i + 1; j < values.length; j++) {
                assertTrue(
                    values[i] != values[j],
                    "Values must be unique across chains"
                );
            }
        }
    }

    /// @notice Fund an account on the current chain
    function _fund(address account, uint256 amount) internal {
        vm.deal(account, account.balance + amount);
    }

    /// @notice Fund an account on a specific chain
    function _fundOnChain(
        L2Chain chain,
        address account,
        uint256 amount
    ) internal {
        _switchToChain(chain);
        vm.deal(account, account.balance + amount);
    }

    /*//////////////////////////////////////////////////////////////
                    ASSERTION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Assert a condition holds on all registered chains
    function _assertOnAllChains(function() internal fn) internal {
        for (uint256 i = 0; i < registeredChains.length; i++) {
            _switchToChain(registeredChains[i]);
            fn();
        }
    }

    /*//////////////////////////////////////////////////////////////
                  INTERNAL: CHAIN CONFIG INIT
    //////////////////////////////////////////////////////////////*/

    function _initChainConfigs() private {
        // Mainnets
        chainConfigs[L2Chain.Mainnet] = ChainConfig({
            chainId: 1,
            rpcEnvVar: "MAINNET_RPC_URL",
            label: "Ethereum Mainnet",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.Arbitrum] = ChainConfig({
            chainId: 42161,
            rpcEnvVar: "ARBITRUM_RPC_URL",
            label: "Arbitrum One",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.Optimism] = ChainConfig({
            chainId: 10,
            rpcEnvVar: "OPTIMISM_RPC_URL",
            label: "Optimism",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.Base] = ChainConfig({
            chainId: 8453,
            rpcEnvVar: "BASE_RPC_URL",
            label: "Base",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.ZkSync] = ChainConfig({
            chainId: 324,
            rpcEnvVar: "ZKSYNC_RPC_URL",
            label: "zkSync Era",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.Scroll] = ChainConfig({
            chainId: 534352,
            rpcEnvVar: "SCROLL_RPC_URL",
            label: "Scroll",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.Linea] = ChainConfig({
            chainId: 59144,
            rpcEnvVar: "LINEA_RPC_URL",
            label: "Linea",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.PolygonZkEVM] = ChainConfig({
            chainId: 1101,
            rpcEnvVar: "POLYGON_ZKEVM_RPC_URL",
            label: "Polygon zkEVM",
            forkId: 0,
            registered: false
        });

        // Testnets
        chainConfigs[L2Chain.Sepolia] = ChainConfig({
            chainId: 11155111,
            rpcEnvVar: "SEPOLIA_RPC_URL",
            label: "Sepolia",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.ArbitrumSepolia] = ChainConfig({
            chainId: 421614,
            rpcEnvVar: "ARBITRUM_SEPOLIA_RPC_URL",
            label: "Arbitrum Sepolia",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.BaseSepolia] = ChainConfig({
            chainId: 84532,
            rpcEnvVar: "BASE_SEPOLIA_RPC_URL",
            label: "Base Sepolia",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.OptimismSepolia] = ChainConfig({
            chainId: 11155420,
            rpcEnvVar: "OPTIMISM_SEPOLIA_RPC_URL",
            label: "Optimism Sepolia",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.ScrollSepolia] = ChainConfig({
            chainId: 534351,
            rpcEnvVar: "SCROLL_SEPOLIA_RPC_URL",
            label: "Scroll Sepolia",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.LineaSepolia] = ChainConfig({
            chainId: 59141,
            rpcEnvVar: "LINEA_SEPOLIA_RPC_URL",
            label: "Linea Sepolia",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.ZkSyncSepolia] = ChainConfig({
            chainId: 300,
            rpcEnvVar: "ZKSYNC_SEPOLIA_RPC_URL",
            label: "zkSync Sepolia",
            forkId: 0,
            registered: false
        });
        chainConfigs[L2Chain.PolygonAmoy] = ChainConfig({
            chainId: 80002,
            rpcEnvVar: "POLYGON_AMOY_RPC_URL",
            label: "Polygon Amoy",
            forkId: 0,
            registered: false
        });
    }
}
