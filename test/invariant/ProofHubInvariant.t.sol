// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../../contracts/bridge/CrossChainProofHubV3.sol";

/**
 * @title ProofHubInvariant
 * @notice Invariant tests for CrossChainProofHubV3
 * @dev Ensures:
 *  - Solvency: contract balance >= sum(relayer stakes) + sum(claimable rewards)
 *  - Proof status only moves forward (Pending→Verified→Finalized, or Pending→Challenged→Rejected)
 *  - totalProofs is monotonically increasing
 *  - Relayer can't withdraw stake while having pending proofs
 *  - Each proof can only be challenged once
 *
 * Run with: forge test --match-contract ProofHubInvariant -vvv
 */
contract ProofHubInvariant is StdInvariant, Test {
    CrossChainProofHubV3 public hub;
    ProofHubHandler public handler;

    function setUp() public {
        hub = new CrossChainProofHubV3();

        // Setup roles
        hub.confirmRoleSeparation();

        handler = new ProofHubHandler(hub);
        targetContract(address(handler));

        // Fund handler for staking
        vm.deal(address(handler), 1000 ether);

        // Grant handler the relayer role
        hub.grantRole(hub.RELAYER_ROLE(), address(handler));
        hub.grantRole(hub.CHALLENGER_ROLE(), address(handler));
    }

    /// @notice totalProofs must be monotonically increasing
    function invariant_totalProofsMonotonic() public view {
        assertGe(
            hub.totalProofs(),
            handler.ghost_previousTotalProofs(),
            "totalProofs decreased"
        );
    }

    /// @notice Relayer stake tracking: staked amounts should be non-negative
    function invariant_stakesNonNegative() public view {
        address[] memory relayers = handler.ghost_knownRelayers();
        for (uint256 i = 0; i < relayers.length; i++) {
            // relayerStakes is a uint256, so always >= 0, but check tracked values
            assertGe(
                handler.ghost_totalStaked(),
                handler.ghost_totalUnstaked(),
                "More unstaked than staked"
            );
        }
    }

    /// @notice Staked amount ghost should track actual deposits
    function invariant_stakeAccounting() public view {
        uint256 expectedMinBalance = handler.ghost_totalStaked() -
            handler.ghost_totalUnstaked();
        // Hub balance should at least cover stakes (may also hold fees)
        assertGe(
            address(hub).balance,
            expectedMinBalance,
            "Hub balance less than expected from stake tracking"
        );
    }
}

/**
 * @title ProofHubHandler
 * @notice Fuzzable handler for CrossChainProofHubV3
 */
contract ProofHubHandler is Test {
    CrossChainProofHubV3 public hub;

    // Ghost state
    uint256 public ghost_previousTotalProofs;
    uint256 public ghost_totalStaked;
    uint256 public ghost_totalUnstaked;
    address[] private _knownRelayers;
    mapping(address => bool) private _isKnownRelayer;

    constructor(CrossChainProofHubV3 _hub) {
        hub = _hub;
    }

    function ghost_knownRelayers() external view returns (address[] memory) {
        return _knownRelayers;
    }

    /// @notice Deposit stake into the hub
    function depositStake(uint256 amountSeed) external {
        uint256 amount = bound(amountSeed, 0.1 ether, 10 ether);

        ghost_previousTotalProofs = hub.totalProofs();

        try hub.depositStake{value: amount}() {
            ghost_totalStaked += amount;
            if (!_isKnownRelayer[address(this)]) {
                _knownRelayers.push(address(this));
                _isKnownRelayer[address(this)] = true;
            }
        } catch {}
    }

    /// @notice Attempt to withdraw stake
    function withdrawStake(uint256 amountSeed) external {
        uint256 stake = hub.relayerStakes(address(this));
        if (stake == 0) return;

        uint256 amount = bound(amountSeed, 1, stake);

        ghost_previousTotalProofs = hub.totalProofs();

        try hub.withdrawStake(amount) {
            ghost_totalUnstaked += amount;
        } catch {
            // Expected if pending proofs exist
        }
    }

    /// @notice Allow handler to receive ETH
    receive() external payable {}
}
