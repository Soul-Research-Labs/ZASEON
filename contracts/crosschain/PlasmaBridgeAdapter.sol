// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "../plasma/PlasmaPrimitives.sol";

/**
 * @title PlasmaBridgeAdapter
 * @notice Bridge adapter for Plasma Layer 2 chains
 * @dev Implements operator management, deposits, exits, and challenges
 *
 * Key Features:
 * - Operator block submission with Merkle roots
 * - Deposit handling with UTXO creation
 * - Standard exit with challenge period
 * - In-flight exit for unconfirmed transactions
 * - Priority queue for exit ordering
 * - Cross-domain nullifier binding for PIL
 */
contract PlasmaBridgeAdapter is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using PlasmaPrimitives for *;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 public constant MAX_TRANSFER = 100_000 ether;
    uint256 public constant DAILY_LIMIT = 1_000_000 ether;
    uint256 public constant MAX_RELAYER_FEE_BPS = 500; // 5%
    uint256 public constant BOND_AMOUNT = 0.1 ether;

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Current plasma block number
    uint256 public currentBlockNumber;

    /// @notice Mapping of block number to block root
    mapping(uint256 => bytes32) public blockRoots;

    /// @notice Mapping of block number to block data
    mapping(uint256 => PlasmaPrimitives.PlasmaBlock) public blocks;

    /// @notice Mapping of UTXO position to owner
    mapping(uint256 => address) public utxoOwners;

    /// @notice Mapping of UTXO position to spent status
    mapping(uint256 => bool) public utxoSpent;

    /// @notice Mapping of exit ID to exit data
    mapping(uint256 => PlasmaPrimitives.Exit) public exits;

    /// @notice Next exit ID
    uint256 public nextExitId;

    /// @notice Exit priority queue (sorted array for simplicity)
    uint256[] public exitQueue;

    /// @notice Mapping of nullifier to consumed status
    mapping(bytes32 => bool) public nullifierConsumed;

    /// @notice Cross-domain nullifier mappings
    mapping(bytes32 => bytes32) public crossDomainNullifiers;

    /// @notice Reverse mapping: PIL nullifier -> Plasma nullifier
    mapping(bytes32 => bytes32) public pilBindings;

    /// @notice Deposit commitments
    mapping(bytes32 => PlasmaPrimitives.Deposit) public deposits;

    /// @notice Next deposit block number
    uint256 public nextDepositBlockNumber;

    /// @notice Circuit breaker status
    bool public circuitBreakerActive;

    /// @notice Daily volume tracking
    uint256 public dailyVolume;
    uint256 public lastVolumeResetDay;

    /// @notice Emergency council address
    address public emergencyCouncil;

    /// @notice Relayer fee in basis points
    uint256 public relayerFeeBps;

    /// @notice Registered relayers
    mapping(address => bool) public registeredRelayers;

    /// @notice Total value locked
    uint256 public totalValueLocked;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event BlockSubmitted(
        uint256 indexed blockNumber,
        bytes32 root,
        address indexed operator
    );
    event DepositCreated(
        address indexed depositor,
        address indexed token,
        uint256 amount,
        uint256 blockNumber,
        bytes32 commitment
    );
    event ExitStarted(
        uint256 indexed exitId,
        address indexed owner,
        uint256 utxoPos,
        uint256 amount,
        uint256 exitableAt
    );
    event ExitFinalized(
        uint256 indexed exitId,
        address indexed owner,
        uint256 amount
    );
    event ExitChallenged(
        uint256 indexed exitId,
        address indexed challenger,
        bytes32 challengingTxHash
    );
    event ExitCancelled(uint256 indexed exitId);
    event NullifierConsumed(bytes32 indexed nullifier);
    event CrossDomainNullifierRegistered(
        bytes32 indexed plasmaNullifier,
        bytes32 indexed pilNullifier
    );
    event CircuitBreakerTriggered(address indexed triggeredBy, string reason);
    event CircuitBreakerReset(address indexed resetBy);
    event RelayerRegistered(address indexed relayer);
    event RelayerUnregistered(address indexed relayer);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidBlock();
    error InvalidTransaction();
    error InvalidProof();
    error InvalidExit();
    error InvalidChallenge();
    error InvalidAmount();
    error InvalidSignature();
    error ExitNotFound();
    error ExitAlreadyExists();
    error ExitNotChallengeable();
    error ExitNotFinalizable();
    error ChallengeExpired();
    error NullifierAlreadyConsumed();
    error CircuitBreakerOn();
    error ExceedsMaxTransfer();
    error ExceedsDailyLimit();
    error UTXOAlreadySpent();
    error NotUTXOOwner();
    error InsufficientBond();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier whenCircuitBreakerOff() {
        if (circuitBreakerActive) revert CircuitBreakerOn();
        _;
    }

    modifier withinDailyLimit(uint256 amount) {
        _updateDailyVolume();
        if (dailyVolume + amount > DAILY_LIMIT) revert ExceedsDailyLimit();
        _;
    }

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract
     * @param admin Admin address
     * @param _emergencyCouncil Emergency council address
     */
    function initialize(
        address admin,
        address _emergencyCouncil
    ) external initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, _emergencyCouncil);
        _grantRole(UPGRADER_ROLE, admin);

        emergencyCouncil = _emergencyCouncil;
        currentBlockNumber = 1;
        nextDepositBlockNumber = 1;
        nextExitId = 1;
        relayerFeeBps = 100; // 1% default
    }

    // =========================================================================
    // OPERATOR FUNCTIONS
    // =========================================================================

    /**
     * @notice Submit a new plasma block
     * @param root Merkle root of transactions
     * @param numTransactions Number of transactions in block
     */
    function submitBlock(
        bytes32 root,
        uint256 numTransactions
    ) external onlyRole(OPERATOR_ROLE) whenNotPaused whenCircuitBreakerOff {
        if (root == bytes32(0)) revert InvalidBlock();

        uint256 blockNum = currentBlockNumber;

        PlasmaPrimitives.PlasmaBlock memory newBlock = PlasmaPrimitives
            .PlasmaBlock({
                root: root,
                timestamp: block.timestamp,
                blockNumber: blockNum,
                operator: msg.sender,
                numTransactions: numTransactions
            });

        blocks[blockNum] = newBlock;
        blockRoots[blockNum] = root;
        currentBlockNumber++;

        emit BlockSubmitted(blockNum, root, msg.sender);
    }

    // =========================================================================
    // DEPOSIT FUNCTIONS
    // =========================================================================

    /**
     * @notice Deposit ETH to Plasma
     * @param commitment Deposit commitment
     */
    function deposit(
        bytes32 commitment
    )
        external
        payable
        nonReentrant
        whenNotPaused
        whenCircuitBreakerOff
        withinDailyLimit(msg.value)
    {
        if (msg.value == 0) revert InvalidAmount();
        if (msg.value > MAX_TRANSFER) revert ExceedsMaxTransfer();
        if (commitment == bytes32(0)) revert InvalidTransaction();

        uint256 depositBlockNum = nextDepositBlockNumber;

        deposits[commitment] = PlasmaPrimitives.Deposit({
            depositor: msg.sender,
            token: address(0),
            amount: msg.value,
            blockNumber: depositBlockNum,
            commitment: commitment
        });

        // Create UTXO for deposit
        uint256 utxoPos = PlasmaPrimitives.encodeUTXOPosition(
            depositBlockNum,
            0,
            0
        );
        utxoOwners[utxoPos] = msg.sender;

        nextDepositBlockNumber++;
        dailyVolume += msg.value;
        totalValueLocked += msg.value;

        emit DepositCreated(
            msg.sender,
            address(0),
            msg.value,
            depositBlockNum,
            commitment
        );
    }

    // =========================================================================
    // EXIT FUNCTIONS
    // =========================================================================

    /**
     * @notice Start a standard exit
     * @param utxoPos UTXO position
     * @param txBytes Transaction bytes
     * @param proof Merkle proof
     * @param signature Owner signature
     */
    function startStandardExit(
        uint256 utxoPos,
        bytes calldata txBytes,
        bytes32[] calldata proof,
        bytes calldata signature
    ) external payable nonReentrant whenNotPaused whenCircuitBreakerOff {
        if (msg.value < BOND_AMOUNT) revert InsufficientBond();
        if (!PlasmaPrimitives.isValidUTXOPosition(utxoPos))
            revert InvalidExit();
        if (utxoSpent[utxoPos]) revert UTXOAlreadySpent();

        // Verify ownership
        (uint256 blockNum, uint256 txIndex, ) = PlasmaPrimitives
            .decodeUTXOPosition(utxoPos);
        bytes32 root = blockRoots[blockNum];
        if (root == bytes32(0)) revert InvalidBlock();

        // Verify Merkle proof
        bytes32 txHash = keccak256(txBytes);
        PlasmaPrimitives.MerkleProof memory merkleProof = PlasmaPrimitives
            .MerkleProof({siblings: proof, index: txIndex});

        if (!PlasmaPrimitives.verifyMerkleProof(txHash, merkleProof, root)) {
            revert InvalidProof();
        }

        // Verify signature
        if (!PlasmaPrimitives.verifySignature(txHash, signature, msg.sender)) {
            revert InvalidSignature();
        }

        uint256 exitId = nextExitId++;
        uint256 exitableAt = PlasmaPrimitives.computeExitableAt(
            block.timestamp
        );

        // Decode amount from txBytes (simplified - actual implementation would parse properly)
        uint256 amount = _extractAmountFromTx(txBytes);

        exits[exitId] = PlasmaPrimitives.Exit({
            owner: msg.sender,
            token: address(0),
            amount: amount,
            utxoPos: utxoPos,
            exitableAt: exitableAt,
            bondAmount: msg.value,
            status: PlasmaPrimitives.ExitStatus.IN_PROGRESS
        });

        // Add to priority queue
        uint256 priority = PlasmaPrimitives.computeExitPriority(
            exitableAt,
            utxoPos
        );
        _insertExitQueue(priority);

        emit ExitStarted(exitId, msg.sender, utxoPos, amount, exitableAt);
    }

    /**
     * @notice Challenge an exit with a spending transaction
     * @param exitId Exit ID to challenge
     * @param challengingTxBytes Spending transaction bytes
     * @param proof Merkle proof
     * @param signature Spender signature
     */
    function challengeExit(
        uint256 exitId,
        bytes calldata challengingTxBytes,
        bytes32[] calldata proof,
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        PlasmaPrimitives.Exit storage exit = exits[exitId];
        if (exit.owner == address(0)) revert ExitNotFound();
        if (!PlasmaPrimitives.isExitChallengeable(exit, block.timestamp)) {
            revert ExitNotChallengeable();
        }

        bytes32 challengingTxHash = keccak256(challengingTxBytes);

        // Verify the challenging transaction spends the exit UTXO
        // (Simplified - actual implementation would verify input references)

        // Verify Merkle proof of challenging transaction
        (uint256 spendBlockNum, , ) = _extractSpendingPosition(
            challengingTxBytes
        );
        bytes32 root = blockRoots[spendBlockNum];
        if (root == bytes32(0)) revert InvalidBlock();

        PlasmaPrimitives.MerkleProof memory merkleProof = PlasmaPrimitives
            .MerkleProof({siblings: proof, index: 0});

        if (
            !PlasmaPrimitives.verifyMerkleProof(
                challengingTxHash,
                merkleProof,
                root
            )
        ) {
            revert InvalidProof();
        }

        // Verify signature from exit owner (they spent the UTXO)
        if (
            !PlasmaPrimitives.verifySignature(
                challengingTxHash,
                signature,
                exit.owner
            )
        ) {
            revert InvalidChallenge();
        }

        // Cancel exit and reward challenger
        exit.status = PlasmaPrimitives.ExitStatus.CHALLENGED;
        uint256 bond = exit.bondAmount;

        // Send bond to challenger
        (bool success, ) = msg.sender.call{value: bond}("");
        require(success, "Bond transfer failed");

        emit ExitChallenged(exitId, msg.sender, challengingTxHash);
    }

    /**
     * @notice Process exits from the queue
     * @param maxExits Maximum number of exits to process
     */
    function processExits(
        uint256 maxExits
    ) external nonReentrant whenNotPaused {
        uint256 processed = 0;

        while (processed < maxExits && exitQueue.length > 0) {
            uint256 priority = exitQueue[0];
            (, uint256 utxoPos) = PlasmaPrimitives.decodeExitPriority(priority);

            // Find exit by utxoPos
            uint256 exitId = _findExitByUtxoPos(utxoPos);
            if (exitId == 0) {
                _removeFromExitQueue(0);
                continue;
            }

            PlasmaPrimitives.Exit storage exit = exits[exitId];

            if (!PlasmaPrimitives.isExitFinalized(exit, block.timestamp)) {
                break; // Can't process yet
            }

            if (exit.status == PlasmaPrimitives.ExitStatus.IN_PROGRESS) {
                // Finalize exit
                exit.status = PlasmaPrimitives.ExitStatus.FINALIZED;
                utxoSpent[exit.utxoPos] = true;
                totalValueLocked -= exit.amount;

                // Transfer funds
                uint256 totalAmount = exit.amount + exit.bondAmount;
                (bool success, ) = exit.owner.call{value: totalAmount}("");
                require(success, "Exit transfer failed");

                emit ExitFinalized(exitId, exit.owner, exit.amount);
            }

            _removeFromExitQueue(0);
            processed++;
        }
    }

    /**
     * @notice Cancel an exit (owner only)
     * @param exitId Exit ID
     */
    function cancelExit(uint256 exitId) external nonReentrant {
        PlasmaPrimitives.Exit storage exit = exits[exitId];
        if (exit.owner != msg.sender) revert NotUTXOOwner();
        if (exit.status != PlasmaPrimitives.ExitStatus.IN_PROGRESS)
            revert InvalidExit();

        exit.status = PlasmaPrimitives.ExitStatus.CANCELLED;

        // Return bond
        (bool success, ) = msg.sender.call{value: exit.bondAmount}("");
        require(success, "Bond return failed");

        emit ExitCancelled(exitId);
    }

    // =========================================================================
    // CROSS-DOMAIN NULLIFIER
    // =========================================================================

    /**
     * @notice Register cross-domain nullifier
     * @param plasmaNullifier Plasma nullifier
     * @param targetChainId Target chain ID
     */
    function registerCrossDomainNullifier(
        bytes32 plasmaNullifier,
        uint256 targetChainId
    ) external {
        if (plasmaNullifier == bytes32(0)) revert InvalidTransaction();

        bytes32 pilNullifier = PlasmaPrimitives.derivePILBinding(
            plasmaNullifier
        );

        if (crossDomainNullifiers[plasmaNullifier] == bytes32(0)) {
            crossDomainNullifiers[plasmaNullifier] = pilNullifier;
            pilBindings[pilNullifier] = plasmaNullifier;

            emit CrossDomainNullifierRegistered(plasmaNullifier, pilNullifier);
        }
    }

    /**
     * @notice Consume a nullifier
     * @param nullifier Nullifier to consume
     */
    function consumeNullifier(
        bytes32 nullifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (nullifierConsumed[nullifier]) revert NullifierAlreadyConsumed();
        nullifierConsumed[nullifier] = true;
        emit NullifierConsumed(nullifier);
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    /**
     * @notice Trigger circuit breaker
     * @param reason Reason for triggering
     */
    function triggerCircuitBreaker(
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerActive = true;
        emit CircuitBreakerTriggered(msg.sender, reason);
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerActive = false;
        emit CircuitBreakerReset(msg.sender);
    }

    // =========================================================================
    // RELAYER MANAGEMENT
    // =========================================================================

    /**
     * @notice Register as a relayer
     */
    function registerRelayer() external {
        registeredRelayers[msg.sender] = true;
        emit RelayerRegistered(msg.sender);
    }

    /**
     * @notice Unregister as a relayer
     */
    function unregisterRelayer() external {
        registeredRelayers[msg.sender] = false;
        emit RelayerUnregistered(msg.sender);
    }

    /**
     * @notice Update relayer fee
     * @param newFeeBps New fee in basis points
     */
    function updateRelayerFee(
        uint256 newFeeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newFeeBps <= MAX_RELAYER_FEE_BPS, "Fee too high");
        relayerFeeBps = newFeeBps;
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Update emergency council
     * @param newCouncil New emergency council address
     */
    function updateEmergencyCouncil(
        address newCouncil
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(GUARDIAN_ROLE, emergencyCouncil);
        emergencyCouncil = newCouncil;
        _grantRole(GUARDIAN_ROLE, newCouncil);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get exit by ID
     * @param exitId Exit ID
     * @return exit Exit data
     */
    function getExit(
        uint256 exitId
    ) external view returns (PlasmaPrimitives.Exit memory) {
        return exits[exitId];
    }

    /**
     * @notice Get block by number
     * @param blockNum Block number
     * @return plasmaBlock Block data
     */
    function getBlock(
        uint256 blockNum
    ) external view returns (PlasmaPrimitives.PlasmaBlock memory) {
        return blocks[blockNum];
    }

    /**
     * @notice Get deposit by commitment
     * @param commitment Deposit commitment
     * @return depositData Deposit data
     */
    function getDeposit(
        bytes32 commitment
    ) external view returns (PlasmaPrimitives.Deposit memory) {
        return deposits[commitment];
    }

    /**
     * @notice Check if nullifier is consumed
     * @param nullifier Nullifier to check
     * @return consumed True if consumed
     */
    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool) {
        return nullifierConsumed[nullifier];
    }

    /**
     * @notice Get exit queue length
     * @return length Queue length
     */
    function getExitQueueLength() external view returns (uint256) {
        return exitQueue.length;
    }

    /**
     * @notice Get today's volume
     * @return volume Daily volume
     */
    function getTodayVolume() external view returns (uint256) {
        uint256 today = block.timestamp / 1 days;
        if (today != lastVolumeResetDay) {
            return 0;
        }
        return dailyVolume;
    }

    /**
     * @notice Get bridge statistics
     * @return _currentBlockNumber Current block number
     * @return _totalValueLocked Total value locked
     * @return _exitQueueLength Exit queue length
     * @return _circuitBreakerActive Circuit breaker status
     */
    function getStats()
        external
        view
        returns (
            uint256 _currentBlockNumber,
            uint256 _totalValueLocked,
            uint256 _exitQueueLength,
            bool _circuitBreakerActive
        )
    {
        return (
            currentBlockNumber,
            totalValueLocked,
            exitQueue.length,
            circuitBreakerActive
        );
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Update daily volume tracking
     */
    function _updateDailyVolume() internal {
        uint256 today = block.timestamp / 1 days;
        if (today != lastVolumeResetDay) {
            dailyVolume = 0;
            lastVolumeResetDay = today;
        }
    }

    /**
     * @notice Insert into exit queue (sorted)
     * @param priority Priority to insert
     */
    function _insertExitQueue(uint256 priority) internal {
        exitQueue.push(priority);
        // Simple insertion sort for small queues
        uint256 i = exitQueue.length - 1;
        while (i > 0 && exitQueue[i] < exitQueue[i - 1]) {
            (exitQueue[i], exitQueue[i - 1]) = (exitQueue[i - 1], exitQueue[i]);
            i--;
        }
    }

    /**
     * @notice Remove from exit queue
     * @param index Index to remove
     */
    function _removeFromExitQueue(uint256 index) internal {
        require(index < exitQueue.length, "Index out of bounds");
        for (uint256 i = index; i < exitQueue.length - 1; i++) {
            exitQueue[i] = exitQueue[i + 1];
        }
        exitQueue.pop();
    }

    /**
     * @notice Find exit ID by UTXO position
     * @param utxoPos UTXO position
     * @return exitId Exit ID (0 if not found)
     */
    function _findExitByUtxoPos(
        uint256 utxoPos
    ) internal view returns (uint256) {
        for (uint256 i = 1; i < nextExitId; i++) {
            if (
                exits[i].utxoPos == utxoPos &&
                exits[i].status == PlasmaPrimitives.ExitStatus.IN_PROGRESS
            ) {
                return i;
            }
        }
        return 0;
    }

    /**
     * @notice Extract amount from transaction bytes
     * @param txBytes Transaction bytes
     * @return amount Amount
     */
    function _extractAmountFromTx(
        bytes calldata txBytes
    ) internal pure returns (uint256) {
        // Simplified - actual implementation would decode properly
        if (txBytes.length >= 32) {
            return uint256(bytes32(txBytes[txBytes.length - 32:]));
        }
        return 0;
    }

    /**
     * @notice Extract spending position from transaction
     * @param txBytes Transaction bytes
     * @return blockNum Block number
     * @return txIndex Transaction index
     * @return outputIndex Output index
     */
    function _extractSpendingPosition(
        bytes calldata txBytes
    )
        internal
        pure
        returns (uint256 blockNum, uint256 txIndex, uint256 outputIndex)
    {
        // Simplified - actual implementation would decode properly
        if (txBytes.length >= 96) {
            blockNum = uint256(bytes32(txBytes[0:32]));
            txIndex = uint256(bytes32(txBytes[32:64]));
            outputIndex = uint256(bytes32(txBytes[64:96]));
        }
    }

    /**
     * @notice Authorize upgrade
     * @param newImplementation New implementation address
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
