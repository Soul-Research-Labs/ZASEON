// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "../alpen/AlpenPrimitives.sol";

/**
 * @title AlpenBridgeAdapter
 * @notice Bridge adapter for Alpen Network - Bitcoin L2 with BitVM
 * @dev Supports BTC peg-in/peg-out with BitVM verification and STARK proofs
 * @author PIL Protocol Team
 * @custom:security-contact security@pil.network
 *
 * Architecture:
 * - BitVM: Trust-minimized bridging via optimistic verification
 * - Operator Committee: 5-of-9 multi-sig for peg operations
 * - STARK Proofs: Validity proofs for zkEVM state transitions
 * - Cross-domain Nullifiers: Prevent double-spending across chains
 */
contract AlpenBridgeAdapter is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using AlpenPrimitives for *;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 public constant MAX_OPERATORS = 15;
    uint256 public constant MIN_OPERATORS = 5;
    uint256 public constant OPERATOR_THRESHOLD = 5; // 5-of-9 multisig

    uint256 public constant CHALLENGE_PERIOD = 7 days;
    uint256 public constant FINALITY_BLOCKS = 6;
    uint256 public constant SATOSHI_DECIMALS = 8;

    uint256 public constant MIN_DEPOSIT = 10000; // 0.0001 BTC in satoshis
    uint256 public constant MAX_DEPOSIT = 100_000_000_000; // 1000 BTC in satoshis
    uint256 public constant MAX_DAILY_VOLUME = 10000 ether; // Daily limit
    uint256 public constant MAX_RELAYER_FEE_BPS = 500; // 5%

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Network identifier
    uint256 public networkId;

    /// @notice Registered operators
    mapping(bytes32 => AlpenPrimitives.Operator) public operators;
    bytes32[] public operatorKeys;

    /// @notice Peg-in records
    mapping(bytes32 => AlpenPrimitives.PegIn) public pegIns;
    bytes32[] public pegInIds;

    /// @notice Peg-out records
    mapping(bytes32 => AlpenPrimitives.PegOut) public pegOuts;
    bytes32[] public pegOutIds;

    /// @notice BitVM programs
    mapping(bytes32 => AlpenPrimitives.BitVMProgram) public programs;

    /// @notice BitVM challenges
    mapping(bytes32 => AlpenPrimitives.BitVMChallenge) public challenges;

    /// @notice Verified batches
    mapping(uint64 => AlpenPrimitives.Batch) public batches;
    uint64 public latestBatchNumber;

    /// @notice Nullifier tracking
    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => bytes32) public crossDomainNullifiers;

    /// @notice Bitcoin block headers
    mapping(bytes32 => AlpenPrimitives.BitcoinBlockHeader) public btcHeaders;
    bytes32 public latestBtcBlockHash;
    uint64 public latestBtcBlockHeight;

    /// @notice Daily volume tracking
    mapping(uint256 => uint256) public dailyVolume;

    /// @notice Relayer fee (basis points)
    uint256 public relayerFeeBps;

    /// @notice Circuit breaker
    bool public circuitBreakerActive;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event OperatorRegistered(
        bytes32 indexed pubkeyHash,
        address evmAddress,
        uint256 stake
    );
    event OperatorRemoved(bytes32 indexed pubkeyHash);
    event PegInInitiated(
        bytes32 indexed pegInId,
        bytes32 btcTxid,
        uint64 amount,
        address recipient
    );
    event PegInConfirmed(bytes32 indexed pegInId, uint256 confirmations);
    event PegInCompleted(
        bytes32 indexed pegInId,
        address recipient,
        uint256 amount
    );
    event PegOutInitiated(
        bytes32 indexed pegOutId,
        address sender,
        bytes btcDestination,
        uint64 amount
    );
    event PegOutSigned(bytes32 indexed pegOutId, uint256 signatureCount);
    event PegOutCompleted(bytes32 indexed pegOutId, bytes32 btcTxid);
    event BatchSubmitted(uint64 indexed batchNumber, bytes32 batchHash);
    event BatchVerified(uint64 indexed batchNumber, bytes32 proofHash);
    event BatchFinalized(uint64 indexed batchNumber);
    event BitVMProgramRegistered(bytes32 indexed programHash, uint32 numGates);
    event ChallengeInitiated(
        bytes32 indexed challengeId,
        bytes32 programHash,
        address challenger
    );
    event ChallengeResponded(bytes32 indexed challengeId, address responder);
    event ChallengeResolved(bytes32 indexed challengeId, bool challengerWon);
    event NullifierRegistered(bytes32 indexed nullifier, bytes32 btcTxid);
    event CrossDomainNullifierBound(
        bytes32 indexed alpenNullifier,
        bytes32 pilNullifier
    );
    event BtcHeaderSubmitted(bytes32 indexed blockHash, uint64 height);
    event CircuitBreakerActivated(address activator);
    event CircuitBreakerDeactivated(address deactivator);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidOperator();
    error OperatorAlreadyRegistered();
    error OperatorNotFound();
    error MaxOperatorsReached();
    error InsufficientOperators();
    error InvalidPegIn();
    error PegInNotFound();
    error PegInAlreadyProcessed();
    error InvalidPegOut();
    error PegOutNotFound();
    error InsufficientSignatures();
    error InvalidBatch();
    error BatchNotFound();
    error BatchNotVerified();
    error InvalidSTARKProof();
    error InvalidBitVMProgram();
    error ChallengeNotFound();
    error ChallengeExpired();
    error ChallengeNotActive();
    error NullifierAlreadyUsed();
    error InvalidBlockHeader();
    error InsufficientConfirmations();
    error AmountTooLow();
    error AmountTooHigh();
    error DailyLimitExceeded();
    error CircuitBreakerActive();
    error InvalidRelayerFee();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier whenCircuitBreakerInactive() {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        _;
    }

    modifier validAmount(uint64 amount) {
        if (amount < MIN_DEPOSIT) revert AmountTooLow();
        if (amount > MAX_DEPOSIT) revert AmountTooHigh();
        _;
    }

    modifier checkDailyLimit(uint256 amount) {
        uint256 day = block.timestamp / 1 days;
        if (dailyVolume[day] + amount > MAX_DAILY_VOLUME)
            revert DailyLimitExceeded();
        _;
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the bridge adapter
     * @param _networkId Network identifier (1 = mainnet, 2 = testnet)
     * @param admin Admin address
     */
    function initialize(
        uint256 _networkId,
        address admin
    ) external initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        networkId = _networkId;
        relayerFeeBps = 100; // 1% default

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    // =========================================================================
    // OPERATOR MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a new operator
     * @param pubkey Schnorr public key
     * @param evmAddress EVM address
     */
    function registerOperator(
        AlpenPrimitives.SchnorrPubkey calldata pubkey,
        address evmAddress
    ) external payable onlyRole(ADMIN_ROLE) {
        bytes32 pubkeyHash = keccak256(abi.encodePacked(pubkey.x));

        if (operators[pubkeyHash].active) revert OperatorAlreadyRegistered();
        if (operatorKeys.length >= MAX_OPERATORS) revert MaxOperatorsReached();
        if (evmAddress == address(0)) revert InvalidOperator();

        operators[pubkeyHash] = AlpenPrimitives.Operator({
            pubkey: pubkey,
            evmAddress: evmAddress,
            stake: msg.value,
            active: true,
            registeredAt: block.timestamp
        });
        operatorKeys.push(pubkeyHash);

        _grantRole(OPERATOR_ROLE, evmAddress);

        emit OperatorRegistered(pubkeyHash, evmAddress, msg.value);
    }

    /**
     * @notice Remove an operator
     * @param pubkeyHash Operator public key hash
     */
    function removeOperator(bytes32 pubkeyHash) external onlyRole(ADMIN_ROLE) {
        AlpenPrimitives.Operator storage op = operators[pubkeyHash];
        if (!op.active) revert OperatorNotFound();

        uint256 activeCount = getActiveOperatorCount();
        if (activeCount <= MIN_OPERATORS) revert InsufficientOperators();

        op.active = false;
        _revokeRole(OPERATOR_ROLE, op.evmAddress);

        // Return stake
        if (op.stake > 0) {
            uint256 stake = op.stake;
            op.stake = 0;
            payable(op.evmAddress).transfer(stake);
        }

        emit OperatorRemoved(pubkeyHash);
    }

    /**
     * @notice Get active operator count
     * @return count Number of active operators
     */
    function getActiveOperatorCount() public view returns (uint256 count) {
        for (uint256 i = 0; i < operatorKeys.length; i++) {
            if (operators[operatorKeys[i]].active) {
                count++;
            }
        }
    }

    // =========================================================================
    // PEG-IN (BTC -> ALPEN)
    // =========================================================================

    /**
     * @notice Initiate a peg-in
     * @param btcTxid Bitcoin transaction ID
     * @param amount Amount in satoshis
     * @param recipient Recipient address
     * @param proof Merkle proof for transaction inclusion
     */
    function initiatePegIn(
        bytes32 btcTxid,
        uint64 amount,
        address recipient,
        AlpenPrimitives.MerkleProof calldata proof
    )
        external
        whenNotPaused
        whenCircuitBreakerInactive
        validAmount(amount)
        nonReentrant
    {
        bytes32 pegInId = AlpenPrimitives.computePegInId(
            btcTxid,
            recipient,
            amount
        );

        if (pegIns[pegInId].btcTxid != bytes32(0))
            revert PegInAlreadyProcessed();
        if (!AlpenPrimitives.verifyMerkleProof(proof)) revert InvalidPegIn();

        pegIns[pegInId] = AlpenPrimitives.PegIn({
            pegInId: pegInId,
            btcTxid: btcTxid,
            amount: amount,
            recipient: recipient,
            inclusionProof: proof,
            confirmations: 0,
            status: AlpenPrimitives.PegStatus.PENDING
        });
        pegInIds.push(pegInId);

        emit PegInInitiated(pegInId, btcTxid, amount, recipient);
    }

    /**
     * @notice Confirm peg-in with block confirmations
     * @param pegInId Peg-in identifier
     * @param confirmations Number of confirmations
     */
    function confirmPegIn(
        bytes32 pegInId,
        uint256 confirmations
    ) external onlyRole(OPERATOR_ROLE) {
        AlpenPrimitives.PegIn storage pegIn = pegIns[pegInId];
        if (pegIn.btcTxid == bytes32(0)) revert PegInNotFound();
        if (pegIn.status != AlpenPrimitives.PegStatus.PENDING)
            revert PegInAlreadyProcessed();

        pegIn.confirmations = confirmations;

        if (confirmations >= FINALITY_BLOCKS) {
            pegIn.status = AlpenPrimitives.PegStatus.CONFIRMED;
        }

        emit PegInConfirmed(pegInId, confirmations);
    }

    /**
     * @notice Complete peg-in and mint tokens
     * @param pegInId Peg-in identifier
     */
    function completePegIn(
        bytes32 pegInId
    )
        external
        whenNotPaused
        whenCircuitBreakerInactive
        nonReentrant
        checkDailyLimit(pegIns[pegInId].amount * 1e10) // Convert satoshis to wei-like
    {
        AlpenPrimitives.PegIn storage pegIn = pegIns[pegInId];
        if (pegIn.btcTxid == bytes32(0)) revert PegInNotFound();
        if (pegIn.status != AlpenPrimitives.PegStatus.CONFIRMED)
            revert InvalidPegIn();
        if (pegIn.confirmations < FINALITY_BLOCKS)
            revert InsufficientConfirmations();

        pegIn.status = AlpenPrimitives.PegStatus.COMPLETED;

        // Register nullifier
        bytes32 nullifier = AlpenPrimitives.deriveAlpenNullifier(
            pegIn.btcTxid,
            0, // vout
            latestBtcBlockHeight
        );
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed();
        nullifiers[nullifier] = true;

        // Update daily volume
        uint256 day = block.timestamp / 1 days;
        dailyVolume[day] += pegIn.amount * 1e10;

        // Mint would happen here in real implementation
        emit PegInCompleted(pegInId, pegIn.recipient, pegIn.amount);
        emit NullifierRegistered(nullifier, pegIn.btcTxid);
    }

    // =========================================================================
    // PEG-OUT (ALPEN -> BTC)
    // =========================================================================

    /**
     * @notice Initiate a peg-out
     * @param btcDestination Bitcoin destination script
     * @param amount Amount in satoshis
     */
    function initiatePegOut(
        bytes calldata btcDestination,
        uint64 amount
    )
        external
        payable
        whenNotPaused
        whenCircuitBreakerInactive
        validAmount(amount)
        nonReentrant
    {
        bytes32 pegOutId = AlpenPrimitives.computePegOutId(
            msg.sender,
            btcDestination,
            amount,
            pegOutIds.length
        );

        pegOuts[pegOutId] = AlpenPrimitives.PegOut({
            pegOutId: pegOutId,
            sender: msg.sender,
            btcDestination: btcDestination,
            amount: amount,
            operatorSignatures: new bytes32[](0),
            timestamp: block.timestamp,
            status: AlpenPrimitives.PegStatus.PENDING
        });
        pegOutIds.push(pegOutId);

        emit PegOutInitiated(pegOutId, msg.sender, btcDestination, amount);
    }

    /**
     * @notice Sign a peg-out as operator
     * @param pegOutId Peg-out identifier
     * @param signature Operator signature
     */
    function signPegOut(
        bytes32 pegOutId,
        bytes32 signature
    ) external onlyRole(OPERATOR_ROLE) {
        AlpenPrimitives.PegOut storage pegOut = pegOuts[pegOutId];
        if (pegOut.sender == address(0)) revert PegOutNotFound();
        if (pegOut.status != AlpenPrimitives.PegStatus.PENDING)
            revert InvalidPegOut();

        // Add signature (simplified - real impl would verify)
        bytes32[] storage sigs = pegOut.operatorSignatures;

        // Check if already signed by this operator
        bytes32 operatorId = keccak256(abi.encodePacked(msg.sender));
        for (uint256 i = 0; i < sigs.length; i++) {
            if (sigs[i] == operatorId) revert InvalidOperator();
        }

        // Store operator ID as placeholder for signature verification
        pegOuts[pegOutId].operatorSignatures.push(signature);

        emit PegOutSigned(
            pegOutId,
            pegOuts[pegOutId].operatorSignatures.length
        );

        // Check threshold
        if (pegOuts[pegOutId].operatorSignatures.length >= OPERATOR_THRESHOLD) {
            pegOut.status = AlpenPrimitives.PegStatus.CONFIRMED;
        }
    }

    /**
     * @notice Complete peg-out with Bitcoin transaction
     * @param pegOutId Peg-out identifier
     * @param btcTxid Bitcoin transaction ID
     */
    function completePegOut(
        bytes32 pegOutId,
        bytes32 btcTxid
    ) external onlyRole(OPERATOR_ROLE) {
        AlpenPrimitives.PegOut storage pegOut = pegOuts[pegOutId];
        if (pegOut.sender == address(0)) revert PegOutNotFound();
        if (pegOut.status != AlpenPrimitives.PegStatus.CONFIRMED)
            revert InvalidPegOut();

        pegOut.status = AlpenPrimitives.PegStatus.COMPLETED;

        emit PegOutCompleted(pegOutId, btcTxid);
    }

    // =========================================================================
    // BITVM
    // =========================================================================

    /**
     * @notice Register a BitVM program
     * @param program BitVM program data
     */
    function registerProgram(
        AlpenPrimitives.BitVMProgram calldata program
    ) external onlyRole(PROVER_ROLE) {
        bytes32 programHash = AlpenPrimitives.computeProgramHash(program);
        if (programs[programHash].programHash != bytes32(0))
            revert InvalidBitVMProgram();

        programs[programHash] = program;

        emit BitVMProgramRegistered(programHash, uint32(program.gates.length));
    }

    /**
     * @notice Initiate a BitVM challenge
     * @param programHash Program being challenged
     * @param gateIndex Gate index to challenge
     * @param inputCommitment Expected input commitment
     * @param outputCommitment Expected output commitment
     */
    function initiateChallenge(
        bytes32 programHash,
        uint32 gateIndex,
        bytes32 inputCommitment,
        bytes32 outputCommitment
    ) external onlyRole(CHALLENGER_ROLE) whenNotPaused {
        if (programs[programHash].programHash == bytes32(0))
            revert InvalidBitVMProgram();

        bytes32 challengeId = keccak256(
            abi.encodePacked(
                programHash,
                gateIndex,
                msg.sender,
                block.timestamp
            )
        );

        challenges[challengeId] = AlpenPrimitives.BitVMChallenge({
            challengeId: challengeId,
            programHash: programHash,
            gateIndex: gateIndex,
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            challenger: msg.sender,
            deadline: block.timestamp + CHALLENGE_PERIOD,
            status: AlpenPrimitives.ChallengeStatus.PENDING
        });

        emit ChallengeInitiated(challengeId, programHash, msg.sender);
    }

    /**
     * @notice Respond to a BitVM challenge
     * @param challengeId Challenge identifier
     * @param response Challenge response (gate evaluation proof)
     */
    function respondToChallenge(
        bytes32 challengeId,
        bytes calldata response
    ) external onlyRole(PROVER_ROLE) {
        AlpenPrimitives.BitVMChallenge storage challenge = challenges[
            challengeId
        ];
        if (challenge.challengeId == bytes32(0)) revert ChallengeNotFound();
        if (!AlpenPrimitives.isChallengeActive(challenge))
            revert ChallengeNotActive();

        // Verify response (simplified)
        // Real implementation would verify gate computation
        challenge.status = AlpenPrimitives.ChallengeStatus.RESPONDED;

        emit ChallengeResponded(challengeId, msg.sender);
    }

    /**
     * @notice Resolve an expired challenge
     * @param challengeId Challenge identifier
     */
    function resolveChallenge(bytes32 challengeId) external {
        AlpenPrimitives.BitVMChallenge storage challenge = challenges[
            challengeId
        ];
        if (challenge.challengeId == bytes32(0)) revert ChallengeNotFound();
        if (challenge.status == AlpenPrimitives.ChallengeStatus.RESOLVED)
            revert ChallengeNotActive();

        bool challengerWon = false;

        if (
            challenge.status == AlpenPrimitives.ChallengeStatus.PENDING &&
            block.timestamp > challenge.deadline
        ) {
            // Challenger wins if no response
            challengerWon = true;
            challenge.status = AlpenPrimitives.ChallengeStatus.SLASHED;
        } else if (
            challenge.status == AlpenPrimitives.ChallengeStatus.RESPONDED
        ) {
            // Prover successfully responded
            challenge.status = AlpenPrimitives.ChallengeStatus.RESOLVED;
        }

        emit ChallengeResolved(challengeId, challengerWon);
    }

    // =========================================================================
    // BATCH MANAGEMENT (ZKEVM)
    // =========================================================================

    /**
     * @notice Submit a new batch
     * @param batch Batch data
     */
    function submitBatch(
        AlpenPrimitives.Batch calldata batch
    ) external onlyRole(PROVER_ROLE) whenNotPaused whenCircuitBreakerInactive {
        if (batch.batchNumber != latestBatchNumber + 1) revert InvalidBatch();
        if (!AlpenPrimitives.isValidSTARKProof(batch.proof))
            revert InvalidSTARKProof();

        batches[batch.batchNumber] = batch;
        batches[batch.batchNumber].status = AlpenPrimitives.BatchStatus.PENDING;

        emit BatchSubmitted(batch.batchNumber, batch.batchHash);
    }

    /**
     * @notice Verify a batch with STARK proof
     * @param batchNumber Batch number to verify
     */
    function verifyBatch(uint64 batchNumber) external onlyRole(PROVER_ROLE) {
        AlpenPrimitives.Batch storage batch = batches[batchNumber];
        if (batch.batchNumber == 0) revert BatchNotFound();
        if (batch.status != AlpenPrimitives.BatchStatus.PENDING)
            revert InvalidBatch();

        // STARK proof verification would happen here
        // This is simplified - real impl uses verifier contract
        batch.status = AlpenPrimitives.BatchStatus.VERIFIED;

        emit BatchVerified(batchNumber, batch.proof.publicInputHash);
    }

    /**
     * @notice Finalize a verified batch
     * @param batchNumber Batch number to finalize
     */
    function finalizeBatch(
        uint64 batchNumber
    ) external onlyRole(OPERATOR_ROLE) {
        AlpenPrimitives.Batch storage batch = batches[batchNumber];
        if (batch.batchNumber == 0) revert BatchNotFound();
        if (batch.status != AlpenPrimitives.BatchStatus.VERIFIED)
            revert BatchNotVerified();

        batch.status = AlpenPrimitives.BatchStatus.FINALIZED;
        latestBatchNumber = batchNumber;

        emit BatchFinalized(batchNumber);
    }

    // =========================================================================
    // BITCOIN HEADER MANAGEMENT
    // =========================================================================

    /**
     * @notice Submit a Bitcoin block header
     * @param header Block header data
     * @param height Block height
     */
    function submitBtcHeader(
        AlpenPrimitives.BitcoinBlockHeader calldata header,
        uint64 height
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 blockHash = AlpenPrimitives.computeBlockHash(header);

        // Verify connects to previous block
        if (
            latestBtcBlockHash != bytes32(0) &&
            header.prevBlockHash != latestBtcBlockHash
        ) {
            revert InvalidBlockHeader();
        }

        // Verify proof of work
        if (!AlpenPrimitives.isValidPoW(header)) {
            revert InvalidBlockHeader();
        }

        btcHeaders[blockHash] = header;
        latestBtcBlockHash = blockHash;
        latestBtcBlockHeight = height;

        emit BtcHeaderSubmitted(blockHash, height);
    }

    // =========================================================================
    // NULLIFIER MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a cross-domain nullifier binding
     * @param alpenNullifier Alpen network nullifier
     * @param pilDomain PIL domain identifier
     */
    function bindCrossDomainNullifier(
        bytes32 alpenNullifier,
        bytes32 pilDomain
    ) external onlyRole(OPERATOR_ROLE) {
        if (nullifiers[alpenNullifier] == false) revert NullifierAlreadyUsed();

        bytes32 pilNullifier = AlpenPrimitives.derivePILBinding(
            alpenNullifier,
            pilDomain
        );
        crossDomainNullifiers[alpenNullifier] = pilNullifier;

        emit CrossDomainNullifierBound(alpenNullifier, pilNullifier);
    }

    /**
     * @notice Check if nullifier is used
     * @param nullifier Nullifier hash
     * @return True if nullifier is used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /**
     * @notice Get cross-domain nullifier
     * @param alpenNullifier Alpen nullifier
     * @return PIL nullifier binding
     */
    function getCrossDomainNullifier(
        bytes32 alpenNullifier
    ) external view returns (bytes32) {
        return crossDomainNullifiers[alpenNullifier];
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    /**
     * @notice Activate circuit breaker
     */
    function activateCircuitBreaker() external onlyRole(PAUSER_ROLE) {
        circuitBreakerActive = true;
        emit CircuitBreakerActivated(msg.sender);
    }

    /**
     * @notice Deactivate circuit breaker
     */
    function deactivateCircuitBreaker() external onlyRole(ADMIN_ROLE) {
        circuitBreakerActive = false;
        emit CircuitBreakerDeactivated(msg.sender);
    }

    // =========================================================================
    // FEE MANAGEMENT
    // =========================================================================

    /**
     * @notice Set relayer fee
     * @param feeBps Fee in basis points
     */
    function setRelayerFee(uint256 feeBps) external onlyRole(ADMIN_ROLE) {
        if (feeBps > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();
        relayerFeeBps = feeBps;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get peg-in details
     * @param pegInId Peg-in identifier
     * @return Peg-in data
     */
    function getPegIn(
        bytes32 pegInId
    ) external view returns (AlpenPrimitives.PegIn memory) {
        return pegIns[pegInId];
    }

    /**
     * @notice Get peg-out details
     * @param pegOutId Peg-out identifier
     * @return Peg-out data
     */
    function getPegOut(
        bytes32 pegOutId
    ) external view returns (AlpenPrimitives.PegOut memory) {
        return pegOuts[pegOutId];
    }

    /**
     * @notice Get batch details
     * @param batchNumber Batch number
     * @return Batch data
     */
    function getBatch(
        uint64 batchNumber
    ) external view returns (AlpenPrimitives.Batch memory) {
        return batches[batchNumber];
    }

    /**
     * @notice Get challenge details
     * @param challengeId Challenge identifier
     * @return Challenge data
     */
    function getChallenge(
        bytes32 challengeId
    ) external view returns (AlpenPrimitives.BitVMChallenge memory) {
        return challenges[challengeId];
    }

    /**
     * @notice Get operator details
     * @param pubkeyHash Operator public key hash
     * @return Operator data
     */
    function getOperator(
        bytes32 pubkeyHash
    ) external view returns (AlpenPrimitives.Operator memory) {
        return operators[pubkeyHash];
    }

    /**
     * @notice Get daily volume
     * @param day Day timestamp (timestamp / 1 days)
     * @return Volume for that day
     */
    function getDailyVolume(uint256 day) external view returns (uint256) {
        return dailyVolume[day];
    }

    /**
     * @notice Get all operator keys
     * @return Array of operator public key hashes
     */
    function getOperatorKeys() external view returns (bytes32[] memory) {
        return operatorKeys;
    }

    /**
     * @notice Get all peg-in IDs
     * @return Array of peg-in IDs
     */
    function getPegInIds() external view returns (bytes32[] memory) {
        return pegInIds;
    }

    /**
     * @notice Get all peg-out IDs
     * @return Array of peg-out IDs
     */
    function getPegOutIds() external view returns (bytes32[] memory) {
        return pegOutIds;
    }

    // =========================================================================
    // PAUSE FUNCTIONS
    // =========================================================================

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    /**
     * @notice Authorize upgrade (UUPS pattern)
     * @param newImplementation New implementation address
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(ADMIN_ROLE) {}
}
