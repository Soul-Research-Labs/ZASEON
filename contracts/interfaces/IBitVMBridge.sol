// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IBitVMBridge
 * @notice Interface for BitVM-based trust-minimized Bitcoin bridge
 */
interface IBitVMBridge {
    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum DepositState {
        PENDING,
        COMMITTED,
        CHALLENGED,
        FINALIZED,
        SLASHED,
        REFUNDED
    }

    enum ChallengeState {
        OPEN,
        RESPONDED,
        ESCALATED,
        PROVER_WON,
        CHALLENGER_WON,
        EXPIRED
    }

    enum GateType {
        NAND,
        AND,
        OR,
        XOR,
        NOT
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice BitVM deposit with circuit commitment
    struct BitVMDeposit {
        bytes32 depositId;
        address depositor;
        address prover;
        uint256 amount;
        uint256 stake;
        bytes32 circuitCommitment;
        bytes32 taprootPubKey;
        bytes32 outputCommitment;
        DepositState state;
        uint256 initiatedAt;
        uint256 finalizedAt;
        uint256 challengeDeadline;
    }

    /// @notice Challenge to a prover's claim
    struct Challenge {
        bytes32 challengeId;
        bytes32 depositId;
        address challenger;
        bytes32 gateId;
        uint256 gateIndex;
        uint256 stake;
        uint256 deadline;
        uint256 responseDeadline;
        bytes32 expectedOutput;
        bytes32 claimedOutput;
        ChallengeState state;
        uint256 createdAt;
        uint256 resolvedAt;
    }

    /// @notice Logic gate commitment
    struct GateCommitment {
        bytes32 gateId;
        GateType gateType;
        bytes32 inputA;
        bytes32 inputB;
        bytes32 output;
        bytes32 hashlock;
        bool revealed;
    }

    /// @notice Bit commitment (hash-based)
    struct BitCommitment {
        bytes32 commitmentId;
        bytes32 hash0;  // H(preimage || 0)
        bytes32 hash1;  // H(preimage || 1)
        bool revealed;
        uint8 value;
        bytes32 preimage;
    }

    /// @notice Circuit metadata
    struct CircuitInfo {
        bytes32 circuitId;
        uint256 numGates;
        uint256 numInputs;
        uint256 numOutputs;
        bytes32 merkleRoot;
        bool verified;
    }

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    // Deposit events
    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed depositor,
        uint256 amount,
        bytes32 circuitCommitment
    );
    event DepositCommitted(
        bytes32 indexed depositId,
        address indexed prover,
        bytes32 taprootPubKey
    );
    event DepositFinalized(bytes32 indexed depositId, address indexed recipient);
    event DepositSlashed(bytes32 indexed depositId, address indexed challenger);
    event DepositRefunded(bytes32 indexed depositId, address indexed depositor);

    // Challenge events
    event ChallengeOpened(
        bytes32 indexed challengeId,
        bytes32 indexed depositId,
        address indexed challenger,
        bytes32 gateId
    );
    event ChallengeResponded(bytes32 indexed challengeId, bytes32 response);
    event ChallengeEscalated(bytes32 indexed challengeId, uint256 newGateIndex);
    event FraudProven(bytes32 indexed challengeId, address indexed challenger);
    event ChallengeResolved(bytes32 indexed challengeId, bool proverWon);
    event ChallengeExpired(bytes32 indexed challengeId);

    // Gate events
    event GateCommitted(bytes32 indexed gateId, GateType gateType);
    event GateRevealed(bytes32 indexed gateId, uint8 inputA, uint8 inputB, uint8 output);
    event BitCommitmentRevealed(bytes32 indexed commitmentId, uint8 value);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ZeroAmount();
    error InsufficientStake();
    error InvalidCircuitCommitment();
    error InvalidTaprootKey();
    
    error DepositNotFound(bytes32 depositId);
    error InvalidDepositState(bytes32 depositId, DepositState state);
    error DepositAlreadyCommitted(bytes32 depositId);
    error ChallengeDeadlineNotPassed(bytes32 depositId);
    error ChallengeDeadlinePassed(bytes32 depositId);

    error ChallengeNotFound(bytes32 challengeId);
    error InvalidChallengeState(bytes32 challengeId, ChallengeState state);
    error ChallengeAlreadyOpen(bytes32 depositId);
    error NotChallenger(bytes32 challengeId);
    error NotProver(bytes32 depositId);
    error ResponseDeadlinePassed(bytes32 challengeId);
    error ChallengeNotExpired(bytes32 challengeId);

    error InvalidGateCommitment(bytes32 gateId);
    error GateNotFound(bytes32 gateId);
    error GateAlreadyRevealed(bytes32 gateId);
    error InvalidGateOutput(bytes32 gateId);
    error InvalidBitCommitment(bytes32 commitmentId);
    error BitAlreadyRevealed(bytes32 commitmentId);

    error InvalidMerkleProof();
    error InvalidPreimage();
    error InvalidSignature();

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    // Deposit lifecycle
    function initiateDeposit(
        uint256 amount,
        bytes32 circuitCommitment,
        address prover
    ) external payable returns (bytes32 depositId);

    function commitDeposit(
        bytes32 depositId,
        bytes32 taprootPubKey,
        bytes32 outputCommitment
    ) external payable;

    function finalizeDeposit(bytes32 depositId) external;

    function refundDeposit(bytes32 depositId) external;

    // Challenge lifecycle
    function openChallenge(
        bytes32 depositId,
        bytes32 gateId,
        bytes32 expectedOutput
    ) external payable returns (bytes32 challengeId);

    function respondToChallenge(
        bytes32 challengeId,
        bytes32 response,
        bytes calldata proof
    ) external;

    function escalateChallenge(
        bytes32 challengeId,
        bytes32 newGateId
    ) external;

    function resolveChallengeTimeout(bytes32 challengeId) external;

    function proveFraud(
        bytes32 challengeId,
        bytes32 gateId,
        uint8 inputA,
        uint8 inputB,
        bytes32 preimageA,
        bytes32 preimageB
    ) external;

    // Gate management
    function commitGate(
        bytes32 gateId,
        GateType gateType,
        bytes32 inputA,
        bytes32 inputB,
        bytes32 output
    ) external;

    function revealGate(
        bytes32 gateId,
        uint8 inputAValue,
        uint8 inputBValue,
        bytes32 preimageA,
        bytes32 preimageB
    ) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDeposit(bytes32 depositId) external view returns (BitVMDeposit memory);
    function getChallenge(bytes32 challengeId) external view returns (Challenge memory);
    function getGateCommitment(bytes32 gateId) external view returns (GateCommitment memory);
    function getCircuitInfo(bytes32 circuitId) external view returns (CircuitInfo memory);
}
