// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IBatchAccumulator
 * @notice Interface for the BatchAccumulator privacy transaction batching contract
 * @dev Aggregates transactions into batches to prevent timing correlation attacks
 */
interface IBatchAccumulator {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum BatchStatus {
        ACCUMULATING,
        READY,
        PROCESSING,
        COMPLETED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct RouteConfig {
        uint256 minBatchSize;
        uint256 maxWaitTime;
        bool isActive;
    }

    struct BatchedTransaction {
        bytes32 commitment;
        bytes32 nullifierHash;
        bytes encryptedPayload;
        uint256 submittedAt;
        address submitter;
        bool processed;
    }

    struct Batch {
        bytes32 batchId;
        uint256 sourceChainId;
        uint256 targetChainId;
        bytes32[] commitments;
        uint256 createdAt;
        uint256 readyAt;
        BatchStatus status;
        bytes32 aggregateProofHash;
        uint256 processedAt;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BatchCreated(
        bytes32 indexed batchId,
        uint256 indexed sourceChainId,
        uint256 indexed targetChainId,
        uint256 minSize,
        uint256 maxWaitTime
    );

    event TransactionAdded(
        bytes32 indexed batchId,
        bytes32 indexed commitment,
        uint256 batchSize,
        uint256 remaining
    );

    event BatchReady(bytes32 indexed batchId, uint256 size, string reason);

    event BatchProcessing(bytes32 indexed batchId, address indexed relayer);

    event BatchCompleted(
        bytes32 indexed batchId,
        bytes32 aggregateProofHash,
        uint256 processedCount
    );

    event BatchFailed(bytes32 indexed batchId, string reason);

    event RouteConfigured(
        bytes32 indexed routeHash,
        uint256 minBatchSize,
        uint256 maxWaitTime
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidChainId();
    error InvalidPayloadSize();
    error CommitmentAlreadyUsed();
    error NullifierAlreadyUsed();
    error BatchNotFound();
    error BatchNotReady();
    error BatchAlreadyProcessing();
    error BatchAlreadyCompleted();
    error InvalidBatchSize();
    error InvalidWaitTime();
    error RouteNotActive();
    error InvalidProof();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function OPERATOR_ROLE() external view returns (bytes32);

    function RELAYER_ROLE() external view returns (bytes32);

    function UPGRADER_ROLE() external view returns (bytes32);

    function DEFAULT_MIN_BATCH_SIZE() external view returns (uint256);

    function MAX_BATCH_SIZE() external view returns (uint256);

    function DEFAULT_MAX_WAIT_TIME() external view returns (uint256);

    function MIN_WAIT_TIME() external view returns (uint256);

    function MAX_WAIT_TIME() external view returns (uint256);

    function FIXED_PAYLOAD_SIZE() external view returns (uint256);

    function totalBatches() external view returns (uint256);

    function totalTransactionsBatched() external view returns (uint256);

    function proofVerifier() external view returns (address);

    function crossChainHub() external view returns (address);

    function activeBatches(bytes32 routeHash) external view returns (bytes32);

    function commitmentToBatch(
        bytes32 commitment
    ) external view returns (bytes32);

    function nullifierUsed(bytes32 nullifierHash) external view returns (bool);

    /*//////////////////////////////////////////////////////////////
                        INITIALIZER
    //////////////////////////////////////////////////////////////*/

    function initialize(
        address admin,
        address _proofVerifier,
        address _crossChainHub
    ) external;

    /*//////////////////////////////////////////////////////////////
                      CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function configureRoute(
        uint256 sourceChainId,
        uint256 targetChainId,
        uint256 minBatchSize,
        uint256 maxWaitTime
    ) external;

    function deactivateRoute(
        uint256 sourceChainId,
        uint256 targetChainId
    ) external;

    /*//////////////////////////////////////////////////////////////
                      BATCH SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function submitToBatch(
        bytes32 commitment,
        bytes32 nullifierHash,
        bytes calldata encryptedPayload,
        uint256 targetChainId
    ) external returns (bytes32 batchId);

    /*//////////////////////////////////////////////////////////////
                       BATCH RELEASE
    //////////////////////////////////////////////////////////////*/

    function releaseBatch(bytes32 batchId) external;

    function forceReleaseBatch(bytes32 batchId) external;

    /*//////////////////////////////////////////////////////////////
                      BATCH PROCESSING
    //////////////////////////////////////////////////////////////*/

    function processBatch(
        bytes32 batchId,
        bytes calldata aggregateProof
    ) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getBatchInfo(
        bytes32 batchId
    )
        external
        view
        returns (
            uint256 size,
            uint256 age,
            BatchStatus status,
            bool isReady,
            uint256 targetChainId
        );

    function getActiveBatch(
        uint256 sourceChainId,
        uint256 targetChainId
    )
        external
        view
        returns (
            bytes32 batchId,
            uint256 currentSize,
            uint256 minSize,
            uint256 timeRemaining
        );

    function getTransactionByCommitment(
        bytes32 commitment
    )
        external
        view
        returns (
            bytes32 batchId,
            uint256 submittedAt,
            bool processed,
            BatchStatus batchStatus
        );

    function getAnonymitySet(
        bytes32 commitment
    ) external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external;

    function unpause() external;

    function setProofVerifier(address _proofVerifier) external;

    function setCrossChainHub(address _crossChainHub) external;
}
