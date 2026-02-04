// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IStarknetBridgeAdapter
 * @notice Interface for Starknet L2 bridge adapter
 */
interface IStarknetBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        PENDING,
        MESSAGE_SENT,
        CONSUMED,
        FINALIZED,
        FAILED
    }

    enum MessageDirection {
        L1_TO_L2,
        L2_TO_L1
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Starknet configuration
    struct StarknetConfig {
        address starknetCore;       // Starknet core contract
        address starknetMessaging;  // Starknet messaging contract
        uint256 l2BridgeAddress;    // L2 bridge contract (felt)
        bool active;
    }

    /// @notice L1 to L2 deposit
    struct L1ToL2Deposit {
        bytes32 depositId;
        address sender;
        uint256 l2Recipient;        // L2 recipient (felt)
        address l1Token;
        uint256 l2Token;            // L2 token (felt)
        uint256 amount;
        uint256 nonce;
        bytes32 messageHash;
        TransferStatus status;
        uint256 initiatedAt;
        uint256 consumedAt;
    }

    /// @notice L2 to L1 withdrawal
    struct L2ToL1Withdrawal {
        bytes32 withdrawalId;
        uint256 l2Sender;           // L2 sender (felt)
        address l1Recipient;
        uint256 l2Token;            // L2 token (felt)
        address l1Token;
        uint256 amount;
        bytes32 messageHash;
        TransferStatus status;
        uint256 initiatedAt;
        uint256 claimedAt;
    }

    /// @notice Starknet message
    struct StarknetMessage {
        uint256 fromAddress;        // Sender (felt)
        uint256 toAddress;          // Recipient (felt)
        uint256[] payload;          // Message payload (felts)
        uint256 nonce;
        bytes32 messageHash;
    }

    /// @notice Token mapping
    struct TokenMapping {
        address l1Token;
        uint256 l2Token;            // L2 token contract (felt)
        uint8 decimals;
        uint256 totalDeposited;
        uint256 totalWithdrawn;
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event StarknetConfigured(address starknetCore, uint256 l2Bridge);
    
    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed sender,
        uint256 l2Recipient,
        uint256 amount,
        bytes32 messageHash
    );
    
    event DepositConsumed(bytes32 indexed depositId, bytes32 messageHash);
    
    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        uint256 l2Sender,
        address indexed l1Recipient,
        uint256 amount
    );
    
    event WithdrawalClaimed(bytes32 indexed withdrawalId);
    
    event TokenMapped(address indexed l1Token, uint256 l2Token);
    
    event MessageSent(
        bytes32 indexed messageHash,
        uint256 toAddress,
        uint256 selector,
        uint256[] payload
    );
    
    event MessageConsumed(bytes32 indexed messageHash, uint256 fromAddress);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error StarknetNotConfigured();
    error InvalidAmount();
    error ZeroAddress();
    error InvalidL2Address();
    error TokenNotMapped();
    error DepositNotFound();
    error WithdrawalNotFound();
    error MessageNotFound();
    error MessageAlreadyConsumed();
    error InvalidMessageHash();
    error InvalidProof();
    error InsufficientFee();

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    // Configuration
    function configure(
        address starknetCore,
        address starknetMessaging,
        uint256 l2BridgeAddress
    ) external;

    // Deposits (L1 → L2)
    function deposit(
        uint256 l2Recipient,
        address l1Token,
        uint256 amount
    ) external payable returns (bytes32 depositId);

    function depositETH(
        uint256 l2Recipient
    ) external payable returns (bytes32 depositId);

    // Withdrawals (L2 → L1)
    function claimWithdrawal(
        uint256 l2Sender,
        address l1Recipient,
        uint256 l2Token,
        uint256 amount,
        uint256[] calldata payload
    ) external returns (bytes32 withdrawalId);

    // Token mapping
    function mapToken(
        address l1Token,
        uint256 l2Token,
        uint8 decimals
    ) external;

    // Send arbitrary L1→L2 message
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    ) external payable returns (bytes32 messageHash);

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDeposit(bytes32 depositId) external view returns (L1ToL2Deposit memory);
    function getWithdrawal(bytes32 withdrawalId) external view returns (L2ToL1Withdrawal memory);
    function getTokenMapping(address l1Token) external view returns (TokenMapping memory);
    function computeMessageHash(
        uint256 fromAddress,
        uint256 toAddress,
        uint256[] calldata payload
    ) external pure returns (bytes32);
}
