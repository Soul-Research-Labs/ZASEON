// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/integrations/PrivateBridgeIntegration.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Mock proof verifier that returns configurable results via staticcall
contract MockBridgeProofVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool val) external {
        shouldVerify = val;
    }

    // Called by _verifyInitiateProof
    function verifyInitiateProof(
        bytes32, bytes32, uint256, uint256, bytes32, bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    // Called by _verifyRefundProof
    function verifyRefundProof(
        bytes32, bytes32, bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}

/// @notice Mock message verifier for cross-chain proof and relayer proof
contract MockMessageVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool val) external {
        shouldVerify = val;
    }

    function verifyCrossChainProof(
        bytes32, bytes32, uint256, uint256, bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifyRelayerProof(
        bytes32, bytes32, uint256, bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}

/// @notice Mock bridge adapter that accepts sendMessage calls
contract MockBridgeAdapter {
    bool public shouldSucceed = true;
    uint256 public lastDestChain;
    bytes public lastMessage;

    function setShouldSucceed(bool val) external {
        shouldSucceed = val;
    }

    function sendMessage(uint256 destChain, bytes calldata message) external payable {
        if (!shouldSucceed) revert("adapter failed");
        lastDestChain = destChain;
        lastMessage = message;
    }

    receive() external payable {}
}

/// @notice Simple ERC20 for testing
contract MockBridgeERC20 is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract PrivateBridgeIntegrationTest is Test {
    PrivateBridgeIntegration public bridge;
    MockBridgeProofVerifier public proofVerifier;
    MockMessageVerifier public msgVerifier;
    MockBridgeAdapter public adapter;
    MockBridgeERC20 public token;

    address public admin = address(this);
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");

    uint256 constant THIS_CHAIN = 1;
    uint256 constant DEST_CHAIN = 42161;

    bytes32 constant COMMITMENT = keccak256("commitment1");
    bytes32 constant NULLIFIER_HASH = keccak256("nullifier1");
    bytes32 constant STEALTH_RECIPIENT = bytes32(uint256(uint160(0xBEEF)));

    // Cache NATIVE_TOKEN to avoid external call consuming vm.prank/vm.expectRevert
    address constant NATIVE = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    function setUp() public {
        proofVerifier = new MockBridgeProofVerifier();
        msgVerifier = new MockMessageVerifier();
        adapter = new MockBridgeAdapter();
        token = new MockBridgeERC20();

        bridge = new PrivateBridgeIntegration(
            address(proofVerifier),
            address(msgVerifier),
            THIS_CHAIN
        );

        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);

        // Configure destination chain
        vm.prank(operator);
        bridge.setChainConfig(DEST_CHAIN, address(adapter), 12, 100 ether, 1000 ether);

        // Authorize relayer
        vm.prank(operator);
        bridge.setRelayerAuthorization(relayer, true);
    }

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsVerifiers() public view {
        assertEq(bridge.proofVerifier(), address(proofVerifier));
        assertEq(bridge.messageVerifier(), address(msgVerifier));
    }

    function test_Constructor_SetsChainId() public view {
        assertEq(bridge.THIS_CHAIN_ID(), THIS_CHAIN);
    }

    function test_Constructor_GrantsRoles() public view {
        assertTrue(bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(bridge.hasRole(bridge.OPERATOR_ROLE(), admin));
        assertTrue(bridge.hasRole(bridge.GUARDIAN_ROLE(), admin));
    }

    function test_Constructor_RevertZeroProofVerifier() public {
        vm.expectRevert(PrivateBridgeIntegration.ZeroAddress.selector);
        new PrivateBridgeIntegration(address(0), address(msgVerifier), 1);
    }

    function test_Constructor_RevertZeroMessageVerifier() public {
        vm.expectRevert(PrivateBridgeIntegration.ZeroAddress.selector);
        new PrivateBridgeIntegration(address(proofVerifier), address(0), 1);
    }

    /*//////////////////////////////////////////////////////////////
                       CHAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_SetChainConfig_Success() public {
        vm.prank(operator);
        bridge.setChainConfig(10, address(adapter), 6, 50 ether, 500 ether);

        PrivateBridgeIntegration.ChainConfig memory config = bridge.getChainConfig(10);
        assertTrue(config.isSupported);
        assertEq(config.bridgeAdapter, address(adapter));
        assertEq(config.minConfirmations, 6);
        assertEq(config.maxTransfer, 50 ether);
        assertEq(config.dailyLimit, 500 ether);
    }

    function test_SetChainConfig_RevertZeroAdapter() public {
        vm.prank(operator);
        vm.expectRevert(PrivateBridgeIntegration.ZeroAddress.selector);
        bridge.setChainConfig(10, address(0), 6, 50 ether, 500 ether);
    }

    function test_SetChainConfig_RevertSameChain() public {
        vm.prank(operator);
        vm.expectRevert(PrivateBridgeIntegration.InvalidChainId.selector);
        bridge.setChainConfig(THIS_CHAIN, address(adapter), 6, 50 ether, 500 ether);
    }

    function test_SetChainConfig_UpdateExisting() public {
        vm.prank(operator);
        bridge.setChainConfig(DEST_CHAIN, makeAddr("newAdapter"), 24, 200 ether, 2000 ether);

        PrivateBridgeIntegration.ChainConfig memory config = bridge.getChainConfig(DEST_CHAIN);
        assertEq(config.bridgeAdapter, makeAddr("newAdapter"));
        assertEq(config.minConfirmations, 24);
    }

    function test_SetChainConfig_AddsSupportedChain() public {
        vm.prank(operator);
        bridge.setChainConfig(10, address(adapter), 6, 50 ether, 500 ether);

        uint256[] memory chains = bridge.getSupportedChains();
        // DEST_CHAIN + 10
        assertEq(chains.length, 2);
    }

    function test_SetRelayerAuthorization() public {
        address newRelayer = makeAddr("newRelayer");
        vm.prank(operator);
        bridge.setRelayerAuthorization(newRelayer, true);
        assertTrue(bridge.authorizedRelayers(newRelayer));

        vm.prank(operator);
        bridge.setRelayerAuthorization(newRelayer, false);
        assertFalse(bridge.authorizedRelayers(newRelayer));
    }

    function test_SetRelayerAuthorization_RevertZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(PrivateBridgeIntegration.ZeroAddress.selector);
        bridge.setRelayerAuthorization(address(0), true);
    }

    /*//////////////////////////////////////////////////////////////
                   INITIATE PRIVATE TRANSFER
    //////////////////////////////////////////////////////////////*/

    function _buildMessage() internal pure returns (PrivateBridgeIntegration.PrivateBridgeMessage memory) {
        return PrivateBridgeIntegration.PrivateBridgeMessage({
            commitment: COMMITMENT,
            nullifierHash: NULLIFIER_HASH,
            sourceChain: THIS_CHAIN,
            destChain: DEST_CHAIN,
            destRecipient: STEALTH_RECIPIENT,
            proof: hex"aabbccdd"
        });
    }

    function test_InitiatePrivateTransfer_Success() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);

        // Check transfer recorded
        bytes32[] memory userTransfers = bridge.getUserTransfers(user1);
        assertEq(userTransfers.length, 1);

        // Check nullifier marked
        assertTrue(bridge.isLocalNullifierUsed(NULLIFIER_HASH));
    }

    function test_InitiatePrivateTransfer_RevertZeroCommitment() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();
        msg_.commitment = bytes32(0);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateBridgeIntegration.InvalidCommitment.selector);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateTransfer_RevertZeroNullifier() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();
        msg_.nullifierHash = bytes32(0);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateBridgeIntegration.InvalidNullifier.selector);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateTransfer_RevertZeroRecipient() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();
        msg_.destRecipient = bytes32(0);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateBridgeIntegration.InvalidRecipient.selector);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateTransfer_RevertWrongSourceChain() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();
        msg_.sourceChain = 999;

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateBridgeIntegration.InvalidChainId.selector);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateTransfer_RevertUnsupportedChain() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();
        msg_.destChain = 999; // Not configured

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateBridgeIntegration.ChainNotSupported.selector);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateTransfer_RevertNullifierAlreadyUsed() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();

        vm.deal(user1, 2 ether);
        vm.prank(user1);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);

        // Same nullifier again
        vm.prank(user1);
        vm.expectRevert(PrivateBridgeIntegration.NullifierAlreadyUsed.selector);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateTransfer_RevertInvalidProof() public {
        proofVerifier.setShouldVerify(false);

        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateBridgeIntegration.InvalidProof.selector);
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateTransfer_RevertWhenPaused() public {
        vm.prank(guardian);
        bridge.pause();

        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert();
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateTransfer_EmitsEvent() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectEmit(false, true, false, false);
        emit PrivateBridgeIntegration.PrivateTransferInitiated(
            bytes32(0), COMMITMENT, THIS_CHAIN, DEST_CHAIN, block.timestamp
        );
        bridge.initiatePrivateTransfer{value: 0.1 ether}(msg_);
    }

    /*//////////////////////////////////////////////////////////////
                  COMPLETE PRIVATE TRANSFER
    //////////////////////////////////////////////////////////////*/

    function test_CompletePrivateTransfer_Success() public {
        // Build message for destination chain
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ =
            PrivateBridgeIntegration.PrivateBridgeMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN, // Source is the OTHER chain
                destChain: THIS_CHAIN,   // Dest is THIS chain
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        bridge.completePrivateTransfer(msg_, hex"aabb", hex"ccdd");

        // Check cross-chain nullifier registered
        assertTrue(bridge.crossChainNullifiers(NULLIFIER_HASH, DEST_CHAIN));
    }

    function test_CompletePrivateTransfer_RevertUnauthorizedRelayer() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ =
            PrivateBridgeIntegration.PrivateBridgeMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: THIS_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(user1); // Not authorized
        vm.expectRevert(PrivateBridgeIntegration.UnauthorizedRelayer.selector);
        bridge.completePrivateTransfer(msg_, hex"aabb", hex"ccdd");
    }

    function test_CompletePrivateTransfer_RevertWrongDestChain() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ =
            PrivateBridgeIntegration.PrivateBridgeMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: 999, // Wrong
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        vm.expectRevert(PrivateBridgeIntegration.InvalidChainId.selector);
        bridge.completePrivateTransfer(msg_, hex"aabb", hex"ccdd");
    }

    function test_CompletePrivateTransfer_RevertNullifierAlreadyUsed() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ =
            PrivateBridgeIntegration.PrivateBridgeMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: THIS_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        bridge.completePrivateTransfer(msg_, hex"aabb", hex"ccdd");

        // Same nullifier again
        vm.prank(relayer);
        vm.expectRevert(PrivateBridgeIntegration.NullifierAlreadyUsed.selector);
        bridge.completePrivateTransfer(msg_, hex"aabb", hex"ccdd");
    }

    function test_CompletePrivateTransfer_RevertCrossChainVerificationFailed() public {
        msgVerifier.setShouldVerify(false);

        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ =
            PrivateBridgeIntegration.PrivateBridgeMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: THIS_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        vm.expectRevert(PrivateBridgeIntegration.CrossChainVerificationFailed.selector);
        bridge.completePrivateTransfer(msg_, hex"aabb", hex"ccdd");
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN NULLIFIER VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_VerifyCrossChainNullifier_Unused() public view {
        assertTrue(bridge.verifyCrossChainNullifier(NULLIFIER_HASH, DEST_CHAIN));
    }

    function test_VerifyCrossChainNullifier_Used() public {
        // Complete a transfer to mark it
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ =
            PrivateBridgeIntegration.PrivateBridgeMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: THIS_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        bridge.completePrivateTransfer(msg_, hex"aabb", hex"ccdd");

        assertFalse(bridge.verifyCrossChainNullifier(NULLIFIER_HASH, DEST_CHAIN));
    }

    /*//////////////////////////////////////////////////////////////
                       REFUND MECHANISM
    //////////////////////////////////////////////////////////////*/

    function test_RefundExpiredTransfer_Success() public {
        // Initiate transfer
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        bridge.initiatePrivateTransfer{value: 0.5 ether}(msg_);

        bytes32[] memory transfers_ = bridge.getUserTransfers(user1);
        bytes32 transferId = transfers_[0];

        // Fund the bridge for the refund (initiate forwards ETH to adapter)
        vm.deal(address(bridge), 0.5 ether);

        // Warp past expiry
        vm.warp(block.timestamp + bridge.TRANSFER_EXPIRY() + 1);

        // Build refund proof: first 20 bytes = refund recipient address
        bytes memory refundProof = abi.encodePacked(user1, hex"aabbccddee1122334455");

        uint256 balBefore = user1.balance;
        bridge.refundExpiredTransfer(transferId, refundProof);

        assertEq(user1.balance, balBefore + 0.5 ether);
    }

    function test_RefundExpiredTransfer_RevertNotExpired() public {
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ = _buildMessage();
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        bridge.initiatePrivateTransfer{value: 0.5 ether}(msg_);

        bytes32[] memory transfers_ = bridge.getUserTransfers(user1);
        bytes32 transferId = transfers_[0];

        // Don't warp — not expired yet
        vm.expectRevert(PrivateBridgeIntegration.TransferNotFound.selector);
        bridge.refundExpiredTransfer(transferId, hex"");
    }

    function test_RefundExpiredTransfer_RevertNotFound() public {
        vm.expectRevert(PrivateBridgeIntegration.TransferNotFound.selector);
        bridge.refundExpiredTransfer(keccak256("fake"), hex"");
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetChainConfig() public view {
        PrivateBridgeIntegration.ChainConfig memory config = bridge.getChainConfig(DEST_CHAIN);
        assertTrue(config.isSupported);
        assertEq(config.bridgeAdapter, address(adapter));
    }

    function test_IsChainSupported() public view {
        assertTrue(bridge.isChainSupported(DEST_CHAIN));
        assertFalse(bridge.isChainSupported(999));
    }

    function test_GetSupportedChains() public view {
        uint256[] memory chains = bridge.getSupportedChains();
        assertEq(chains.length, 1);
        assertEq(chains[0], DEST_CHAIN);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetProofVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        bridge.setProofVerifier(newVerifier);
        assertEq(bridge.proofVerifier(), newVerifier);
    }

    function test_SetProofVerifier_RevertZeroAddress() public {
        vm.expectRevert(PrivateBridgeIntegration.ZeroAddress.selector);
        bridge.setProofVerifier(address(0));
    }

    function test_SetMessageVerifier() public {
        address newVerifier = makeAddr("newMsgVerifier");
        bridge.setMessageVerifier(newVerifier);
        assertEq(bridge.messageVerifier(), newVerifier);
    }

    function test_SetMessageVerifier_RevertZeroAddress() public {
        vm.expectRevert(PrivateBridgeIntegration.ZeroAddress.selector);
        bridge.setMessageVerifier(address(0));
    }

    function test_PauseUnpause() public {
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());

        vm.prank(operator);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function test_EmergencyWithdraw_Native() public {
        // Fund the bridge
        vm.deal(address(bridge), 5 ether);

        address recipient = makeAddr("recipient");
        bridge.emergencyWithdraw(NATIVE, recipient);
        assertEq(recipient.balance, 5 ether);
    }

    function test_EmergencyWithdraw_ERC20() public {
        token.transfer(address(bridge), 1000 ether);

        address recipient = makeAddr("recipient");
        bridge.emergencyWithdraw(address(token), recipient);
        assertEq(token.balanceOf(recipient), 1000 ether);
    }

    function test_EmergencyWithdraw_RevertZeroAddress() public {
        vm.expectRevert(PrivateBridgeIntegration.ZeroAddress.selector);
        bridge.emergencyWithdraw(NATIVE, address(0));
    }

    function test_ReceiveETH() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        (bool ok, ) = address(bridge).call{value: 0.5 ether}("");
        assertTrue(ok);
        assertEq(address(bridge).balance, 0.5 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetChainConfig_UniqueChains(uint256 chainId) public {
        vm.assume(chainId != THIS_CHAIN && chainId != DEST_CHAIN && chainId != 0);
        vm.prank(operator);
        bridge.setChainConfig(chainId, address(adapter), 6, 50 ether, 500 ether);
        assertTrue(bridge.isChainSupported(chainId));
    }

    function testFuzz_InitiateTransfer_UniqueNullifiers(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));
        PrivateBridgeIntegration.PrivateBridgeMessage memory msg_ =
            PrivateBridgeIntegration.PrivateBridgeMessage({
                commitment: COMMITMENT,
                nullifierHash: nullifier,
                sourceChain: THIS_CHAIN,
                destChain: DEST_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        bridge.initiatePrivateTransfer{value: 0.01 ether}(msg_);

        assertTrue(bridge.isLocalNullifierUsed(nullifier));
    }
}
