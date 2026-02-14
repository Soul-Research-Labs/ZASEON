// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/LayerZeroBridgeAdapter.sol";

/// @title LayerZeroBridgeAdapter Unit Tests
/// @notice Comprehensive tests for peer management, messaging, OFT transfers, and admin functions
contract LayerZeroBridgeAdapterTest is Test {
    LayerZeroBridgeAdapter public adapter;

    address public admin = address(this);
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public executor = makeAddr("executor");
    address public configAdmin = makeAddr("configAdmin");
    address public alice = makeAddr("alice");

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");

    // Common Endpoint IDs
    uint32 constant ETH_EID = 30101;
    uint32 constant ARB_EID = 30110;
    uint32 constant OP_EID = 30111;

    bytes32 constant REMOTE_PEER = bytes32(uint256(0xDEADBEEF));

    function setUp() public {
        adapter = new LayerZeroBridgeAdapter();

        // Grant roles
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(GUARDIAN_ROLE, guardian);
        adapter.grantRole(EXECUTOR_ROLE, executor);
        adapter.grantRole(CONFIG_ROLE, configAdmin);

        // Fund accounts
        vm.deal(alice, 100 ether);
        vm.deal(admin, 100 ether);
    }

    // ============ Constructor Tests ============

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
        assertTrue(adapter.hasRole(CONFIG_ROLE, admin));
    }

    function test_constructor_setsDefaultFee() public view {
        assertEq(adapter.bridgeFee(), 10); // 0.1%
    }

    function test_constructor_initialCounters() public view {
        assertEq(adapter.totalMessagesSent(), 0);
        assertEq(adapter.totalMessagesReceived(), 0);
        assertEq(adapter.accumulatedFees(), 0);
    }

    // ============ Configuration Tests ============

    function test_setEndpoint_success() public {
        address endpoint = makeAddr("lzEndpoint");
        adapter.setEndpoint(endpoint, ETH_EID);

        assertEq(adapter.lzEndpoint(), endpoint);
        assertEq(adapter.localEid(), ETH_EID);
    }

    function test_setEndpoint_revertsZeroAddress() public {
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEndpoint.selector);
        adapter.setEndpoint(address(0), ETH_EID);
    }

    function test_setEndpoint_revertsZeroEid() public {
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEid.selector);
        adapter.setEndpoint(makeAddr("ep"), 0);
    }

    function test_setEndpoint_revertsNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        adapter.setEndpoint(makeAddr("ep"), ETH_EID);
    }

    function test_setDelegate_success() public {
        address del = makeAddr("delegate");
        adapter.setDelegate(del);
        assertEq(adapter.delegate(), del);
    }

    function test_setBridgeFee_success() public {
        adapter.setBridgeFee(50); // 0.5%
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_revertsMax() public {
        vm.expectRevert(LayerZeroBridgeAdapter.FeeTooHigh.selector);
        adapter.setBridgeFee(101); // > 1%
    }

    function test_setBridgeFee_maxAllowed() public {
        adapter.setBridgeFee(100); // 1% is allowed
        assertEq(adapter.bridgeFee(), 100);
    }

    // ============ Peer Management Tests ============

    function test_setPeer_success() public {
        vm.prank(configAdmin);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            200000,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        assertTrue(adapter.isPeerActive(ARB_EID));
        LayerZeroBridgeAdapter.PeerConfig memory peer = adapter.getPeer(
            ARB_EID
        );
        assertEq(peer.eid, ARB_EID);
        assertEq(peer.peerAddress, REMOTE_PEER);
        assertEq(peer.minGas, 200000);
    }

    function test_setPeer_defaultMinGas() public {
        vm.prank(configAdmin);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0, // Should default to MIN_GAS
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        LayerZeroBridgeAdapter.PeerConfig memory peer = adapter.getPeer(
            ARB_EID
        );
        assertEq(peer.minGas, adapter.MIN_GAS());
    }

    function test_setPeer_revertsZeroEid() public {
        vm.prank(configAdmin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEid.selector);
        adapter.setPeer(
            0,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );
    }

    function test_setPeer_revertsZeroPeer() public {
        vm.prank(configAdmin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidPeer.selector);
        adapter.setPeer(
            ARB_EID,
            bytes32(0),
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );
    }

    function test_setPeer_revertsDuplicate() public {
        vm.startPrank(configAdmin);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        vm.expectRevert(LayerZeroBridgeAdapter.PeerAlreadySet.selector);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );
        vm.stopPrank();
    }

    function test_setPeer_revertsNotConfigRole() public {
        vm.prank(alice);
        vm.expectRevert();
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );
    }

    function test_updatePeerSecurity() public {
        vm.prank(configAdmin);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        vm.prank(guardian);
        adapter.updatePeerSecurity(
            ARB_EID,
            LayerZeroBridgeAdapter.SecurityLevel.MAXIMUM
        );

        LayerZeroBridgeAdapter.PeerConfig memory peer = adapter.getPeer(
            ARB_EID
        );
        assertEq(
            uint256(peer.securityLevel),
            uint256(LayerZeroBridgeAdapter.SecurityLevel.MAXIMUM)
        );
    }

    function test_updatePeerSecurity_revertsNoPeer() public {
        vm.prank(guardian);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerNotSet.selector);
        adapter.updatePeerSecurity(
            ARB_EID,
            LayerZeroBridgeAdapter.SecurityLevel.ENHANCED
        );
    }

    function test_deactivatePeer() public {
        vm.prank(configAdmin);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        vm.prank(guardian);
        adapter.deactivatePeer(ARB_EID);

        assertFalse(adapter.isPeerActive(ARB_EID));
    }

    function test_reactivatePeer() public {
        vm.prank(configAdmin);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        vm.prank(guardian);
        adapter.deactivatePeer(ARB_EID);
        assertFalse(adapter.isPeerActive(ARB_EID));

        vm.prank(configAdmin);
        adapter.reactivatePeer(ARB_EID);
        assertTrue(adapter.isPeerActive(ARB_EID));
    }

    // ============ Library Configuration Tests ============

    function test_setSendLibConfig_success() public {
        address[] memory requiredDVNs = new address[](1);
        requiredDVNs[0] = makeAddr("dvn1");
        address[] memory optionalDVNs = new address[](0);

        vm.prank(configAdmin);
        adapter.setSendLibConfig(
            ARB_EID,
            makeAddr("sendLib"),
            requiredDVNs,
            optionalDVNs,
            0,
            0,
            makeAddr("exec")
        );
    }

    function test_setSendLibConfig_revertsZeroEid() public {
        address[] memory empty = new address[](0);
        vm.prank(configAdmin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEid.selector);
        adapter.setSendLibConfig(
            0,
            makeAddr("lib"),
            empty,
            empty,
            0,
            0,
            makeAddr("exec")
        );
    }

    function test_setReceiveLibConfig_success() public {
        address[] memory requiredDVNs = new address[](2);
        requiredDVNs[0] = makeAddr("dvn1");
        requiredDVNs[1] = makeAddr("dvn2");
        address[] memory optionalDVNs = new address[](0);

        vm.prank(configAdmin);
        adapter.setReceiveLibConfig(
            ARB_EID,
            makeAddr("recvLib"),
            requiredDVNs,
            optionalDVNs,
            0,
            3600
        );
    }

    // ============ Messaging Tests ============

    function _setupPeerAndEndpoint() internal {
        adapter.setEndpoint(makeAddr("lzEndpoint"), ETH_EID);

        vm.prank(configAdmin);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            100000,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );
    }

    function test_lzSend_success() public {
        _setupPeerAndEndpoint();

        bytes memory message = abi.encode("hello");
        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        // Quote the fee first
        LayerZeroBridgeAdapter.MessagingFee memory fee = adapter.quoteSend(
            ARB_EID,
            message,
            opts
        );

        vm.prank(alice);
        bytes32 guid = adapter.lzSend{value: fee.nativeFee + 0.01 ether}(
            ARB_EID,
            REMOTE_PEER,
            message,
            opts
        );

        assertTrue(guid != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
    }

    function test_lzSend_revertsPeerNotSet() public {
        adapter.setEndpoint(makeAddr("ep"), ETH_EID);

        bytes memory message = abi.encode("hello");
        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        vm.prank(alice);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerNotSet.selector);
        adapter.lzSend{value: 1 ether}(ARB_EID, REMOTE_PEER, message, opts);
    }

    function test_lzSend_revertsPeerInactive() public {
        _setupPeerAndEndpoint();

        vm.prank(guardian);
        adapter.deactivatePeer(ARB_EID);

        bytes memory message = abi.encode("hello");
        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        vm.prank(alice);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerNotActive.selector);
        adapter.lzSend{value: 1 ether}(ARB_EID, REMOTE_PEER, message, opts);
    }

    function test_lzSend_revertsInsufficientGas() public {
        _setupPeerAndEndpoint();

        bytes memory message = abi.encode("test");
        LayerZeroBridgeAdapter.MessageOptions memory opts = LayerZeroBridgeAdapter
            .MessageOptions({
                gas: 50000, // Below peer.minGas of 100000
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        vm.prank(alice);
        vm.expectRevert(LayerZeroBridgeAdapter.InsufficientGas.selector);
        adapter.lzSend{value: 1 ether}(ARB_EID, REMOTE_PEER, message, opts);
    }

    function test_lzSend_revertsWhenPaused() public {
        _setupPeerAndEndpoint();

        vm.prank(guardian);
        adapter.pause();

        bytes memory message = abi.encode("test");
        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        vm.prank(alice);
        vm.expectRevert();
        adapter.lzSend{value: 1 ether}(ARB_EID, REMOTE_PEER, message, opts);
    }

    function test_lzSend_incrementsNonce() public {
        _setupPeerAndEndpoint();

        bytes memory message = abi.encode("msg1");
        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        assertEq(adapter.getNonce(alice), 0);

        vm.prank(alice);
        adapter.lzSend{value: 1 ether}(ARB_EID, REMOTE_PEER, message, opts);

        assertEq(adapter.getNonce(alice), 1);
    }

    // ============ lzReceive Tests ============

    function test_lzReceive_success() public {
        _setupPeerAndEndpoint();
        address endpoint = adapter.lzEndpoint();

        bytes32 guid = keccak256("testGuid");
        bytes memory message = abi.encode("inbound");

        vm.prank(endpoint);
        adapter.lzReceive(ARB_EID, REMOTE_PEER, guid, message, "");

        assertEq(adapter.totalMessagesReceived(), 1);

        LayerZeroBridgeAdapter.OmniMessage memory msg_ = adapter.getMessage(
            guid
        );
        assertEq(msg_.guid, guid);
        assertEq(
            uint256(msg_.status),
            uint256(LayerZeroBridgeAdapter.MessageStatus.DELIVERED)
        );
    }

    function test_lzReceive_revertsUnauthorizedCaller() public {
        _setupPeerAndEndpoint();

        vm.prank(alice);
        vm.expectRevert(LayerZeroBridgeAdapter.UnauthorizedCaller.selector);
        adapter.lzReceive(ARB_EID, REMOTE_PEER, keccak256("g"), "", "");
    }

    function test_lzReceive_revertsUnauthorizedSender() public {
        _setupPeerAndEndpoint();
        address endpoint = adapter.lzEndpoint();

        bytes32 wrongSender = bytes32(uint256(0xBADBAD));
        vm.prank(endpoint);
        vm.expectRevert(LayerZeroBridgeAdapter.UnauthorizedCaller.selector);
        adapter.lzReceive(ARB_EID, wrongSender, keccak256("g"), "", "");
    }

    function test_lzReceive_idempotent() public {
        _setupPeerAndEndpoint();
        address endpoint = adapter.lzEndpoint();

        bytes32 guid = keccak256("dupeGuid");
        vm.prank(endpoint);
        adapter.lzReceive(ARB_EID, REMOTE_PEER, guid, "data", "");

        // Second call should silently return (idempotent)
        vm.prank(endpoint);
        adapter.lzReceive(ARB_EID, REMOTE_PEER, guid, "data", "");

        // Only counted once
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    // ============ Store / Retry Payload Tests ============

    function test_storeAndRetryPayload() public {
        _setupPeerAndEndpoint();
        address endpoint = adapter.lzEndpoint();

        bytes32 guid = keccak256("storeGuid");
        vm.prank(endpoint);
        adapter.lzReceive(ARB_EID, REMOTE_PEER, guid, "payload", "");

        // Store the payload
        vm.prank(executor);
        adapter.storePayload(guid, "stored_data");

        LayerZeroBridgeAdapter.OmniMessage memory msg_ = adapter.getMessage(
            guid
        );
        assertEq(
            uint256(msg_.status),
            uint256(LayerZeroBridgeAdapter.MessageStatus.STORED)
        );

        // Retry the payload
        vm.prank(operator);
        adapter.retryPayload(guid);

        msg_ = adapter.getMessage(guid);
        assertEq(
            uint256(msg_.status),
            uint256(LayerZeroBridgeAdapter.MessageStatus.DELIVERED)
        );
    }

    function test_storePayload_revertsNotExecutor() public {
        vm.prank(alice);
        vm.expectRevert();
        adapter.storePayload(keccak256("g"), "data");
    }

    function test_retryPayload_revertsNotStored() public {
        vm.prank(operator);
        vm.expectRevert(LayerZeroBridgeAdapter.PayloadNotStored.selector);
        adapter.retryPayload(keccak256("nonexist"));
    }

    // ============ OFT Transfer Tests ============

    function test_mapToken() public {
        address token = makeAddr("token");
        bytes32 remoteToken = bytes32(uint256(0xAABBCC));

        vm.prank(configAdmin);
        adapter.mapToken(token, ARB_EID, remoteToken);

        assertEq(adapter.getRemoteToken(token, ARB_EID), remoteToken);
    }

    function test_mapToken_revertsZeroToken() public {
        vm.prank(configAdmin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidToken.selector);
        adapter.mapToken(address(0), ARB_EID, bytes32(uint256(1)));
    }

    function test_mapToken_revertsZeroEid() public {
        vm.prank(configAdmin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEid.selector);
        adapter.mapToken(makeAddr("t"), 0, bytes32(uint256(1)));
    }

    function test_setOFTAdapter() public {
        address token = makeAddr("token");
        address oft = makeAddr("oftAdapter");

        vm.prank(configAdmin);
        adapter.setOFTAdapter(token, oft);
    }

    function test_setOFTAdapter_revertsZeroToken() public {
        vm.prank(configAdmin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidToken.selector);
        adapter.setOFTAdapter(address(0), makeAddr("oft"));
    }

    function test_sendOFT_success() public {
        _setupPeerAndEndpoint();

        address token = makeAddr("token");
        bytes32 remoteToken = bytes32(uint256(0xAABBCC));

        vm.prank(configAdmin);
        adapter.mapToken(token, ARB_EID, remoteToken);

        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        vm.prank(alice);
        bytes32 transferId = adapter.sendOFT{value: 0.1 ether}(
            token,
            ARB_EID,
            REMOTE_PEER,
            1000 ether,
            opts
        );

        assertTrue(transferId != bytes32(0));

        LayerZeroBridgeAdapter.OFTTransfer memory transfer = adapter
            .getOFTTransfer(transferId);
        assertEq(transfer.amountSent, 1000 ether);
        // Fee: 1000 * 10 / 10000 = 1 ether
        assertEq(transfer.amountReceived, 999 ether);
        assertEq(transfer.fee, 1 ether);
    }

    function test_sendOFT_revertsZeroAmount() public {
        _setupPeerAndEndpoint();

        address token = makeAddr("token");
        vm.prank(configAdmin);
        adapter.mapToken(token, ARB_EID, bytes32(uint256(1)));

        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        vm.prank(alice);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidAmount.selector);
        adapter.sendOFT{value: 0.1 ether}(token, ARB_EID, REMOTE_PEER, 0, opts);
    }

    function test_sendOFT_revertsTokenNotMapped() public {
        _setupPeerAndEndpoint();

        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        vm.prank(alice);
        vm.expectRevert(LayerZeroBridgeAdapter.TokenNotMapped.selector);
        adapter.sendOFT{value: 0.1 ether}(
            makeAddr("unmapped"),
            ARB_EID,
            REMOTE_PEER,
            100,
            opts
        );
    }

    // ============ Fee Estimation Tests ============

    function test_quoteSend_evm() public {
        _setupPeerAndEndpoint();

        bytes memory message = abi.encode("hello");
        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        LayerZeroBridgeAdapter.MessagingFee memory fee = adapter.quoteSend(
            ARB_EID,
            message,
            opts
        );
        assertGt(fee.nativeFee, 0);
        assertEq(fee.lzTokenFee, 0);
    }

    // ============ Admin Tests ============

    function test_pause_unpause() public {
        vm.prank(guardian);
        adapter.pause();

        adapter.unpause(); // admin has DEFAULT_ADMIN_ROLE
    }

    function test_pause_revertsNotGuardian() public {
        vm.prank(alice);
        vm.expectRevert();
        adapter.pause();
    }

    function test_withdrawFees_success() public {
        _setupPeerAndEndpoint();

        // Generate some fees via sendOFT
        address token = makeAddr("token");
        vm.prank(configAdmin);
        adapter.mapToken(token, ARB_EID, bytes32(uint256(1)));

        LayerZeroBridgeAdapter.MessageOptions
            memory opts = LayerZeroBridgeAdapter.MessageOptions({
                gas: 200000,
                value: 0,
                composeMsg: "",
                extraOptions: ""
            });

        vm.prank(alice);
        adapter.sendOFT{value: 0.5 ether}(
            token,
            ARB_EID,
            REMOTE_PEER,
            1000,
            opts
        );

        uint256 fees = adapter.accumulatedFees();
        assertGt(fees, 0);

        // Ensure the adapter has enough ETH to cover fees
        vm.deal(address(adapter), fees + 1 ether);

        address payable recipient = payable(makeAddr("feeRecipient"));
        uint256 recipBalBefore = recipient.balance;

        adapter.withdrawFees(recipient);
        assertEq(recipient.balance, recipBalBefore + fees);
        assertEq(adapter.accumulatedFees(), 0);
    }

    function test_withdrawFees_revertsZeroAddress() public {
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidRecipient.selector);
        adapter.withdrawFees(payable(address(0)));
    }

    function test_withdrawFees_revertsNoFees() public {
        vm.expectRevert(LayerZeroBridgeAdapter.NoFeesToWithdraw.selector);
        adapter.withdrawFees(payable(makeAddr("r")));
    }

    function test_withdrawFees_revertsNotAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        adapter.withdrawFees(payable(alice));
    }

    // ============ View Tests ============

    function test_getStats() public {
        (
            uint256 sent,
            uint256 received,
            uint256 fees,
            uint256 peerCount
        ) = adapter.getStats();
        assertEq(sent, 0);
        assertEq(received, 0);
        assertEq(fees, 0);
        assertEq(peerCount, 0);
    }

    function test_getRegisteredEids() public {
        vm.prank(configAdmin);
        adapter.setPeer(
            ARB_EID,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        uint32[] memory eids = adapter.getRegisteredEids();
        assertEq(eids.length, 1);
        assertEq(eids[0], ARB_EID);
    }

    function test_isPeerActive_false() public view {
        assertFalse(adapter.isPeerActive(99999));
    }

    function test_getMessage_nonexistent() public view {
        LayerZeroBridgeAdapter.OmniMessage memory msg_ = adapter.getMessage(
            keccak256("nope")
        );
        assertEq(msg_.guid, bytes32(0));
    }

    // ============ Fuzz Tests ============

    function testFuzz_bridgeFeeInRange(uint256 fee) public {
        if (fee <= 100) {
            adapter.setBridgeFee(fee);
            assertEq(adapter.bridgeFee(), fee);
        } else {
            vm.expectRevert(LayerZeroBridgeAdapter.FeeTooHigh.selector);
            adapter.setBridgeFee(fee);
        }
    }

    function testFuzz_peerSetup(uint32 eid) public {
        vm.assume(eid > 0);

        vm.prank(configAdmin);
        adapter.setPeer(
            eid,
            REMOTE_PEER,
            LayerZeroBridgeAdapter.ChainType.EVM,
            0,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        assertTrue(adapter.isPeerActive(eid));
    }
}
