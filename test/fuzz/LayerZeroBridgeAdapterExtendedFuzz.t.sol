// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/LayerZeroBridgeAdapter.sol";

contract LayerZeroBridgeAdapterExtendedFuzz is Test {
    LayerZeroBridgeAdapter public bridge;

    address public admin   = address(0xA);
    address public operator = address(0xB);
    address public guardian = address(0xC);
    address public executor = address(0xD);
    address public config  = address(0xE);
    address public user1   = address(0xF1);

    // A mock LZ endpoint
    address public endpoint = address(0x1234);
    uint32 public localEid = 30101;

    function setUp() public {
        vm.prank(admin);
        bridge = new LayerZeroBridgeAdapter();

        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.EXECUTOR_ROLE(), executor);
        bridge.grantRole(bridge.CONFIG_ROLE(), config);
        bridge.setEndpoint(endpoint, localEid);
        vm.stopPrank();

        // Fund accounts
        vm.deal(user1, 100 ether);
        vm.deal(admin, 100 ether);
    }

    // =====================================================================
    // Section 1 — Peer Management (extended)
    // =====================================================================

    function testFuzz_setPeer(
        uint32 eid,
        bytes32 peerAddr,
        uint256 minGas
    ) public {
        vm.assume(eid != 0);
        vm.assume(peerAddr != bytes32(0));
        minGas = bound(minGas, 0, 1e9);

        vm.prank(config);
        bridge.setPeer(
            eid,
            peerAddr,
            LayerZeroBridgeAdapter.ChainType.EVM,
            minGas,
            LayerZeroBridgeAdapter.SecurityLevel.STANDARD
        );

        LayerZeroBridgeAdapter.PeerConfig memory p = bridge.getPeer(eid);
        assertEq(p.eid, eid);
        assertEq(p.peerAddress, peerAddr);
        assertTrue(p.active);
        // If minGas was 0, should default to MIN_GAS
        if (minGas == 0) {
            assertEq(p.minGas, bridge.MIN_GAS());
        } else {
            assertEq(p.minGas, minGas);
        }
    }

    function test_setPeer_duplicateReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        vm.prank(config);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerAlreadySet.selector);
        bridge.setPeer(30102, bytes32(uint256(2)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
    }

    function test_setPeer_zeroEidReverts() public {
        vm.prank(config);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEid.selector);
        bridge.setPeer(0, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
    }

    function test_setPeer_zeroPeerReverts() public {
        vm.prank(config);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidPeer.selector);
        bridge.setPeer(30102, bytes32(0), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
    }

    function test_deactivateAndReactivatePeer() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        vm.prank(guardian);
        bridge.deactivatePeer(30102);
        assertFalse(bridge.isPeerActive(30102));

        vm.prank(config);
        bridge.reactivatePeer(30102);
        assertTrue(bridge.isPeerActive(30102));
    }

    function testFuzz_updatePeerSecurity(uint8 level) public {
        level = uint8(bound(level, 0, 2)); // 3 SecurityLevel values
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        vm.prank(guardian);
        bridge.updatePeerSecurity(30102, LayerZeroBridgeAdapter.SecurityLevel(level));
    }

    function test_updatePeerSecurity_notSetReverts() public {
        vm.prank(guardian);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerNotSet.selector);
        bridge.updatePeerSecurity(99999, LayerZeroBridgeAdapter.SecurityLevel.ENHANCED);
    }

    // =====================================================================
    // Section 2 — lzSend
    // =====================================================================

    function testFuzz_lzSend(bytes memory message, uint128 gas) public {
        gas = uint128(bound(gas, bridge.MIN_GAS(), 1e8));
        vm.assume(message.length > 0 && message.length <= bridge.MAX_MESSAGE_SIZE());

        // Setup peer
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        LayerZeroBridgeAdapter.MessageOptions memory opts = LayerZeroBridgeAdapter.MessageOptions({
            gas: gas,
            value: 0,
            composeMsg: "",
            extraOptions: ""
        });

        // Quote fee
        LayerZeroBridgeAdapter.MessagingFee memory fee = bridge.quoteSend(30102, message, opts);

        vm.prank(user1);
        bridge.lzSend{value: fee.nativeFee}(30102, bytes32(uint256(0xBEEF)), message, opts);

        (uint256 sent, , , ) = bridge.getStats();
        assertEq(sent, 1);
    }

    function test_lzSend_peerNotActiveReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.prank(guardian);
        bridge.deactivatePeer(30102);

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();

        vm.prank(user1);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerNotActive.selector);
        bridge.lzSend{value: 1 ether}(30102, bytes32(uint256(1)), "hello", opts);
    }

    function test_lzSend_peerNotSetReverts() public {
        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();
        vm.prank(user1);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerNotSet.selector);
        bridge.lzSend{value: 1 ether}(99999, bytes32(uint256(1)), "hello", opts);
    }

    function test_lzSend_messageTooLargeReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        bytes memory bigMsg = new bytes(bridge.MAX_MESSAGE_SIZE() + 1);
        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();

        vm.prank(user1);
        vm.expectRevert(LayerZeroBridgeAdapter.MessageTooLarge.selector);
        bridge.lzSend{value: 1 ether}(30102, bytes32(uint256(1)), bigMsg, opts);
    }

    function test_lzSend_insufficientGasReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 200000, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        LayerZeroBridgeAdapter.MessageOptions memory opts = LayerZeroBridgeAdapter.MessageOptions({
            gas: 50000, // below minGas
            value: 0,
            composeMsg: "",
            extraOptions: ""
        });

        vm.prank(user1);
        vm.expectRevert(LayerZeroBridgeAdapter.InsufficientGas.selector);
        bridge.lzSend{value: 1 ether}(30102, bytes32(uint256(1)), "hello", opts);
    }

    function test_lzSend_insufficientFeeReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();
        vm.prank(user1);
        vm.expectRevert(LayerZeroBridgeAdapter.InsufficientFee.selector);
        bridge.lzSend{value: 1 wei}(30102, bytes32(uint256(1)), "hello", opts);
    }

    function test_lzSend_incrementsNonce() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        uint64 nonceBefore = bridge.getNonce(user1);
        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();

        vm.prank(user1);
        bridge.lzSend{value: 1 ether}(30102, bytes32(uint256(1)), "msg1", opts);
        assertEq(bridge.getNonce(user1), nonceBefore + 1);

        vm.prank(user1);
        bridge.lzSend{value: 1 ether}(30102, bytes32(uint256(1)), "msg2", opts);
        assertEq(bridge.getNonce(user1), nonceBefore + 2);
    }

    function test_lzSend_pausedReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.prank(guardian);
        bridge.pause();

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();
        vm.prank(user1);
        vm.expectRevert();
        bridge.lzSend{value: 1 ether}(30102, bytes32(uint256(1)), "hello", opts);
    }

    // =====================================================================
    // Section 3 — lzReceive
    // =====================================================================

    function test_lzReceive_fromEndpoint() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        bytes32 guid = keccak256("guid1");
        vm.prank(endpoint);
        bridge.lzReceive(30102, bytes32(uint256(1)), guid, "hello", "");

        (, uint256 received, , ) = bridge.getStats();
        assertEq(received, 1);
    }

    function test_lzReceive_nonEndpointReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        vm.prank(user1);
        vm.expectRevert(LayerZeroBridgeAdapter.UnauthorizedCaller.selector);
        bridge.lzReceive(30102, bytes32(uint256(1)), keccak256("guid"), "hello", "");
    }

    function test_lzReceive_unknownPeerReverts() public {
        vm.prank(endpoint);
        vm.expectRevert(LayerZeroBridgeAdapter.PeerNotSet.selector);
        bridge.lzReceive(99999, bytes32(uint256(1)), keccak256("guid"), "hello", "");
    }

    function test_lzReceive_idempotent() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        bytes32 guid = keccak256("guid1");
        vm.prank(endpoint);
        bridge.lzReceive(30102, bytes32(uint256(1)), guid, "hello", "");

        // Second call with same GUID should be idempotent (no revert)
        vm.prank(endpoint);
        bridge.lzReceive(30102, bytes32(uint256(1)), guid, "hello2", "");

        // Count should still be 1 (idempotent)
        (, uint256 received, , ) = bridge.getStats();
        assertEq(received, 1);
    }

    // =====================================================================
    // Section 4 — storePayload & retryPayload
    // =====================================================================

    function test_storePayload_executorRole() public {
        // First create a message
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        bytes32 guid = keccak256("guid1");
        vm.prank(endpoint);
        bridge.lzReceive(30102, bytes32(uint256(1)), guid, "hello", "");

        // Store payload
        vm.prank(executor);
        bridge.storePayload(guid, "stored_data");
    }

    function test_storePayload_messageNotFoundReverts() public {
        bytes32 guid = keccak256("nonexistent");
        vm.prank(executor);
        vm.expectRevert(LayerZeroBridgeAdapter.MessageNotFound.selector);
        bridge.storePayload(guid, "data");
    }

    function test_retryPayload() public {
        // Create message
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        bytes32 guid = keccak256("guid1");
        vm.prank(endpoint);
        bridge.lzReceive(30102, bytes32(uint256(1)), guid, "hello", "");

        // Store payload
        vm.prank(executor);
        bridge.storePayload(guid, "stored");

        // Retry
        vm.prank(operator);
        bridge.retryPayload(guid);
    }

    function test_retryPayload_notStoredReverts() public {
        // Create message without storing payload
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        bytes32 guid = keccak256("guid1");
        vm.prank(endpoint);
        bridge.lzReceive(30102, bytes32(uint256(1)), guid, "hello", "");

        vm.prank(operator);
        vm.expectRevert(LayerZeroBridgeAdapter.PayloadNotStored.selector);
        bridge.retryPayload(guid);
    }

    // =====================================================================
    // Section 5 — OFT / Token Mapping
    // =====================================================================

    function testFuzz_mapToken(address localToken, uint32 remoteEid, bytes32 remoteToken) public {
        vm.assume(localToken != address(0) && remoteEid != 0);
        vm.prank(config);
        bridge.mapToken(localToken, remoteEid, remoteToken);
        assertEq(bridge.getRemoteToken(localToken, remoteEid), remoteToken);
    }

    function test_mapToken_zeroTokenReverts() public {
        vm.prank(config);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidToken.selector);
        bridge.mapToken(address(0), 30102, bytes32(uint256(1)));
    }

    function test_mapToken_zeroEidReverts() public {
        vm.prank(config);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEid.selector);
        bridge.mapToken(address(0xBAD), 0, bytes32(uint256(1)));
    }

    function testFuzz_setOFTAdapter(address token, address adapter) public {
        vm.assume(token != address(0));
        vm.prank(config);
        bridge.setOFTAdapter(token, adapter);
    }

    function test_setOFTAdapter_zeroTokenReverts() public {
        vm.prank(config);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidToken.selector);
        bridge.setOFTAdapter(address(0), address(0x1));
    }

    // =====================================================================
    // Section 6 — sendOFT
    // =====================================================================

    function testFuzz_sendOFT(uint256 amount) public {
        amount = bound(amount, 1, 1e30);

        // Setup: peer + token mapping
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.prank(config);
        bridge.mapToken(address(0xBEEF), 30102, bytes32(uint256(0xDEAD)));

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();

        vm.prank(user1);
        bridge.sendOFT{value: 1 ether}(address(0xBEEF), 30102, bytes32(uint256(uint160(user1))), amount, opts);
    }

    function test_sendOFT_zeroAmountReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.prank(config);
        bridge.mapToken(address(0xBEEF), 30102, bytes32(uint256(0xDEAD)));

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();

        vm.prank(user1);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidAmount.selector);
        bridge.sendOFT{value: 1 ether}(address(0xBEEF), 30102, bytes32(uint256(uint160(user1))), 0, opts);
    }

    function test_sendOFT_tokenNotMappedReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();

        vm.prank(user1);
        vm.expectRevert(LayerZeroBridgeAdapter.TokenNotMapped.selector);
        bridge.sendOFT{value: 1 ether}(address(0xBEEF), 30102, bytes32(uint256(uint160(user1))), 1000, opts);
    }

    function test_sendOFT_pausedReverts() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.prank(config);
        bridge.mapToken(address(0xBEEF), 30102, bytes32(uint256(0xDEAD)));
        vm.prank(guardian);
        bridge.pause();

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();
        vm.prank(user1);
        vm.expectRevert();
        bridge.sendOFT{value: 1 ether}(address(0xBEEF), 30102, bytes32(uint256(uint160(user1))), 1000, opts);
    }

    // =====================================================================
    // Section 7 — Fee Estimation (quoteSend)
    // =====================================================================

    function testFuzz_quoteSend_evmChain(uint128 gas) public {
        gas = uint128(bound(gas, bridge.MIN_GAS(), 1e8));
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        LayerZeroBridgeAdapter.MessageOptions memory opts = LayerZeroBridgeAdapter.MessageOptions({
            gas: gas,
            value: 0,
            composeMsg: "",
            extraOptions: ""
        });

        LayerZeroBridgeAdapter.MessagingFee memory fee = bridge.quoteSend(30102, "hello", opts);
        assertGt(fee.nativeFee, 0, "fee should be non-zero");
    }

    function test_quoteSend_chainTypeMultipliers() public {
        // Set up two peers with different chain types
        vm.startPrank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        bridge.setPeer(30103, bytes32(uint256(2)), LayerZeroBridgeAdapter.ChainType.SOLANA, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.stopPrank();

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();

        LayerZeroBridgeAdapter.MessagingFee memory feeEVM = bridge.quoteSend(30102, "hello", opts);
        LayerZeroBridgeAdapter.MessagingFee memory feeSolana = bridge.quoteSend(30103, "hello", opts);

        // Solana should be 1.5x EVM
        assertGt(feeSolana.nativeFee, feeEVM.nativeFee, "Solana fee > EVM fee");
    }

    // =====================================================================
    // Section 8 — withdrawFees
    // =====================================================================

    function test_withdrawFees_happyPath() public {
        // Generate some fees via lzSend
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();
        vm.prank(user1);
        bridge.lzSend{value: 1 ether}(30102, bytes32(uint256(1)), "msg", opts);

        uint256 fees = bridge.accumulatedFees();
        assertGt(fees, 0, "should have accumulated fees");

        address payable recipient = payable(address(0xCAFE));
        vm.prank(admin);
        bridge.withdrawFees(recipient);
        assertEq(bridge.accumulatedFees(), 0, "fees reset after withdrawal");
        assertGt(recipient.balance, 0, "recipient received fees");
    }

    function test_withdrawFees_zeroFeesReverts() public {
        vm.prank(admin);
        vm.expectRevert(LayerZeroBridgeAdapter.NoFeesToWithdraw.selector);
        bridge.withdrawFees(payable(address(0xCAFE)));
    }

    function test_withdrawFees_zeroRecipientReverts() public {
        // First generate fees
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        LayerZeroBridgeAdapter.MessageOptions memory opts = _defaultOpts();
        vm.prank(user1);
        bridge.lzSend{value: 1 ether}(30102, bytes32(uint256(1)), "msg", opts);

        vm.prank(admin);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidRecipient.selector);
        bridge.withdrawFees(payable(address(0)));
    }

    // =====================================================================
    // Section 9 — Library Config
    // =====================================================================

    function test_setSendLibConfig() public {
        address[] memory reqDVNs = new address[](1);
        reqDVNs[0] = address(0x111);
        address[] memory optDVNs = new address[](0);

        vm.prank(config);
        bridge.setSendLibConfig(30102, address(0x222), reqDVNs, optDVNs, 0, 0, address(0x333));
    }

    function test_setSendLibConfig_zeroEidReverts() public {
        address[] memory empty = new address[](0);
        vm.prank(config);
        vm.expectRevert(LayerZeroBridgeAdapter.InvalidEid.selector);
        bridge.setSendLibConfig(0, address(0x222), empty, empty, 0, 0, address(0x333));
    }

    function test_setReceiveLibConfig() public {
        address[] memory reqDVNs = new address[](1);
        reqDVNs[0] = address(0x111);
        address[] memory optDVNs = new address[](0);

        vm.prank(config);
        bridge.setReceiveLibConfig(30102, address(0x444), reqDVNs, optDVNs, 0, 3600);
    }

    // =====================================================================
    // Section 10 — Bridge Fee
    // =====================================================================

    function testFuzz_setBridgeFee(uint256 feeBps) public {
        feeBps = bound(feeBps, 0, 100); // max 1%
        vm.prank(admin);
        bridge.setBridgeFee(feeBps);
        assertEq(bridge.bridgeFee(), feeBps);
    }

    function test_setBridgeFee_tooHighReverts() public {
        vm.prank(admin);
        vm.expectRevert(LayerZeroBridgeAdapter.FeeTooHigh.selector);
        bridge.setBridgeFee(101);
    }

    // =====================================================================
    // Section 11 — Delegate
    // =====================================================================

    function testFuzz_setDelegate(address _delegate) public {
        vm.prank(admin);
        bridge.setDelegate(_delegate);
        assertEq(bridge.delegate(), _delegate);
    }

    // =====================================================================
    // Section 12 — View Functions
    // =====================================================================

    function test_getStats_initial() public view {
        (uint256 sent, uint256 received, uint256 fees, uint256 peerCount) = bridge.getStats();
        assertEq(sent, 0);
        assertEq(received, 0);
        assertEq(fees, 0);
        assertEq(peerCount, 0);
    }

    function test_getRegisteredEids() public {
        vm.startPrank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        bridge.setPeer(30103, bytes32(uint256(2)), LayerZeroBridgeAdapter.ChainType.SOLANA, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
        vm.stopPrank();

        uint32[] memory eids = bridge.getRegisteredEids();
        assertEq(eids.length, 2);
    }

    function test_getMessage() public {
        vm.prank(config);
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);

        bytes32 guid = keccak256("guid1");
        vm.prank(endpoint);
        bridge.lzReceive(30102, bytes32(uint256(1)), guid, "hello", "");

        LayerZeroBridgeAdapter.OmniMessage memory msg_ = bridge.getMessage(guid);
        assertEq(msg_.srcEid, 30102);
        assertEq(uint8(msg_.status), uint8(LayerZeroBridgeAdapter.MessageStatus.DELIVERED));
    }

    // =====================================================================
    // Section 13 — Access Control
    // =====================================================================

    function testFuzz_setPeer_unauthorizedReverts(address caller) public {
        vm.assume(caller != config && caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.setPeer(30102, bytes32(uint256(1)), LayerZeroBridgeAdapter.ChainType.EVM, 0, LayerZeroBridgeAdapter.SecurityLevel.STANDARD);
    }

    function testFuzz_storePayload_unauthorizedReverts(address caller) public {
        vm.assume(caller != executor && caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.storePayload(keccak256("guid"), "payload");
    }

    function testFuzz_retryPayload_unauthorizedReverts(address caller) public {
        vm.assume(caller != operator && caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.retryPayload(keccak256("guid"));
    }

    function testFuzz_withdrawFees_unauthorizedReverts(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.withdrawFees(payable(address(0xCAFE)));
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    function _defaultOpts() internal view returns (LayerZeroBridgeAdapter.MessageOptions memory) {
        return LayerZeroBridgeAdapter.MessageOptions({
            gas: uint128(bridge.MIN_GAS()),
            value: 0,
            composeMsg: "",
            extraOptions: ""
        });
    }
}
