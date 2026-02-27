// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/libraries/CrossChainMessageCodec.sol";

/// @dev Harness exposing internal library functions for testing
contract CodecHarness {
    function computeMessageId(
        CrossChainMessageCodec.CanonicalMessage memory msg_
    ) external pure returns (bytes32) {
        return CrossChainMessageCodec.computeMessageId(msg_);
    }

    function computeMessageIdParams(
        uint256 sourceChainId,
        uint256 destChainId,
        address sender,
        address recipient,
        uint256 nonce,
        bytes memory payload,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return
            CrossChainMessageCodec.computeMessageId(
                sourceChainId,
                destChainId,
                sender,
                recipient,
                nonce,
                payload,
                timestamp
            );
    }

    function computeProofMessageId(
        uint256 sourceChainId,
        uint256 destChainId,
        address sender,
        address recipient,
        uint256 nonce,
        bytes32 proofHash,
        bytes32 publicInputsHash,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return
            CrossChainMessageCodec.computeProofMessageId(
                sourceChainId,
                destChainId,
                sender,
                recipient,
                nonce,
                proofHash,
                publicInputsHash,
                timestamp
            );
    }

    function computeDepositId(
        uint256 sourceChainId,
        address depositor,
        address recipient,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return
            CrossChainMessageCodec.computeDepositId(
                sourceChainId,
                depositor,
                recipient,
                token,
                amount,
                nonce,
                timestamp
            );
    }

    function computeWithdrawalId(
        uint256 sourceChainId,
        address requester,
        address recipient,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return
            CrossChainMessageCodec.computeWithdrawalId(
                sourceChainId,
                requester,
                recipient,
                token,
                amount,
                nonce,
                timestamp
            );
    }

    function computeEmergencyId(
        uint256 sourceChainId,
        uint256 destChainId,
        uint8 severity,
        address broadcaster,
        uint256 nonce,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return
            CrossChainMessageCodec.computeEmergencyId(
                sourceChainId,
                destChainId,
                severity,
                broadcaster,
                nonce,
                timestamp
            );
    }

    function encodeEnvelope(
        CrossChainMessageCodec.CanonicalMessage memory msg_
    ) external pure returns (bytes memory) {
        return CrossChainMessageCodec.encodeEnvelope(msg_);
    }

    function decodeEnvelope(
        bytes memory envelope
    )
        external
        pure
        returns (CrossChainMessageCodec.CanonicalMessage memory, bytes32)
    {
        return CrossChainMessageCodec.decodeEnvelope(envelope);
    }

    function validateMessage(
        CrossChainMessageCodec.CanonicalMessage memory msg_
    ) external pure returns (bool) {
        return CrossChainMessageCodec.validateMessage(msg_);
    }
}

contract CrossChainMessageCodecTest is Test {
    CodecHarness harness;

    function setUp() public {
        harness = new CodecHarness();
    }

    // ── Helpers ──

    function _validMsg()
        internal
        pure
        returns (CrossChainMessageCodec.CanonicalMessage memory)
    {
        return
            CrossChainMessageCodec.CanonicalMessage({
                sourceChainId: 1,
                destChainId: 42161,
                sender: address(0xABCD),
                recipient: address(0xDEAD),
                nonce: 7,
                payload: hex"cafebabe",
                timestamp: 1700000000
            });
    }

    // ── computeMessageId ──

    function test_computeMessageId_deterministic() public view {
        CrossChainMessageCodec.CanonicalMessage memory m = _validMsg();
        bytes32 id1 = harness.computeMessageId(m);
        bytes32 id2 = harness.computeMessageId(m);
        assertEq(id1, id2, "IDs must be deterministic");
        assertTrue(id1 != bytes32(0), "ID must be non-zero");
    }

    function test_computeMessageId_structVsParams() public view {
        CrossChainMessageCodec.CanonicalMessage memory m = _validMsg();
        bytes32 idStruct = harness.computeMessageId(m);
        bytes32 idParams = harness.computeMessageIdParams(
            m.sourceChainId,
            m.destChainId,
            m.sender,
            m.recipient,
            m.nonce,
            m.payload,
            m.timestamp
        );
        assertEq(idStruct, idParams, "Struct and param overloads must agree");
    }

    function test_computeMessageId_differentNonce() public view {
        CrossChainMessageCodec.CanonicalMessage memory m1 = _validMsg();
        CrossChainMessageCodec.CanonicalMessage memory m2 = _validMsg();
        m2.nonce = 8;
        assertTrue(
            harness.computeMessageId(m1) != harness.computeMessageId(m2),
            "Different nonces must produce different IDs"
        );
    }

    // ── computeProofMessageId ──

    function test_computeProofMessageId_nonZero() public view {
        bytes32 id = harness.computeProofMessageId(
            1,
            42161,
            address(0xAA),
            address(0xBB),
            0,
            keccak256("proof"),
            keccak256("inputs"),
            1700000000
        );
        assertTrue(id != bytes32(0));
    }

    // ── computeDepositId / computeWithdrawalId / computeEmergencyId ──

    function test_depositId_nonZero() public view {
        bytes32 id = harness.computeDepositId(
            1,
            address(0xAA),
            address(0xBB),
            address(0xCC),
            1e18,
            0,
            1700000000
        );
        assertTrue(id != bytes32(0));
    }

    function test_withdrawalId_nonZero() public view {
        bytes32 id = harness.computeWithdrawalId(
            1,
            address(0xAA),
            address(0xBB),
            address(0xCC),
            1e18,
            0,
            1700000000
        );
        assertTrue(id != bytes32(0));
    }

    function test_emergencyId_nonZero() public view {
        bytes32 id = harness.computeEmergencyId(
            1,
            42161,
            3,
            address(0xAA),
            0,
            1700000000
        );
        assertTrue(id != bytes32(0));
    }

    function test_depositAndWithdrawalIds_differ() public view {
        bytes32 dId = harness.computeDepositId(
            1,
            address(0xAA),
            address(0xBB),
            address(0xCC),
            1e18,
            0,
            1700000000
        );
        bytes32 wId = harness.computeWithdrawalId(
            1,
            address(0xAA),
            address(0xBB),
            address(0xCC),
            1e18,
            0,
            1700000000
        );
        assertTrue(
            dId != wId,
            "Deposit and withdrawal IDs must differ (different type hashes)"
        );
    }

    // ── encodeEnvelope / decodeEnvelope roundtrip ──

    function test_encodeDecodeRoundtrip() public view {
        CrossChainMessageCodec.CanonicalMessage memory original = _validMsg();
        bytes memory envelope = harness.encodeEnvelope(original);
        (
            CrossChainMessageCodec.CanonicalMessage memory decoded,
            bytes32 msgId
        ) = harness.decodeEnvelope(envelope);

        assertEq(decoded.sourceChainId, original.sourceChainId);
        assertEq(decoded.destChainId, original.destChainId);
        assertEq(decoded.sender, original.sender);
        assertEq(decoded.recipient, original.recipient);
        assertEq(decoded.nonce, original.nonce);
        assertEq(keccak256(decoded.payload), keccak256(original.payload));
        assertEq(decoded.timestamp, original.timestamp);
        assertEq(msgId, harness.computeMessageId(original));
    }

    // ── validateMessage ──

    function test_validateMessage_valid() public view {
        assertTrue(harness.validateMessage(_validMsg()));
    }

    function test_validateMessage_sameSourceDest() public view {
        CrossChainMessageCodec.CanonicalMessage memory m = _validMsg();
        m.destChainId = m.sourceChainId; // same chain
        assertFalse(harness.validateMessage(m));
    }

    function test_validateMessage_zeroSender() public view {
        CrossChainMessageCodec.CanonicalMessage memory m = _validMsg();
        m.sender = address(0);
        assertFalse(harness.validateMessage(m));
    }

    function test_validateMessage_zeroRecipient() public view {
        CrossChainMessageCodec.CanonicalMessage memory m = _validMsg();
        m.recipient = address(0);
        assertFalse(harness.validateMessage(m));
    }

    function test_validateMessage_emptyPayload() public view {
        CrossChainMessageCodec.CanonicalMessage memory m = _validMsg();
        m.payload = "";
        assertFalse(harness.validateMessage(m));
    }

    // ── Fuzz: encode/decode roundtrip ──

    function testFuzz_encodeDecodeRoundtrip(
        uint256 srcChain,
        uint256 dstChain,
        address sender,
        address recipient,
        uint256 nonce,
        uint256 timestamp
    ) public view {
        vm.assume(srcChain != dstChain);
        vm.assume(sender != address(0));
        vm.assume(recipient != address(0));

        CrossChainMessageCodec.CanonicalMessage
            memory m = CrossChainMessageCodec.CanonicalMessage({
                sourceChainId: srcChain,
                destChainId: dstChain,
                sender: sender,
                recipient: recipient,
                nonce: nonce,
                payload: hex"01",
                timestamp: timestamp
            });

        bytes memory env = harness.encodeEnvelope(m);
        (CrossChainMessageCodec.CanonicalMessage memory d, bytes32 id) = harness
            .decodeEnvelope(env);
        assertEq(d.sourceChainId, srcChain);
        assertEq(d.nonce, nonce);
        assertEq(id, harness.computeMessageId(m));
    }
}
