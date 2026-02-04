// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./FHETypes.sol";
import "./FHEGateway.sol";
import "../libraries/FHELib.sol";

/**
 * @title FHEOperations
 * @author Soul Protocol
 * @notice Library for FHE arithmetic operations with gateway integration
 * @dev Provides TFHE-compatible interface for encrypted computations
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                   FHE Operations Flow                                │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  ┌────────────┐  asEuint256()  ┌────────────┐  add()  ┌──────────┐ │
 * │  │ Plaintext  │──────────────▶│  Handle    │────────▶│ Gateway  │ │
 * │  │   Value    │                │ (euint256) │         │ Request  │ │
 * │  └────────────┘                └────────────┘         └──────────┘ │
 * │                                                             │       │
 * │                                                             ▼       │
 * │  ┌────────────┐  decrypt()    ┌────────────┐  ┌───────────────────┐│
 * │  │  Result    │◀──────────────│  Output    │◀─│   Coprocessor     ││
 * │  │ (callback) │               │  Handle    │  │   Computation     ││
 * │  └────────────┘               └────────────┘  └───────────────────┘│
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Note: Operations are delegated to the FHEGateway which routes them
 * to off-chain coprocessors. Results are returned as new handles.
 */
library FHEOperations {
    // ============================================
    // GATEWAY REFERENCE
    // ============================================

    /// @notice Storage slot for gateway address
    /// @dev keccak256("soul.fhe.gateway") - 1
    bytes32 private constant GATEWAY_SLOT = 0x8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19a;

    /**
     * @notice Set the gateway address (called once during initialization)
     * @param gateway The gateway contract address
     */
    function setGateway(address gateway) internal {
        bytes32 slot = GATEWAY_SLOT;
        assembly {
            sstore(slot, gateway)
        }
    }

    /**
     * @notice Get the gateway address
     * @return gateway The gateway contract address
     */
    function getGateway() internal view returns (address gateway) {
        bytes32 slot = GATEWAY_SLOT;
        assembly {
            gateway := sload(slot)
        }
    }

    // ============================================
    // TRIVIAL ENCRYPTION (Plaintext -> Ciphertext)
    // ============================================

    /**
     * @notice Encrypt a boolean value
     * @param value The plaintext value
     * @return result Encrypted boolean handle
     */
    function asEbool(bool value) internal returns (ebool memory result) {
        bytes32 handle = _createHandle(uint8(FHELib.ValueType.ebool));
        bytes32 ctHash = keccak256(abi.encode("TRIVIAL", value, block.timestamp));
        result = ebool(handle, ctHash);
    }

    /**
     * @notice Encrypt a uint8 value
     * @param value The plaintext value
     * @return result Encrypted uint8 handle
     */
    function asEuint8(uint8 value) internal returns (euint8 memory result) {
        bytes32 handle = _createHandle(uint8(FHELib.ValueType.euint8));
        bytes32 ctHash = keccak256(abi.encode("TRIVIAL", value, block.timestamp));
        result = euint8(handle, ctHash);
    }

    /**
     * @notice Encrypt a uint16 value
     * @param value The plaintext value
     * @return result Encrypted uint16 handle
     */
    function asEuint16(uint16 value) internal returns (euint16 memory result) {
        bytes32 handle = _createHandle(uint8(FHELib.ValueType.euint16));
        bytes32 ctHash = keccak256(abi.encode("TRIVIAL", value, block.timestamp));
        result = euint16(handle, ctHash);
    }

    /**
     * @notice Encrypt a uint32 value
     * @param value The plaintext value
     * @return result Encrypted uint32 handle
     */
    function asEuint32(uint32 value) internal returns (euint32 memory result) {
        bytes32 handle = _createHandle(uint8(FHELib.ValueType.euint32));
        bytes32 ctHash = keccak256(abi.encode("TRIVIAL", value, block.timestamp));
        result = euint32(handle, ctHash);
    }

    /**
     * @notice Encrypt a uint64 value
     * @param value The plaintext value
     * @return result Encrypted uint64 handle
     */
    function asEuint64(uint64 value) internal returns (euint64 memory result) {
        bytes32 handle = _createHandle(uint8(FHELib.ValueType.euint64));
        bytes32 ctHash = keccak256(abi.encode("TRIVIAL", value, block.timestamp));
        result = euint64(handle, ctHash);
    }

    /**
     * @notice Encrypt a uint128 value
     * @param value The plaintext value
     * @return result Encrypted uint128 handle
     */
    function asEuint128(uint128 value) internal returns (euint128 memory result) {
        bytes32 handle = _createHandle(uint8(FHELib.ValueType.euint128));
        bytes32 ctHash = keccak256(abi.encode("TRIVIAL", value, block.timestamp));
        result = euint128(handle, ctHash);
    }

    /**
     * @notice Encrypt a uint256 value
     * @param value The plaintext value
     * @return result Encrypted uint256 handle
     */
    function asEuint256(uint256 value) internal returns (euint256 memory result) {
        bytes32 handle = _createHandle(uint8(FHELib.ValueType.euint256));
        bytes32 ctHash = keccak256(abi.encode("TRIVIAL", value, block.timestamp));
        result = euint256(handle, ctHash);
    }

    /**
     * @notice Encrypt an address value
     * @param value The plaintext address
     * @return result Encrypted address handle
     */
    function asEaddress(address value) internal returns (eaddress memory result) {
        bytes32 handle = _createHandle(uint8(FHELib.ValueType.eaddress));
        bytes32 ctHash = keccak256(abi.encode("TRIVIAL", value, block.timestamp));
        result = eaddress(handle, ctHash);
    }

    // ============================================
    // ARITHMETIC OPERATIONS
    // ============================================

    /**
     * @notice Add two encrypted uint256 values
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted sum
     */
    function add(
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.ADD), inputs);
        bytes32 ctHash = keccak256(abi.encode("ADD", a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    /**
     * @notice Add encrypted value and plaintext
     * @param a Encrypted operand
     * @param b Plaintext operand
     * @return result Encrypted sum
     */
    function add(
        euint256 memory a,
        uint256 b
    ) internal returns (euint256 memory result) {
        euint256 memory encryptedB = asEuint256(b);
        return add(a, encryptedB);
    }

    /**
     * @notice Subtract two encrypted uint256 values
     * @param a First operand (minuend)
     * @param b Second operand (subtrahend)
     * @return result Encrypted difference
     */
    function sub(
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.SUB), inputs);
        bytes32 ctHash = keccak256(abi.encode("SUB", a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    /**
     * @notice Subtract plaintext from encrypted value
     * @param a Encrypted operand
     * @param b Plaintext operand
     * @return result Encrypted difference
     */
    function sub(
        euint256 memory a,
        uint256 b
    ) internal returns (euint256 memory result) {
        euint256 memory encryptedB = asEuint256(b);
        return sub(a, encryptedB);
    }

    /**
     * @notice Multiply two encrypted uint256 values
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted product
     */
    function mul(
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.MUL), inputs);
        bytes32 ctHash = keccak256(abi.encode("MUL", a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    /**
     * @notice Multiply encrypted value by plaintext
     * @param a Encrypted operand
     * @param b Plaintext operand
     * @return result Encrypted product
     */
    function mul(
        euint256 memory a,
        uint256 b
    ) internal returns (euint256 memory result) {
        euint256 memory encryptedB = asEuint256(b);
        return mul(a, encryptedB);
    }

    // ============================================
    // COMPARISON OPERATIONS
    // ============================================

    /**
     * @notice Check if a < b (encrypted)
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted boolean result
     */
    function lt(
        euint256 memory a,
        euint256 memory b
    ) internal returns (ebool memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.LT), inputs);
        bytes32 ctHash = keccak256(abi.encode("LT", a.handle, b.handle));
        result = ebool(outputHandle, ctHash);
    }

    /**
     * @notice Check if a <= b (encrypted)
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted boolean result
     */
    function le(
        euint256 memory a,
        euint256 memory b
    ) internal returns (ebool memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.LE), inputs);
        bytes32 ctHash = keccak256(abi.encode("LE", a.handle, b.handle));
        result = ebool(outputHandle, ctHash);
    }

    /**
     * @notice Check if a > b (encrypted)
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted boolean result
     */
    function gt(
        euint256 memory a,
        euint256 memory b
    ) internal returns (ebool memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.GT), inputs);
        bytes32 ctHash = keccak256(abi.encode("GT", a.handle, b.handle));
        result = ebool(outputHandle, ctHash);
    }

    /**
     * @notice Check if a >= b (encrypted)
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted boolean result
     */
    function ge(
        euint256 memory a,
        euint256 memory b
    ) internal returns (ebool memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.GE), inputs);
        bytes32 ctHash = keccak256(abi.encode("GE", a.handle, b.handle));
        result = ebool(outputHandle, ctHash);
    }

    /**
     * @notice Check if a == b (encrypted)
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted boolean result
     */
    function eq(
        euint256 memory a,
        euint256 memory b
    ) internal returns (ebool memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.EQ), inputs);
        bytes32 ctHash = keccak256(abi.encode("EQ", a.handle, b.handle));
        result = ebool(outputHandle, ctHash);
    }

    /**
     * @notice Check if a != b (encrypted)
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted boolean result
     */
    function ne(
        euint256 memory a,
        euint256 memory b
    ) internal returns (ebool memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.NE), inputs);
        bytes32 ctHash = keccak256(abi.encode("NE", a.handle, b.handle));
        result = ebool(outputHandle, ctHash);
    }

    // ============================================
    // BITWISE OPERATIONS
    // ============================================

    /**
     * @notice Bitwise AND of encrypted values
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted AND result
     */
    function and(
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.AND), inputs);
        bytes32 ctHash = keccak256(abi.encode("AND", a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    /**
     * @notice Bitwise OR of encrypted values
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted OR result
     */
    function or(
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.OR), inputs);
        bytes32 ctHash = keccak256(abi.encode("OR", a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    /**
     * @notice Bitwise XOR of encrypted values
     * @param a First operand
     * @param b Second operand
     * @return result Encrypted XOR result
     */
    function xor(
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.XOR), inputs);
        bytes32 ctHash = keccak256(abi.encode("XOR", a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    /**
     * @notice Bitwise NOT of encrypted value
     * @param a Operand
     * @return result Encrypted NOT result
     */
    function not(
        euint256 memory a
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = a.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.NOT), inputs);
        bytes32 ctHash = keccak256(abi.encode("NOT", a.handle));
        result = euint256(outputHandle, ctHash);
    }

    // ============================================
    // CONDITIONAL OPERATIONS
    // ============================================

    /**
     * @notice Conditional select: condition ? a : b
     * @param condition Encrypted boolean condition
     * @param a Value if true
     * @param b Value if false
     * @return result Selected value
     */
    function select(
        ebool memory condition,
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](3);
        inputs[0] = condition.handle;
        inputs[1] = a.handle;
        inputs[2] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.SELECT), inputs);
        bytes32 ctHash = keccak256(abi.encode("SELECT", condition.handle, a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    /**
     * @notice Get minimum of two encrypted values
     * @param a First operand
     * @param b Second operand
     * @return result Minimum value
     */
    function min(
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.MIN), inputs);
        bytes32 ctHash = keccak256(abi.encode("MIN", a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    /**
     * @notice Get maximum of two encrypted values
     * @param a First operand
     * @param b Second operand
     * @return result Maximum value
     */
    function max(
        euint256 memory a,
        euint256 memory b
    ) internal returns (euint256 memory result) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = a.handle;
        inputs[1] = b.handle;
        
        bytes32 outputHandle = _requestCompute(uint8(FHELib.Opcode.MAX), inputs);
        bytes32 ctHash = keccak256(abi.encode("MAX", a.handle, b.handle));
        result = euint256(outputHandle, ctHash);
    }

    // ============================================
    // DECRYPTION
    // ============================================

    /**
     * @notice Request decryption of an encrypted value
     * @param encrypted The encrypted value to decrypt
     * @param callbackContract Contract to receive result
     * @param callbackSelector Function selector for callback
     * @return requestId The decryption request ID
     */
    function decrypt(
        euint256 memory encrypted,
        address callbackContract,
        bytes4 callbackSelector
    ) internal returns (bytes32 requestId) {
        address gateway = getGateway();
        require(gateway != address(0), "FHE: Gateway not set");
        
        requestId = FHEGateway(gateway).requestDecryption(
            encrypted.handle,
            callbackContract,
            callbackSelector,
            uint64(block.timestamp + FHELib.MAX_REQUEST_TTL)
        );
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================

    /**
     * @notice Check if an encrypted value is initialized
     * @param encrypted The encrypted value
     * @return initialized Whether the handle is non-zero
     */
    function isInitialized(
        euint256 memory encrypted
    ) internal pure returns (bool initialized) {
        return encrypted.handle != bytes32(0);
    }

    /**
     * @notice Get the handle from an encrypted value
     * @param encrypted The encrypted value
     * @return handle The handle ID
     */
    function unwrap(
        euint256 memory encrypted
    ) internal pure returns (bytes32 handle) {
        return encrypted.handle;
    }

    /**
     * @notice Wrap a handle as an encrypted value
     * @param handle The handle ID
     * @return encrypted The wrapped encrypted value
     */
    function wrap(bytes32 handle) internal pure returns (euint256 memory encrypted) {
        return euint256(handle, bytes32(0));
    }

    // ============================================
    // INTERNAL HELPERS
    // ============================================

    /**
     * @notice Create a new handle via gateway
     * @param valueType The type of encrypted value
     * @return handle The new handle ID
     */
    function _createHandle(uint8 valueType) private returns (bytes32 handle) {
        address gateway = getGateway();
        require(gateway != address(0), "FHE: Gateway not set");
        
        bytes32 defaultZone = keccak256("DEFAULT");
        handle = FHEGateway(gateway).createHandle(valueType, defaultZone);
    }

    /**
     * @notice Request computation via gateway
     * @param opcode The operation code
     * @param inputs Input handles
     * @return outputHandle The output handle
     */
    function _requestCompute(
        uint8 opcode,
        bytes32[] memory inputs
    ) private returns (bytes32 outputHandle) {
        address gateway = getGateway();
        require(gateway != address(0), "FHE: Gateway not set");
        
        uint64 deadline = uint64(block.timestamp + FHELib.MAX_REQUEST_TTL);
        
        (, outputHandle) = FHEGateway(gateway).requestCompute(
            opcode,
            inputs,
            deadline
        );
    }
}
