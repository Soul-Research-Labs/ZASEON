// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TransparentUpgradeableProxy
/// @notice EIP-1967 compliant transparent proxy for upgradeable contracts
/// @dev SECURITY: Uses EIP-1967 storage slots to prevent storage collision with implementation
///      Original implementation stored at slots 0 and 1 which could collide with implementation storage
contract TransparentUpgradeableProxy {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when caller is not admin
    error NotAdmin();
    /// @notice Thrown when implementation address is zero
    error InvalidImplementation();
    /// @notice Thrown when admin address is zero
    error InvalidAdmin();
    /// @notice Thrown when no implementation is set
    error NoImplementation();
    /// @notice Thrown when admin tries to call fallback
    error AdminCannotCallFallback();
    /// @notice Thrown when recipient is zero address
    error InvalidRecipient();
    /// @notice Thrown when balance is insufficient
    error InsufficientBalance();
    /// @notice Thrown when ETH transfer fails
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when implementation is upgraded
    event Upgraded(address indexed newImplementation);
    /// @notice Emitted when admin is changed
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);
    /// @notice Emitted when ETH is withdrawn
    event EmergencyWithdraw(address indexed recipient, uint256 amount);

    /// @dev EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
    bytes32 private constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev EIP-1967 admin slot: keccak256("eip1967.proxy.admin") - 1
    bytes32 private constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    constructor(address _implementation, address _admin) {
        if (_implementation == address(0)) revert InvalidImplementation();
        if (_admin == address(0)) revert InvalidAdmin();
        _setImplementation(_implementation);
        _setAdmin(_admin);
    }

    /// @notice Returns the current implementation address
    function implementation() public view returns (address impl) {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    /// @notice Returns the current admin address
    function admin() public view returns (address adm) {
        bytes32 slot = _ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function upgradeTo(address newImplementation) external {
        if (msg.sender != admin()) revert NotAdmin();
        if (newImplementation == address(0)) revert InvalidImplementation();
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    function changeAdmin(address newAdmin) external {
        if (msg.sender != admin()) revert NotAdmin();
        if (newAdmin == address(0)) revert InvalidAdmin();
        address previousAdmin = admin();
        _setAdmin(newAdmin);
        emit AdminChanged(previousAdmin, newAdmin);
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _setAdmin(address newAdmin) private {
        bytes32 slot = _ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }

    /* solhint-disable-next-line no-complex-fallback */
    fallback() external payable {
        address impl = implementation();
        if (impl == address(0)) revert NoImplementation();

        // SECURITY: Prevent admin from calling implementation functions
        // to avoid function selector collision attacks
        if (msg.sender == admin()) revert AdminCannotCallFallback();

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}

    /// @notice Emergency withdraw ETH locked in proxy
    /// @param recipient Address to receive withdrawn ETH
    /// @param amount Amount of ETH to withdraw
    /// @dev Only callable by admin
    function emergencyWithdrawETH(
        address payable recipient,
        uint256 amount
    ) external {
        if (msg.sender != admin()) revert NotAdmin();
        if (recipient == address(0)) revert InvalidRecipient();
        if (amount > address(this).balance) revert InsufficientBalance();

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit EmergencyWithdraw(recipient, amount);
    }
}
