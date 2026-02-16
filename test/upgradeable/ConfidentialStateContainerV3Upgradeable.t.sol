// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ConfidentialStateContainerV3Upgradeable} from "../../contracts/upgradeable/ConfidentialStateContainerV3Upgradeable.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";

contract MockCSCVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        return true;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 1;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

contract ConfidentialStateContainerV3UpgradeableTest is Test {
    ConfidentialStateContainerV3Upgradeable public impl;
    ConfidentialStateContainerV3Upgradeable public csc;
    MockCSCVerifier public verifier;
    address admin = address(this);

    function setUp() public {
        verifier = new MockCSCVerifier();
        impl = new ConfidentialStateContainerV3Upgradeable();
        bytes memory data = abi.encodeCall(
            impl.initialize,
            (admin, address(verifier))
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
        csc = ConfidentialStateContainerV3Upgradeable(address(proxy));
    }

    function test_InitializerSetsAdmin() public view {
        assertTrue(csc.hasRole(csc.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_InitializerSetsOperator() public view {
        assertTrue(csc.hasRole(csc.OPERATOR_ROLE(), admin));
    }

    function test_ContractVersion() public view {
        assertEq(csc.contractVersion(), 1);
    }

    function test_CannotDoubleInitialize() public {
        vm.expectRevert();
        csc.initialize(admin, address(verifier));
    }

    function test_RegisterState() public {
        bytes memory encryptedData = hex"deadbeef";
        bytes32 stateHash = keccak256(encryptedData);
        bytes32 ownerCommitment = keccak256(abi.encode(admin));
        bytes memory proof = hex"01";
        bytes32 nullifier = bytes32(uint256(1));

        csc.registerState(
            encryptedData,
            stateHash,
            ownerCommitment,
            proof,
            nullifier
        );

        assertTrue(csc.isStateActive(stateHash));
    }

    function test_PauseUnpause() public {
        csc.pause();
        assertTrue(csc.paused());
        csc.unpause();
        assertFalse(csc.paused());
    }

    function test_LockUnlockState() public {
        bytes memory data = hex"aabb";
        bytes32 stateHash = keccak256(data);
        bytes32 commit = keccak256(abi.encode(admin));
        csc.registerState(
            data,
            stateHash,
            commit,
            hex"01",
            bytes32(uint256(2))
        );

        csc.lockState(stateHash);
        csc.unlockState(stateHash);
    }

    function test_StorageGap() public view {
        // Verify the contract has been deployed via proxy correctly
        assertEq(csc.contractVersion(), 1);
        // totalStates starts at 0 because each test is isolated
        assertEq(csc.totalStates(), 0);
    }
}
