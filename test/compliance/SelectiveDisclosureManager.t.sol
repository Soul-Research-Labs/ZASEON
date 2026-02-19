// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/compliance/SelectiveDisclosureManager.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

/// @dev Mock verifier that always returns true
contract MockComplianceVerifier is IProofVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool _pass) external {
        shouldPass = _pass;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view returns (bool) {
        return shouldPass;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 1;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

contract SelectiveDisclosureManagerTest is Test {
    SelectiveDisclosureManager public manager;
    MockComplianceVerifier public mockVerifier;

    address public admin = makeAddr("admin");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public auditor = makeAddr("auditor");
    address public regulator = makeAddr("regulator");
    address public viewer1 = makeAddr("viewer1");

    bytes32 public constant TX_ID_1 = keccak256("tx1");
    bytes32 public constant TX_ID_2 = keccak256("tx2");
    bytes32 public constant COMMITMENT_1 = keccak256("commitment1");
    bytes32 public constant COMMITMENT_2 = keccak256("commitment2");

    event TransactionRegistered(
        bytes32 indexed txId,
        address indexed owner,
        SelectiveDisclosureManager.DisclosureLevel defaultLevel
    );
    event ViewingKeyGranted(
        bytes32 indexed txId,
        address indexed viewer,
        SelectiveDisclosureManager.DisclosureLevel level,
        uint256 expiresAt
    );
    event ViewingKeyRevoked(bytes32 indexed txId, address indexed viewer);
    event TransactionViewed(
        bytes32 indexed txId,
        address indexed viewer,
        uint256 fieldCount
    );
    event ComplianceProofVerified(bytes32 indexed txId, bytes32 proofHash);
    event AuditorAuthorized(address indexed auditor);
    event RegulatorAuthorized(address indexed regulator);

    function setUp() public {
        mockVerifier = new MockComplianceVerifier();
        manager = new SelectiveDisclosureManager(admin, address(mockVerifier));

        vm.startPrank(admin);
        manager.authorizeAuditor(auditor);
        manager.authorizeRegulator(regulator);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        REGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RegisterTransaction() public {
        vm.prank(user1);
        vm.expectEmit(true, true, false, true);
        emit TransactionRegistered(
            TX_ID_1,
            user1,
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        manager.registerTransaction(
            TX_ID_1,
            COMMITMENT_1,
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        SelectiveDisclosureManager.PrivateTransaction memory txn = manager
            .getTransaction(TX_ID_1);
        assertEq(txn.commitment, COMMITMENT_1);
        assertEq(txn.owner, user1);
        assertTrue(txn.exists);
        assertEq(
            uint8(txn.defaultLevel),
            uint8(SelectiveDisclosureManager.DisclosureLevel.NONE)
        );
    }

    function test_RevertOnDuplicateRegistration() public {
        vm.startPrank(user1);
        manager.registerTransaction(
            TX_ID_1,
            COMMITMENT_1,
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        vm.expectRevert(
            SelectiveDisclosureManager.TransactionAlreadyExists.selector
        );
        manager.registerTransaction(
            TX_ID_1,
            COMMITMENT_2,
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );
        vm.stopPrank();
    }

    function test_RegisterTransactionFor() public {
        vm.prank(admin);
        manager.registerTransactionFor(
            TX_ID_1,
            COMMITMENT_1,
            user1,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR
        );

        SelectiveDisclosureManager.PrivateTransaction memory txn = manager
            .getTransaction(TX_ID_1);
        assertEq(txn.owner, user1);
        assertEq(
            uint8(txn.defaultLevel),
            uint8(SelectiveDisclosureManager.DisclosureLevel.AUDITOR)
        );
    }

    function test_RevertOnRegisterTransactionFor_NotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        manager.registerTransactionFor(
            TX_ID_1,
            COMMITMENT_1,
            user1,
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );
    }

    function test_RevertOnRegisterTransactionFor_ZeroOwner() public {
        vm.prank(admin);
        vm.expectRevert(SelectiveDisclosureManager.ZeroAddress.selector);
        manager.registerTransactionFor(
            TX_ID_1,
            COMMITMENT_1,
            address(0),
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );
    }

    /*//////////////////////////////////////////////////////////////
                      VIEWING KEY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GrantViewingKey() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](2);
        fields[0] = SelectiveDisclosureManager.FieldType.AMOUNT;
        fields[1] = SelectiveDisclosureManager.FieldType.SENDER;

        vm.prank(user1);
        manager.grantViewingKey(
            TX_ID_1,
            viewer1,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            1 hours,
            fields
        );

        assertTrue(manager.hasViewingPermission(TX_ID_1, viewer1));
        assertEq(manager.getViewerCount(TX_ID_1), 1);
    }

    function test_GrantViewingKey_Permanent() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(user1);
        manager.grantViewingKey(
            TX_ID_1,
            viewer1,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            0,
            fields
        );

        assertTrue(manager.hasViewingPermission(TX_ID_1, viewer1));

        // Check permanent key (expiresAt == 0)
        SelectiveDisclosureManager.ViewingKey memory key = manager
            .getViewingKey(TX_ID_1, viewer1);
        assertEq(key.expiresAt, 0);
        assertTrue(key.isActive);
    }

    function test_RevokeViewingKey() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _grantAllAccess(user1, TX_ID_1, viewer1, 1 hours);

        assertTrue(manager.hasViewingPermission(TX_ID_1, viewer1));

        vm.prank(user1);
        vm.expectEmit(true, true, false, true);
        emit ViewingKeyRevoked(TX_ID_1, viewer1);
        manager.revokeViewingKey(TX_ID_1, viewer1);

        assertFalse(manager.hasViewingPermission(TX_ID_1, viewer1));
    }

    function test_ViewingKeyExpiration() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _grantAllAccess(user1, TX_ID_1, viewer1, 1 hours);

        assertTrue(manager.hasViewingPermission(TX_ID_1, viewer1));

        // Warp past expiration
        vm.warp(block.timestamp + 2 hours);

        assertFalse(manager.hasViewingPermission(TX_ID_1, viewer1));
    }

    function test_RevertOnGrantViewingKey_NotOwner() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(user2);
        vm.expectRevert(
            SelectiveDisclosureManager.NotTransactionOwner.selector
        );
        manager.grantViewingKey(
            TX_ID_1,
            viewer1,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            1 hours,
            fields
        );
    }

    function test_RevertOnGrantViewingKey_ZeroAddress() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(user1);
        vm.expectRevert(SelectiveDisclosureManager.ZeroAddress.selector);
        manager.grantViewingKey(
            TX_ID_1,
            address(0),
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            1 hours,
            fields
        );
    }

    function test_RevertOnGrantViewingKey_TxNotFound() public {
        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(user1);
        vm.expectRevert(
            SelectiveDisclosureManager.TransactionNotFound.selector
        );
        manager.grantViewingKey(
            TX_ID_1,
            viewer1,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            1 hours,
            fields
        );
    }

    function test_OwnerAlwaysHasPermission() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        assertTrue(manager.hasViewingPermission(TX_ID_1, user1));
    }

    function test_NoPermissionForUnknownViewer() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        assertFalse(manager.hasViewingPermission(TX_ID_1, viewer1));
    }

    /*//////////////////////////////////////////////////////////////
                      BATCH OPERATIONS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_BatchGrantViewingKeys() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _registerTx(user1, TX_ID_2, COMMITMENT_2);

        bytes32[] memory txIds = new bytes32[](2);
        txIds[0] = TX_ID_1;
        txIds[1] = TX_ID_2;

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(user1);
        manager.batchGrantViewingKeys(
            txIds,
            viewer1,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            1 hours,
            fields
        );

        assertTrue(manager.hasViewingPermission(TX_ID_1, viewer1));
        assertTrue(manager.hasViewingPermission(TX_ID_2, viewer1));
    }

    function test_RevertOnBatchTooLarge() public {
        bytes32[] memory txIds = new bytes32[](51);
        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(user1);
        vm.expectRevert(SelectiveDisclosureManager.BatchTooLarge.selector);
        manager.batchGrantViewingKeys(
            txIds,
            viewer1,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            1 hours,
            fields
        );
    }

    /*//////////////////////////////////////////////////////////////
                      RECORD VIEW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecordView_OwnerCanView() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(user1);
        bool authorized = manager.recordView(TX_ID_1, fields);
        assertTrue(authorized);

        SelectiveDisclosureManager.AuditEntry[] memory trail = manager
            .getAuditTrail(TX_ID_1);
        assertEq(trail.length, 1);
        assertEq(trail[0].viewer, user1);
        assertEq(trail[0].fieldCount, 1);
    }

    function test_RecordView_AuthorizedViewer() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _grantAllAccess(user1, TX_ID_1, viewer1, 1 hours);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](2);
        fields[0] = SelectiveDisclosureManager.FieldType.AMOUNT;
        fields[1] = SelectiveDisclosureManager.FieldType.SENDER;

        // viewer1 has ALL access, so any field works
        vm.prank(viewer1);
        bool authorized = manager.recordView(TX_ID_1, fields);
        assertTrue(authorized);
    }

    function test_RevertOnRecordView_Unauthorized() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(viewer1);
        vm.expectRevert(
            SelectiveDisclosureManager.ViewingKeyNotActive.selector
        );
        manager.recordView(TX_ID_1, fields);
    }

    function test_RevertOnRecordView_Expired() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _grantAllAccess(user1, TX_ID_1, viewer1, 1 hours);

        vm.warp(block.timestamp + 2 hours);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(viewer1);
        vm.expectRevert(SelectiveDisclosureManager.ViewingKeyExpired.selector);
        manager.recordView(TX_ID_1, fields);
    }

    function test_RevertOnRecordView_FieldNotAllowed() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        // Grant only AMOUNT access
        SelectiveDisclosureManager.FieldType[]
            memory grantFields = new SelectiveDisclosureManager.FieldType[](1);
        grantFields[0] = SelectiveDisclosureManager.FieldType.AMOUNT;

        vm.prank(user1);
        manager.grantViewingKey(
            TX_ID_1,
            viewer1,
            SelectiveDisclosureManager.DisclosureLevel.COUNTERPARTY,
            1 hours,
            grantFields
        );

        // Try to view SENDER (not allowed)
        SelectiveDisclosureManager.FieldType[]
            memory viewFields = new SelectiveDisclosureManager.FieldType[](1);
        viewFields[0] = SelectiveDisclosureManager.FieldType.SENDER;

        vm.prank(viewer1);
        vm.expectRevert(
            abi.encodeWithSelector(
                SelectiveDisclosureManager.FieldNotAllowed.selector,
                SelectiveDisclosureManager.FieldType.SENDER
            )
        );
        manager.recordView(TX_ID_1, viewFields);
    }

    /*//////////////////////////////////////////////////////////////
                    COMPLIANCE PROOF TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SubmitComplianceProof() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        bytes memory proof = hex"deadbeef";
        bytes memory publicInputs = hex"cafebabe";

        vm.prank(user1);
        bool valid = manager.submitComplianceProof(
            TX_ID_1,
            proof,
            publicInputs
        );
        assertTrue(valid);
        assertTrue(manager.isCompliant(TX_ID_1));
    }

    function test_RevertOnComplianceProof_InvalidProof() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        mockVerifier.setShouldPass(false);

        vm.prank(user1);
        vm.expectRevert(SelectiveDisclosureManager.InvalidProof.selector);
        manager.submitComplianceProof(TX_ID_1, hex"aa", hex"bb");
    }

    function test_RevertOnComplianceProof_NoVerifier() public {
        // Deploy manager without verifier
        SelectiveDisclosureManager noVerifierManager = new SelectiveDisclosureManager(
                admin,
                address(0)
            );

        vm.prank(user1);
        noVerifierManager.registerTransaction(
            TX_ID_1,
            COMMITMENT_1,
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        vm.prank(user1);
        vm.expectRevert(
            SelectiveDisclosureManager.NoVerifierConfigured.selector
        );
        noVerifierManager.submitComplianceProof(TX_ID_1, hex"aa", hex"bb");
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AuthorizeAuditor() public {
        address newAuditor = makeAddr("newAuditor");

        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit AuditorAuthorized(newAuditor);
        manager.authorizeAuditor(newAuditor);

        assertTrue(manager.hasRole(manager.AUDITOR_ROLE(), newAuditor));
    }

    function test_RevokeAuditor() public {
        vm.prank(admin);
        manager.revokeAuditor(auditor);
        assertFalse(manager.hasRole(manager.AUDITOR_ROLE(), auditor));
    }

    function test_AuthorizeRegulator() public {
        address newReg = makeAddr("newRegulator");
        vm.prank(admin);
        manager.authorizeRegulator(newReg);
        assertTrue(manager.hasRole(manager.REGULATOR_ROLE(), newReg));
    }

    function test_RevertOnAuthorizeAuditor_NotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        manager.authorizeAuditor(makeAddr("x"));
    }

    function test_RevertOnAuthorizeAuditor_ZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(SelectiveDisclosureManager.ZeroAddress.selector);
        manager.authorizeAuditor(address(0));
    }

    function test_SetComplianceVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(admin);
        manager.setComplianceVerifier(newVerifier);
        assertEq(address(manager.complianceVerifier()), newVerifier);
    }

    function test_SetUserDefaultLevel() public {
        vm.prank(admin);
        manager.setUserDefaultLevel(
            user1,
            SelectiveDisclosureManager.DisclosureLevel.REGULATOR
        );
        assertEq(
            uint8(manager.userDefaultLevel(user1)),
            uint8(SelectiveDisclosureManager.DisclosureLevel.REGULATOR)
        );
    }

    /*//////////////////////////////////////////////////////////////
                      MAX VIEWERS BOUND TEST
    //////////////////////////////////////////////////////////////*/

    function test_MaxViewersEnforced() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        // Grant 50 viewers (maximum)
        vm.startPrank(user1);
        for (uint256 i; i < 50; i++) {
            address v = address(uint160(1000 + i));
            manager.grantViewingKey(
                TX_ID_1,
                v,
                SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
                1 hours,
                fields
            );
        }

        // 51st should revert
        vm.expectRevert(SelectiveDisclosureManager.MaxViewersReached.selector);
        manager.grantViewingKey(
            TX_ID_1,
            makeAddr("overflow"),
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            1 hours,
            fields
        );
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_RegisterTransaction(
        bytes32 txId,
        bytes32 commitment
    ) public {
        vm.assume(txId != bytes32(0));
        vm.assume(commitment != bytes32(0));

        vm.prank(user1);
        manager.registerTransaction(
            txId,
            commitment,
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        SelectiveDisclosureManager.PrivateTransaction memory txn = manager
            .getTransaction(txId);
        assertEq(txn.commitment, commitment);
        assertEq(txn.owner, user1);
        assertTrue(txn.exists);
    }

    function testFuzz_GrantAndCheckPermission(uint256 duration) public {
        duration = bound(duration, 1, 365 days);

        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _grantAllAccess(user1, TX_ID_1, viewer1, duration);

        assertTrue(manager.hasViewingPermission(TX_ID_1, viewer1));

        // Warp past expiration
        vm.warp(block.timestamp + duration + 1);
        assertFalse(manager.hasViewingPermission(TX_ID_1, viewer1));
    }

    function testFuzz_ReGrantAfterRevoke(
        uint256 duration1,
        uint256 duration2
    ) public {
        duration1 = bound(duration1, 1, 365 days);
        duration2 = bound(duration2, 1, 365 days);

        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _grantAllAccess(user1, TX_ID_1, viewer1, duration1);
        assertTrue(manager.hasViewingPermission(TX_ID_1, viewer1));

        vm.prank(user1);
        manager.revokeViewingKey(TX_ID_1, viewer1);
        assertFalse(manager.hasViewingPermission(TX_ID_1, viewer1));

        // Re-grant
        _grantAllAccess(user1, TX_ID_1, viewer1, duration2);
        assertTrue(manager.hasViewingPermission(TX_ID_1, viewer1));
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetTransactionViewers() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _grantAllAccess(user1, TX_ID_1, viewer1, 1 hours);

        address[] memory viewers = manager.getTransactionViewers(TX_ID_1);
        assertEq(viewers.length, 1);
        assertEq(viewers[0], viewer1);
    }

    function test_GetViewingKeyDetails() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        _grantAllAccess(user1, TX_ID_1, viewer1, 1 hours);

        SelectiveDisclosureManager.ViewingKey memory key = manager
            .getViewingKey(TX_ID_1, viewer1);
        assertEq(key.viewer, viewer1);
        assertTrue(key.isActive);
        assertEq(
            uint8(key.level),
            uint8(SelectiveDisclosureManager.DisclosureLevel.AUDITOR)
        );
    }

    function test_NonExistentTxPermission() public {
        assertFalse(manager.hasViewingPermission(TX_ID_1, viewer1));
    }

    function test_IsCompliant_False() public {
        _registerTx(user1, TX_ID_1, COMMITMENT_1);
        assertFalse(manager.isCompliant(TX_ID_1));
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _registerTx(
        address owner,
        bytes32 txId,
        bytes32 commitment
    ) internal {
        vm.prank(owner);
        manager.registerTransaction(
            txId,
            commitment,
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );
    }

    function _grantAllAccess(
        address owner,
        bytes32 txId,
        address viewer,
        uint256 duration
    ) internal {
        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(owner);
        manager.grantViewingKey(
            txId,
            viewer,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            duration,
            fields
        );
    }
}
