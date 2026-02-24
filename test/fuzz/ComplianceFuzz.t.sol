// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/compliance/SelectiveDisclosureManager.sol";
import "../../contracts/compliance/ComplianceReportingModule.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

// ─── Mock Verifier ──────────────────────────────────────────────────
contract MockComplianceVerifier is IProofVerifier {
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

/**
 * @title ComplianceFuzz
 * @notice Fuzz tests for SelectiveDisclosureManager and ComplianceReportingModule
 * @dev Run with: forge test --match-contract ComplianceFuzz --fuzz-runs 10000
 */
contract ComplianceFuzz is Test {
    SelectiveDisclosureManager public disclosure;
    ComplianceReportingModule public reporting;
    MockComplianceVerifier public verifier;

    address public admin = address(0xAD);
    address public user1 = address(0xF1);
    address public user2 = address(0xF2);
    address public auditor = address(0xA1);

    function setUp() public {
        verifier = new MockComplianceVerifier();

        vm.startPrank(admin);
        disclosure = new SelectiveDisclosureManager(admin, address(verifier));
        reporting = new ComplianceReportingModule(admin, address(verifier));

        // Authorize auditor
        disclosure.authorizeAuditor(auditor);
        reporting.authorizeAuditor(auditor);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
        SECTION 1 — SelectiveDisclosureManager FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz transaction registration with various txId and commitment values
    function testFuzz_registerTransaction(
        bytes32 txId,
        bytes32 commitment,
        uint8 levelRaw
    ) public {
        vm.assume(txId != bytes32(0));
        levelRaw = uint8(bound(levelRaw, 0, 4)); // DisclosureLevel has 5 values
        SelectiveDisclosureManager.DisclosureLevel level = SelectiveDisclosureManager
                .DisclosureLevel(levelRaw);

        vm.prank(user1);
        disclosure.registerTransaction(txId, commitment, level);

        SelectiveDisclosureManager.PrivateTransaction memory txn = disclosure
            .getTransaction(txId);
        assertTrue(txn.exists, "Transaction should exist");
        assertEq(txn.owner, user1);
        assertEq(txn.commitment, commitment);
        assertEq(uint8(txn.defaultLevel), levelRaw);
    }

    /// @notice Fuzz: duplicate txId registration should revert
    function testFuzz_registerTransaction_duplicate(bytes32 txId) public {
        vm.assume(txId != bytes32(0));

        vm.prank(user1);
        disclosure.registerTransaction(
            txId,
            bytes32(uint256(1)),
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        vm.prank(user2);
        vm.expectRevert();
        disclosure.registerTransaction(
            txId,
            bytes32(uint256(2)),
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );
    }

    /// @notice Fuzz viewing key grant with various durations
    function testFuzz_grantViewingKey(bytes32 txId, uint256 duration) public {
        vm.assume(txId != bytes32(0));
        duration = bound(duration, 0, 365 days);

        // Register transaction
        vm.prank(user1);
        disclosure.registerTransaction(
            txId,
            bytes32(uint256(1)),
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        // Grant viewing key
        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](2);
        fields[0] = SelectiveDisclosureManager.FieldType.AMOUNT;
        fields[1] = SelectiveDisclosureManager.FieldType.SENDER;

        vm.prank(user1);
        disclosure.grantViewingKey(
            txId,
            auditor,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            duration,
            fields
        );

        assertTrue(
            disclosure.hasViewingPermission(txId, auditor),
            "Auditor should have viewing permission"
        );

        SelectiveDisclosureManager.ViewingKey memory key = disclosure
            .getViewingKey(txId, auditor);
        assertTrue(key.isActive);
        assertEq(key.viewer, auditor);
        if (duration > 0) {
            assertGt(
                key.expiresAt,
                0,
                "Expiry should be non-zero for timed keys"
            );
        } else {
            assertEq(
                key.expiresAt,
                0,
                "Permanent keys should have expiresAt = 0"
            );
        }
    }

    /// @notice Fuzz: revoking viewing key
    function testFuzz_revokeViewingKey(bytes32 txId) public {
        vm.assume(txId != bytes32(0));

        vm.prank(user1);
        disclosure.registerTransaction(
            txId,
            bytes32(uint256(1)),
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        vm.prank(user1);
        disclosure.grantViewingKey(
            txId,
            auditor,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            0,
            fields
        );

        assertTrue(disclosure.hasViewingPermission(txId, auditor));

        vm.prank(user1);
        disclosure.revokeViewingKey(txId, auditor);

        assertFalse(
            disclosure.hasViewingPermission(txId, auditor),
            "Permission should be revoked"
        );
    }

    /// @notice Fuzz: non-owner cannot grant viewing key
    function testFuzz_grantViewingKey_accessControl(address caller) public {
        vm.assume(caller != user1 && caller != address(0));

        bytes32 txId = keccak256("test-tx");

        vm.prank(user1);
        disclosure.registerTransaction(
            txId,
            bytes32(uint256(1)),
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.AMOUNT;

        vm.prank(caller);
        vm.expectRevert();
        disclosure.grantViewingKey(
            txId,
            auditor,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            0,
            fields
        );
    }

    /// @notice Fuzz: viewer count should match number of unique grants
    function testFuzz_viewerCount(uint8 numViewers) public {
        numViewers = uint8(bound(numViewers, 1, 20));
        bytes32 txId = keccak256("viewer-count-test");

        vm.prank(user1);
        disclosure.registerTransaction(
            txId,
            bytes32(uint256(1)),
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](1);
        fields[0] = SelectiveDisclosureManager.FieldType.ALL;

        for (uint8 i = 0; i < numViewers; i++) {
            address viewer = address(uint160(0x8000 + i));
            vm.prank(user1);
            disclosure.grantViewingKey(
                txId,
                viewer,
                SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
                0,
                fields
            );
        }

        assertEq(
            disclosure.getViewerCount(txId),
            numViewers,
            "Viewer count mismatch"
        );
    }

    /// @notice Fuzz compliance proof submission
    function testFuzz_submitComplianceProof(bytes32 txId) public {
        vm.assume(txId != bytes32(0));

        vm.prank(user1);
        disclosure.registerTransaction(
            txId,
            bytes32(uint256(1)),
            SelectiveDisclosureManager.DisclosureLevel.NONE
        );

        vm.prank(user1);
        bool valid = disclosure.submitComplianceProof(
            txId,
            bytes("proof-data"),
            bytes("public-inputs")
        );

        assertTrue(valid, "Compliance proof should verify");
        assertTrue(
            disclosure.isCompliant(txId),
            "Transaction should be marked compliant"
        );
    }

    /*//////////////////////////////////////////////////////////////
        SECTION 2 — ComplianceReportingModule FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz report generation with various time periods and types
    function testFuzz_generateReport(
        uint8 reportTypeRaw,
        uint48 periodStart,
        uint48 periodEnd,
        uint16 txCount
    ) public {
        // Warp to a reasonable time to allow valid time ranges
        vm.warp(100_000);

        reportTypeRaw = uint8(bound(reportTypeRaw, 0, 5)); // 6 ReportType values
        ComplianceReportingModule.ReportType reportType = ComplianceReportingModule
                .ReportType(reportTypeRaw);

        // Ensure valid time range: start < end <= now
        periodStart = uint48(
            bound(uint256(periodStart), 1, uint256(block.timestamp) - 2)
        );
        periodEnd = uint48(
            bound(
                uint256(periodEnd),
                uint256(periodStart) + 1,
                uint256(block.timestamp)
            )
        );

        address[] memory viewers = new address[](0);

        vm.prank(admin);
        bytes32 reportId = reporting.generateReport(
            user1,
            reportType,
            periodStart,
            periodEnd,
            keccak256("encrypted-data"),
            txCount,
            viewers
        );

        ComplianceReportingModule.ComplianceReport memory report = reporting
            .getReport(reportId);
        assertEq(report.entity, user1);
        assertEq(uint8(report.reportType), reportTypeRaw);
        assertEq(
            uint8(report.status),
            uint8(ComplianceReportingModule.ReportStatus.DRAFT)
        );
        assertEq(report.periodStart, periodStart);
        assertEq(report.periodEnd, periodEnd);
        assertEq(report.txCount, txCount);
    }

    /// @notice Fuzz: invalid time ranges should revert
    function testFuzz_generateReport_invalidTimeRange(
        uint48 periodStart,
        uint48 periodEnd
    ) public {
        // Either start >= end or end > block.timestamp should fail
        vm.assume(
            periodStart >= periodEnd || periodEnd > uint48(block.timestamp)
        );

        address[] memory viewers = new address[](0);

        vm.prank(admin);
        vm.expectRevert();
        reporting.generateReport(
            user1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            periodStart,
            periodEnd,
            keccak256("data"),
            10,
            viewers
        );
    }

    /// @notice Fuzz: report verification with ZK proof
    function testFuzz_verifyReport(bytes32 seed) public {
        // Warp to a reasonable time to allow valid time ranges
        vm.warp(10000);

        address[] memory viewers = new address[](0);

        vm.prank(admin);
        bytes32 reportId = reporting.generateReport(
            user1,
            ComplianceReportingModule.ReportType.AML_CHECK,
            1,
            uint48(block.timestamp) - 1,
            keccak256(abi.encode(seed)),
            5,
            viewers
        );

        vm.prank(admin);
        reporting.verifyReport(reportId, bytes("proof"), bytes("inputs"));

        assertTrue(
            reporting.isReportVerified(reportId),
            "Report should be verified"
        );
        ComplianceReportingModule.ComplianceReport memory report = reporting
            .getReport(reportId);
        assertEq(
            uint8(report.status),
            uint8(ComplianceReportingModule.ReportStatus.VERIFIED)
        );
    }

    /// @notice Fuzz: report viewers management
    function testFuzz_reportViewers(uint8 numViewers) public {
        numViewers = uint8(bound(numViewers, 1, 15));

        // Warp for valid time range
        vm.warp(10000);

        address[] memory initViewers = new address[](0);
        vm.prank(admin);
        bytes32 reportId = reporting.generateReport(
            user1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            1,
            uint48(block.timestamp) - 1,
            keccak256("data"),
            10,
            initViewers
        );

        for (uint8 i = 0; i < numViewers; i++) {
            address viewer = address(uint160(0x9000 + i));
            vm.prank(admin);
            reporting.addReportViewer(reportId, viewer);
            assertTrue(
                reporting.canAccessReport(reportId, viewer),
                "Viewer should have access"
            );
        }

        ComplianceReportingModule.ComplianceReport memory report = reporting
            .getReport(reportId);
        assertEq(report.viewerCount, numViewers);
    }

    /// @notice Fuzz: revoking a report prevents further access
    function testFuzz_revokeReport(bytes32 seed) public {
        vm.warp(10000);

        address[] memory viewers = new address[](1);
        viewers[0] = auditor;

        vm.prank(admin);
        bytes32 reportId = reporting.generateReport(
            user1,
            ComplianceReportingModule.ReportType.KYC_VERIFICATION,
            1,
            uint48(block.timestamp) - 1,
            keccak256(abi.encode(seed)),
            3,
            viewers
        );

        assertTrue(reporting.canAccessReport(reportId, auditor));

        vm.prank(admin);
        reporting.revokeReport(reportId);

        assertFalse(
            reporting.canAccessReport(reportId, auditor),
            "Revoked report should deny access"
        );
    }

    /// @notice Fuzz: non-officer cannot generate reports
    function testFuzz_generateReport_accessControl(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        vm.warp(10000);
        address[] memory viewers = new address[](0);

        vm.prank(caller);
        vm.expectRevert();
        reporting.generateReport(
            user1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            1,
            uint48(block.timestamp) - 1,
            keccak256("data"),
            5,
            viewers
        );
    }

    /// @notice Fuzz: report state transitions — DRAFT → SUBMITTED
    function testFuzz_submitReport(bytes32 seed) public {
        vm.warp(10000);

        address[] memory viewers = new address[](0);
        vm.prank(admin);
        bytes32 reportId = reporting.generateReport(
            user1,
            ComplianceReportingModule.ReportType.REGULATORY_FILING,
            1,
            uint48(block.timestamp) - 1,
            keccak256(abi.encode(seed)),
            10,
            viewers
        );

        vm.prank(admin);
        reporting.submitReport(reportId);

        ComplianceReportingModule.ComplianceReport memory report = reporting
            .getReport(reportId);
        assertEq(
            uint8(report.status),
            uint8(ComplianceReportingModule.ReportStatus.SUBMITTED)
        );
    }

    /// @notice Fuzz: totalReports counter monotonically increases
    function testFuzz_totalReportsMonotonic(uint8 count) public {
        count = uint8(bound(count, 1, 10));
        vm.warp(10000);

        for (uint8 i = 0; i < count; i++) {
            uint256 prevTotal = reporting.totalReports();
            address[] memory viewers = new address[](0);

            vm.prank(admin);
            reporting.generateReport(
                user1,
                ComplianceReportingModule.ReportType.CUSTOM,
                1,
                uint48(block.timestamp) - 1,
                keccak256(abi.encode(i)),
                i + 1,
                viewers
            );

            assertEq(
                reporting.totalReports(),
                prevTotal + 1,
                "totalReports should increment"
            );
        }
    }

    /// @notice Fuzz: zero-address entity should revert
    function testFuzz_generateReport_zeroEntity() public {
        vm.warp(10000);
        address[] memory viewers = new address[](0);

        vm.prank(admin);
        vm.expectRevert();
        reporting.generateReport(
            address(0),
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            1,
            uint48(block.timestamp) - 1,
            keccak256("data"),
            5,
            viewers
        );
    }

    /// @notice Fuzz retention period bounds
    function testFuzz_setRetentionPeriod(uint256 period) public {
        uint256 minRetention = reporting.MIN_RETENTION_PERIOD();
        uint256 maxRetention = reporting.MAX_RETENTION_PERIOD();

        vm.prank(admin);
        if (period < minRetention || period > maxRetention) {
            vm.expectRevert();
            reporting.setDefaultRetentionPeriod(period);
        } else {
            reporting.setDefaultRetentionPeriod(period);
            assertEq(reporting.defaultRetentionPeriod(), period);
        }
    }
}
