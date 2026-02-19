// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/compliance/ComplianceReportingModule.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

/// @dev Mock verifier for compliance proofs
contract MockReportVerifier is IProofVerifier {
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

contract ComplianceReportingModuleTest is Test {
    ComplianceReportingModule public module;
    MockReportVerifier public mockVerifier;

    address public admin = makeAddr("admin");
    address public officer = makeAddr("officer");
    address public auditor1 = makeAddr("auditor1");
    address public auditor2 = makeAddr("auditor2");
    address public entity1 = makeAddr("entity1");
    address public entity2 = makeAddr("entity2");
    address public viewer1 = makeAddr("viewer1");
    address public viewer2 = makeAddr("viewer2");
    address public unauthorized = makeAddr("unauthorized");

    event ReportGenerated(
        bytes32 indexed reportId,
        address indexed entity,
        ComplianceReportingModule.ReportType reportType,
        uint48 periodStart,
        uint48 periodEnd,
        uint16 txCount
    );
    event ReportVerified(bytes32 indexed reportId, bytes32 proofHash);
    event ReportViewerAdded(bytes32 indexed reportId, address indexed viewer);
    event ReportViewerRemoved(bytes32 indexed reportId, address indexed viewer);
    event ReportAccessed(bytes32 indexed reportId, address indexed accessor);
    event ReportRevoked(bytes32 indexed reportId, address indexed revoker);

    function setUp() public {
        // Set a realistic timestamp so timestamp arithmetic doesn't underflow
        vm.warp(1740000000); // Feb 2025

        mockVerifier = new MockReportVerifier();
        module = new ComplianceReportingModule(admin, address(mockVerifier));

        // Setup roles
        vm.startPrank(admin);
        module.grantRole(module.COMPLIANCE_OFFICER(), officer);
        module.authorizeAuditor(auditor1);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    REPORT GENERATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GenerateReport() public {
        address[] memory viewers = new address[](2);
        viewers[0] = viewer1;
        viewers[1] = viewer2;

        vm.prank(officer);
        bytes32 reportId = module.generateReport(
            entity1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            uint48(block.timestamp - 30 days),
            uint48(block.timestamp - 1),
            keccak256("reportData"),
            100,
            viewers
        );

        assertNotEq(reportId, bytes32(0));
        assertEq(module.totalReports(), 1);

        ComplianceReportingModule.ComplianceReport memory report = module
            .getReport(reportId);
        assertEq(report.entity, entity1);
        assertEq(
            uint8(report.reportType),
            uint8(ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY)
        );
        assertEq(
            uint8(report.status),
            uint8(ComplianceReportingModule.ReportStatus.DRAFT)
        );
        assertEq(report.txCount, 100);
        assertEq(report.viewerCount, 2);
    }

    function test_GenerateReport_WithoutViewers() public {
        address[] memory viewers = new address[](0);

        vm.prank(officer);
        bytes32 reportId = module.generateReport(
            entity1,
            ComplianceReportingModule.ReportType.AML_CHECK,
            uint48(block.timestamp - 7 days),
            uint48(block.timestamp - 1),
            keccak256("amlReport"),
            50,
            viewers
        );

        ComplianceReportingModule.ComplianceReport memory report = module
            .getReport(reportId);
        assertEq(report.viewerCount, 0);
        assertNotEq(reportId, bytes32(0));
    }

    function test_RevertOnGenerateReport_NotOfficer() public {
        address[] memory viewers = new address[](0);

        vm.prank(unauthorized);
        vm.expectRevert();
        module.generateReport(
            entity1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            uint48(block.timestamp - 30 days),
            uint48(block.timestamp - 1),
            keccak256("data"),
            10,
            viewers
        );
    }

    function test_RevertOnGenerateReport_ZeroEntity() public {
        address[] memory viewers = new address[](0);

        vm.prank(officer);
        vm.expectRevert(ComplianceReportingModule.ZeroAddress.selector);
        module.generateReport(
            address(0),
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            uint48(block.timestamp - 30 days),
            uint48(block.timestamp - 1),
            keccak256("data"),
            10,
            viewers
        );
    }

    function test_RevertOnGenerateReport_InvalidTimeRange() public {
        address[] memory viewers = new address[](0);

        // periodStart >= periodEnd
        vm.prank(officer);
        vm.expectRevert(ComplianceReportingModule.InvalidTimeRange.selector);
        module.generateReport(
            entity1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            uint48(block.timestamp),
            uint48(block.timestamp),
            keccak256("data"),
            10,
            viewers
        );
    }

    function test_RevertOnGenerateReport_FutureEnd() public {
        address[] memory viewers = new address[](0);

        vm.prank(officer);
        vm.expectRevert(ComplianceReportingModule.InvalidTimeRange.selector);
        module.generateReport(
            entity1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            uint48(block.timestamp - 30 days),
            uint48(block.timestamp + 1 days),
            keccak256("data"),
            10,
            viewers
        );
    }

    function test_RevertOnGenerateReport_TooManyViewers() public {
        address[] memory viewers = new address[](21);
        for (uint256 i; i < 21; i++) {
            viewers[i] = address(uint160(2000 + i));
        }

        vm.prank(officer);
        vm.expectRevert(ComplianceReportingModule.MaxViewersReached.selector);
        module.generateReport(
            entity1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            uint48(block.timestamp - 30 days),
            uint48(block.timestamp - 1),
            keccak256("data"),
            10,
            viewers
        );
    }

    /*//////////////////////////////////////////////////////////////
                     REPORT VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_VerifyReport() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        vm.prank(officer);
        module.verifyReport(reportId, hex"deadbeef", hex"cafebabe");

        ComplianceReportingModule.ComplianceReport memory report = module
            .getReport(reportId);
        assertEq(
            uint8(report.status),
            uint8(ComplianceReportingModule.ReportStatus.VERIFIED)
        );
        assertNotEq(report.complianceProofHash, bytes32(0));
    }

    function test_RevertOnVerifyReport_InvalidProof() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        mockVerifier.setShouldPass(false);

        vm.prank(officer);
        vm.expectRevert(ComplianceReportingModule.InvalidProof.selector);
        module.verifyReport(reportId, hex"badd", hex"badd");
    }

    function test_RevertOnVerifyReport_NotFound() public {
        vm.prank(officer);
        vm.expectRevert(ComplianceReportingModule.ReportNotFound.selector);
        module.verifyReport(bytes32(uint256(999)), hex"aa", hex"bb");
    }

    function test_SubmitReport() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        vm.prank(officer);
        module.submitReport(reportId);

        ComplianceReportingModule.ComplianceReport memory report = module
            .getReport(reportId);
        assertEq(
            uint8(report.status),
            uint8(ComplianceReportingModule.ReportStatus.SUBMITTED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       REPORT ACCESS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecordReportAccess_Viewer() public {
        bytes32 reportId = _generateReportWithViewer(entity1, viewer1);

        vm.prank(viewer1);
        module.recordReportAccess(reportId, bytes32(0));

        ComplianceReportingModule.ReportAuditEntry[] memory trail = module
            .getReportAuditTrail(reportId);
        assertEq(trail.length, 1);
        assertEq(trail[0].accessor, viewer1);
    }

    function test_RecordReportAccess_Auditor() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        // auditor1 has REPORT_AUDITOR role → can access any report
        vm.prank(auditor1);
        module.recordReportAccess(reportId, bytes32(0));

        ComplianceReportingModule.ReportAuditEntry[] memory trail = module
            .getReportAuditTrail(reportId);
        assertEq(trail.length, 1);
        assertEq(trail[0].accessor, auditor1);
    }

    function test_RevertOnRecordAccess_Unauthorized() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        vm.prank(unauthorized);
        vm.expectRevert(ComplianceReportingModule.UnauthorizedAccess.selector);
        module.recordReportAccess(reportId, bytes32(0));
    }

    function test_RevertOnRecordAccess_Revoked() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        vm.prank(officer);
        module.revokeReport(reportId);

        vm.prank(auditor1);
        vm.expectRevert(ComplianceReportingModule.ReportIsRevoked.selector);
        module.recordReportAccess(reportId, bytes32(0));
    }

    function test_RevertOnRecordAccess_Expired() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        // Warp past retention period (default 365 days)
        vm.warp(block.timestamp + 366 days);

        vm.prank(auditor1);
        vm.expectRevert(ComplianceReportingModule.ReportIsExpired.selector);
        module.recordReportAccess(reportId, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                     VIEWER MANAGEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AddReportViewer() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        vm.prank(officer);
        module.addReportViewer(reportId, viewer1);

        assertTrue(module.canAccessReport(reportId, viewer1));
    }

    function test_RemoveReportViewer() public {
        bytes32 reportId = _generateReportWithViewer(entity1, viewer1);

        assertTrue(module.canAccessReport(reportId, viewer1));

        vm.prank(officer);
        module.removeReportViewer(reportId, viewer1);

        assertFalse(module.canAccessReport(reportId, viewer1));
    }

    function test_RevertOnAddViewer_MaxReached() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        vm.startPrank(officer);
        for (uint256 i; i < 20; i++) {
            module.addReportViewer(reportId, address(uint160(3000 + i)));
        }

        vm.expectRevert(ComplianceReportingModule.MaxViewersReached.selector);
        module.addReportViewer(reportId, makeAddr("overflow"));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       REPORT REVOCATION
    //////////////////////////////////////////////////////////////*/

    function test_RevokeReport() public {
        bytes32 reportId = _generateDefaultReport(entity1);

        vm.prank(officer);
        vm.expectEmit(true, true, false, true);
        emit ReportRevoked(reportId, officer);
        module.revokeReport(reportId);

        ComplianceReportingModule.ComplianceReport memory report = module
            .getReport(reportId);
        assertEq(
            uint8(report.status),
            uint8(ComplianceReportingModule.ReportStatus.REVOKED)
        );
        assertFalse(module.canAccessReport(reportId, auditor1));
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_CanAccessReport_False_NotFound() public view {
        assertFalse(module.canAccessReport(bytes32(uint256(999)), viewer1));
    }

    function test_IsReportVerified() public {
        bytes32 reportId = _generateDefaultReport(entity1);
        assertFalse(module.isReportVerified(reportId));

        vm.prank(officer);
        module.verifyReport(reportId, hex"aa", hex"bb");

        assertTrue(module.isReportVerified(reportId));
    }

    function test_IsReportExpired() public {
        bytes32 reportId = _generateDefaultReport(entity1);
        assertFalse(module.isReportExpired(reportId));

        vm.warp(block.timestamp + 366 days);
        assertTrue(module.isReportExpired(reportId));
    }

    function test_GetEntityReports() public {
        bytes32 r1 = _generateDefaultReport(entity1);
        bytes32 r2 = _generateReport(
            entity1,
            ComplianceReportingModule.ReportType.AML_CHECK
        );

        bytes32[] memory reports = module.getEntityReports(entity1);
        assertEq(reports.length, 2);
        assertEq(reports[0], r1);
        assertEq(reports[1], r2);
    }

    /*//////////////////////////////////////////////////////////////
                     ADMIN / CONFIG TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetComplianceVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(admin);
        module.setComplianceVerifier(newVerifier);
        assertEq(address(module.complianceVerifier()), newVerifier);
    }

    function test_SetRetentionPeriod() public {
        vm.prank(admin);
        module.setDefaultRetentionPeriod(730 days);
        assertEq(module.defaultRetentionPeriod(), 730 days);
    }

    function test_RevertOnSetRetentionPeriod_TooShort() public {
        vm.prank(admin);
        vm.expectRevert(ComplianceReportingModule.RetentionOutOfRange.selector);
        module.setDefaultRetentionPeriod(1 days);
    }

    function test_RevertOnSetRetentionPeriod_TooLong() public {
        vm.prank(admin);
        vm.expectRevert(ComplianceReportingModule.RetentionOutOfRange.selector);
        module.setDefaultRetentionPeriod(3651 days);
    }

    function test_AuthorizeAndRevokeAuditor() public {
        vm.startPrank(officer);
        module.authorizeAuditor(auditor2);
        assertTrue(module.hasRole(module.REPORT_AUDITOR(), auditor2));

        module.revokeAuditor(auditor2);
        assertFalse(module.hasRole(module.REPORT_AUDITOR(), auditor2));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_GenerateReport(uint16 txCount, uint48 offset) public {
        offset = uint48(bound(offset, 1 days, 365 days));
        uint48 start = uint48(block.timestamp) - offset;
        uint48 end = uint48(block.timestamp) - 1;

        address[] memory viewers = new address[](0);

        vm.prank(officer);
        bytes32 reportId = module.generateReport(
            entity1,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            start,
            end,
            keccak256(abi.encodePacked(txCount, offset)),
            txCount,
            viewers
        );

        ComplianceReportingModule.ComplianceReport memory report = module
            .getReport(reportId);
        assertEq(report.txCount, txCount);
        assertEq(report.periodStart, start);
        assertEq(report.periodEnd, end);
    }

    function testFuzz_MultipleReportsSameEntity(uint8 count) public {
        count = uint8(bound(count, 1, 10));

        for (uint8 i; i < count; i++) {
            address[] memory viewers = new address[](0);
            uint48 start = uint48(block.timestamp - (uint256(i) + 2) * 1 days);
            uint48 end = uint48(block.timestamp - (uint256(i) + 1) * 1 days);

            vm.prank(officer);
            module.generateReport(
                entity1,
                ComplianceReportingModule.ReportType(i % 6),
                start,
                end,
                keccak256(abi.encodePacked(i)),
                uint16(i * 10),
                viewers
            );
        }

        assertEq(module.totalReports(), count);
        assertEq(module.getEntityReports(entity1).length, count);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _generateDefaultReport(address entity) internal returns (bytes32) {
        return
            _generateReport(
                entity,
                ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY
            );
    }

    function _generateReport(
        address entity,
        ComplianceReportingModule.ReportType reportType
    ) internal returns (bytes32) {
        address[] memory viewers = new address[](0);

        vm.prank(officer);
        return
            module.generateReport(
                entity,
                reportType,
                uint48(block.timestamp - 30 days),
                uint48(block.timestamp - 1),
                keccak256("reportData"),
                100,
                viewers
            );
    }

    function _generateReportWithViewer(
        address entity,
        address viewer
    ) internal returns (bytes32) {
        address[] memory viewers = new address[](1);
        viewers[0] = viewer;

        vm.prank(officer);
        return
            module.generateReport(
                entity,
                ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
                uint48(block.timestamp - 30 days),
                uint48(block.timestamp - 1),
                keccak256("reportData"),
                100,
                viewers
            );
    }
}
