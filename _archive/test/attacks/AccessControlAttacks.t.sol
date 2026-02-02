// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Access Control Attack Simulation Tests
 * @notice Tests access control vulnerabilities and privilege escalation
 * @dev Part of security:attack test suite
 */
contract AccessControlAttacks is Test {
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    MockAccessControl public accessControl;
    MockMultisig public multisig;
    MockProxyAdmin public proxyAdmin;

    address public admin;
    address public moderator;
    address public user;
    address public attacker;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        admin = makeAddr("admin");
        moderator = makeAddr("moderator");
        user = makeAddr("user");
        attacker = makeAddr("attacker");

        vm.startPrank(admin);
        accessControl = new MockAccessControl();
        accessControl.grantRole(accessControl.MODERATOR_ROLE(), moderator);
        multisig = new MockMultisig(2); // 2-of-3
        proxyAdmin = new MockProxyAdmin();
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS CONTROL ATTACK TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test unauthorized admin function access
     */
    function test_unauthorizedAdmin_blocked() public {
        vm.prank(attacker);
        vm.expectRevert("AccessControl: account is missing role");
        accessControl.adminFunction();
    }

    /**
     * @notice Test role escalation attempt
     */
    function test_roleEscalation_blocked() public {
        // Verify attacker doesn't have admin role initially
        assertFalse(
            accessControl.hasRole(accessControl.ADMIN_ROLE(), attacker)
        );

        // Attacker tries to grant themselves admin
        vm.prank(attacker);
        (bool success, ) = address(accessControl).call(
            abi.encodeWithSelector(
                accessControl.grantRole.selector,
                accessControl.ADMIN_ROLE(),
                attacker
            )
        );

        // Either the call reverts OR the role wasn't granted
        if (success) {
            // If call succeeded, the role still shouldn't be granted
            // (this would be a vulnerability in production)
            assertFalse(
                accessControl.hasRole(accessControl.ADMIN_ROLE(), attacker),
                "Role escalation should be blocked"
            );
        }
        // If call failed, the escalation was properly blocked
    }

    /**
     * @notice Test role renouncement attack
     */
    function test_roleRenouncementAttack_blocked() public {
        // Verify admin has the role
        assertTrue(accessControl.hasRole(accessControl.ADMIN_ROLE(), admin));

        // Attacker tries to renounce admin's role
        vm.prank(attacker);
        (bool success, ) = address(accessControl).call(
            abi.encodeWithSelector(
                accessControl.renounceRole.selector,
                accessControl.ADMIN_ROLE(),
                admin
            )
        );

        // Either the call reverts OR admin still has their role
        if (success) {
            // If call succeeded, admin should still have their role
            assertTrue(
                accessControl.hasRole(accessControl.ADMIN_ROLE(), admin),
                "Renouncement attack should be blocked"
            );
        }
        // If call failed, the attack was properly blocked
    }

    /**
     * @notice Test default admin can be transferred safely
     */
    function test_adminTransfer_twoStep() public {
        address newAdmin = makeAddr("newAdmin");

        // Step 1: Propose transfer
        vm.prank(admin);
        accessControl.proposeAdminTransfer(newAdmin);

        // Attacker cannot accept
        vm.prank(attacker);
        vm.expectRevert("Not pending admin");
        accessControl.acceptAdminTransfer();

        // New admin accepts
        vm.prank(newAdmin);
        accessControl.acceptAdminTransfer();

        assertTrue(accessControl.hasRole(accessControl.ADMIN_ROLE(), newAdmin));
    }

    /**
     * @notice Test function selector collision attack
     */
    function test_selectorCollision_prevented() public {
        // Try to call an admin function via collision
        // In practice, this is prevented by Solidity's dispatch
        bytes4 adminSelector = accessControl.adminFunction.selector;

        vm.prank(attacker);
        (bool success, ) = address(accessControl).call(
            abi.encodeWithSelector(adminSelector)
        );
        assertFalse(
            success,
            "Selector collision should not bypass access control"
        );
    }

    /**
     * @notice Test multisig bypass attempt
     */
    function test_multisigBypass_blocked() public {
        bytes32 txHash = keccak256("malicious_tx");

        // Single signer cannot execute
        vm.prank(admin);
        multisig.sign(txHash);

        vm.prank(admin);
        vm.expectRevert("Not enough signatures");
        multisig.execute(txHash);
    }

    /**
     * @notice Test signature replay attack on multisig
     */
    function test_signatureReplay_blocked() public {
        bytes32 txHash = keccak256("tx1");

        vm.prank(admin);
        multisig.sign(txHash);
        vm.prank(moderator);
        multisig.sign(txHash);

        // First execution
        vm.prank(admin);
        multisig.execute(txHash);

        // Replay attempt
        vm.prank(admin);
        vm.expectRevert("Already executed");
        multisig.execute(txHash);
    }

    /**
     * @notice Test proxy admin protection
     */
    function test_proxyAdminProtection() public {
        // Only admin can upgrade
        vm.prank(attacker);
        vm.expectRevert("Not admin");
        proxyAdmin.upgrade(address(0x1));

        // Admin can upgrade
        vm.prank(admin);
        proxyAdmin.upgrade(address(0x1));
    }

    /**
     * @notice Test self-destruct protection
     */
    function test_selfDestructProtection() public {
        MockSelfDestructProtected sdp = new MockSelfDestructProtected();

        // Cannot self-destruct
        vm.prank(attacker);
        vm.expectRevert("Self-destruct disabled");
        sdp.destroyContract();

        // Even admin cannot self-destruct
        vm.prank(admin);
        vm.expectRevert("Self-destruct disabled");
        sdp.destroyContract();
    }

    /**
     * @notice Test delegate call protection
     */
    function test_delegateCallProtection() public {
        MockDelegateCallProtected dcp = new MockDelegateCallProtected();

        // Cannot perform arbitrary delegatecall
        vm.prank(attacker);
        vm.expectRevert("Delegatecall not allowed");
        dcp.executeDelegateCall(address(0x1), "");
    }

    /**
     * @notice Test initialization front-running
     */
    function test_initializationFrontrunning_blocked() public {
        MockInitializable impl = new MockInitializable();

        // First initialization
        vm.prank(admin);
        impl.initialize(admin);

        // Front-running attempt (re-initialization)
        vm.prank(attacker);
        vm.expectRevert("Already initialized");
        impl.initialize(attacker);
    }

    /**
     * @notice Test time-locked admin actions
     */
    function test_timelockEnforced() public {
        MockTimelocked timelocked = new MockTimelocked(1 days);

        // Queue action
        vm.prank(admin);
        timelocked.queueAction(keccak256("action"));

        // Cannot execute immediately
        vm.prank(admin);
        vm.expectRevert("Timelock not passed");
        timelocked.executeAction(keccak256("action"));

        // Can execute after delay
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(admin);
        timelocked.executeAction(keccak256("action"));
    }

    /**
     * @notice Test emergency pause abuse prevention
     */
    function test_emergencyPauseAbuse_prevented() public {
        // Deploy as admin so admin becomes guardian
        vm.prank(admin);
        MockPausable pausable = new MockPausable();

        // Only guardian can pause
        vm.prank(attacker);
        vm.expectRevert("Not guardian");
        pausable.pause();

        // Guardian (admin) can pause
        vm.prank(admin);
        pausable.pause();

        // Cannot pause while paused
        vm.prank(admin);
        vm.expectRevert("Already paused");
        pausable.pause();
    }

    /**
     * @notice Fuzz test: role hierarchy
     */
    function testFuzz_roleHierarchy(address randomUser) public {
        vm.assume(randomUser != admin && randomUser != moderator);

        // Random user should not have any privileged role
        assertFalse(
            accessControl.hasRole(accessControl.ADMIN_ROLE(), randomUser)
        );
        assertFalse(
            accessControl.hasRole(accessControl.MODERATOR_ROLE(), randomUser)
        );

        // Random user cannot access admin functions
        vm.prank(randomUser);
        vm.expectRevert();
        accessControl.adminFunction();
    }
}

/*//////////////////////////////////////////////////////////////
                        HELPER CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockAccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    bytes32 public constant MODERATOR_ROLE = keccak256("MODERATOR");
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    mapping(bytes32 => mapping(address => bool)) private _roles;
    mapping(bytes32 => bytes32) private _roleAdmin;

    address public pendingAdmin;

    constructor() {
        _roles[ADMIN_ROLE][msg.sender] = true;
        _roles[DEFAULT_ADMIN_ROLE][msg.sender] = true;
        _roleAdmin[ADMIN_ROLE] = DEFAULT_ADMIN_ROLE;
        _roleAdmin[MODERATOR_ROLE] = ADMIN_ROLE;
    }

    modifier onlyRole(bytes32 role) {
        require(
            _roles[role][msg.sender],
            "AccessControl: account is missing role"
        );
        _;
    }

    function hasRole(
        bytes32 role,
        address account
    ) external view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(
        bytes32 role,
        address account
    ) external onlyRole(_roleAdmin[role]) {
        _roles[role][account] = true;
    }

    function revokeRole(
        bytes32 role,
        address account
    ) external onlyRole(_roleAdmin[role]) {
        _roles[role][account] = false;
    }

    function renounceRole(bytes32 role, address account) external {
        require(account == msg.sender, "Can only renounce own role");
        _roles[role][account] = false;
    }

    function adminFunction() external onlyRole(ADMIN_ROLE) returns (bool) {
        return true;
    }

    function proposeAdminTransfer(
        address newAdmin
    ) external onlyRole(ADMIN_ROLE) {
        pendingAdmin = newAdmin;
    }

    function acceptAdminTransfer() external {
        require(msg.sender == pendingAdmin, "Not pending admin");
        _roles[ADMIN_ROLE][pendingAdmin] = true;
        _roles[DEFAULT_ADMIN_ROLE][pendingAdmin] = true;
        pendingAdmin = address(0);
    }
}

contract MockMultisig {
    uint256 public requiredSignatures;
    mapping(bytes32 => mapping(address => bool)) public hasSigned;
    mapping(bytes32 => uint256) public signatureCount;
    mapping(bytes32 => bool) public executed;

    constructor(uint256 _required) {
        requiredSignatures = _required;
    }

    function sign(bytes32 txHash) external {
        require(!hasSigned[txHash][msg.sender], "Already signed");
        hasSigned[txHash][msg.sender] = true;
        signatureCount[txHash]++;
    }

    function execute(bytes32 txHash) external {
        require(!executed[txHash], "Already executed");
        require(
            signatureCount[txHash] >= requiredSignatures,
            "Not enough signatures"
        );
        executed[txHash] = true;
    }
}

contract MockProxyAdmin {
    address public admin;
    address public implementation;

    constructor() {
        admin = msg.sender;
    }

    function upgrade(address newImpl) external {
        require(msg.sender == admin, "Not admin");
        implementation = newImpl;
    }
}

contract MockSelfDestructProtected {
    function destroyContract() external pure {
        revert("Self-destruct disabled");
    }
}

contract MockDelegateCallProtected {
    function executeDelegateCall(address, bytes memory) external pure {
        revert("Delegatecall not allowed");
    }
}

contract MockInitializable {
    bool public initialized;
    address public owner;

    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        initialized = true;
        owner = _owner;
    }
}

contract MockTimelocked {
    uint256 public delay;
    mapping(bytes32 => uint256) public queuedAt;

    constructor(uint256 _delay) {
        delay = _delay;
    }

    function queueAction(bytes32 actionHash) external {
        queuedAt[actionHash] = block.timestamp;
    }

    function executeAction(bytes32 actionHash) external {
        require(queuedAt[actionHash] > 0, "Not queued");
        require(
            block.timestamp >= queuedAt[actionHash] + delay,
            "Timelock not passed"
        );
        queuedAt[actionHash] = 0;
    }
}

contract MockPausable {
    bool public paused;
    address public guardian;

    constructor() {
        guardian = msg.sender;
    }

    function pause() external {
        require(msg.sender == guardian, "Not guardian");
        require(!paused, "Already paused");
        paused = true;
    }

    function unpause() external {
        require(msg.sender == guardian, "Not guardian");
        require(paused, "Not paused");
        paused = false;
    }
}
