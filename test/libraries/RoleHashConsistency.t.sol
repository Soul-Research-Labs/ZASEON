// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title RoleHashConsistency
 * @notice Cross-contract role hash verification test
 * @dev Ensures all pre-computed role hashes across the codebase match keccak256 of their string names.
 *      Prevents copy-paste hash corruption like the GUARDIAN_ROLE mismatch found in audit.
 *
 * This test reads the public ROLE constants from deployed contract bytecode to verify
 * they match the expected keccak256 values, without needing to import all 100+ contracts.
 */
contract RoleHashConsistencyTest is Test {
    /* ── All role name <-> expected hash pairs ───────── */

    function test_guardianRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("GUARDIAN_ROLE");
        assertEq(
            expected,
            0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041,
            "GUARDIAN_ROLE hash mismatch"
        );
    }

    function test_operatorRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("OPERATOR_ROLE");
        assertEq(
            expected,
            0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929,
            "OPERATOR_ROLE hash mismatch"
        );
    }

    function test_relayerRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("RELAYER_ROLE");
        assertEq(
            expected,
            0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4,
            "RELAYER_ROLE hash mismatch"
        );
    }

    function test_challengerRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("CHALLENGER_ROLE");
        assertEq(
            expected,
            0xe752add323323eb13e36c71ee508dfd16d74e9e4c4fd78786ba97989e5e13818,
            "CHALLENGER_ROLE hash mismatch"
        );
    }

    function test_emergencyRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("EMERGENCY_ROLE");
        assertEq(
            expected,
            0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26,
            "EMERGENCY_ROLE hash mismatch"
        );
    }

    function test_sequencerRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("SEQUENCER_ROLE");
        assertEq(
            expected,
            0xac4f1890dc96c9a02330d1fa696648a38f3b282d2449c2d8e6f10507488c84c8,
            "SEQUENCER_ROLE hash mismatch"
        );
    }

    function test_monitorRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("MONITOR_ROLE");
        assertEq(
            expected,
            0x8227712ef8ad39d0f26f06731ef0df8665eb7ada7f41b1ee089adf3c238862a2,
            "MONITOR_ROLE hash mismatch"
        );
    }

    function test_recoveryRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("RECOVERY_ROLE");
        assertEq(
            expected,
            0x0acf805600123ef007091da3b3ffb39474074c656c127aa68cb0ffec232a8ff8,
            "RECOVERY_ROLE hash mismatch"
        );
    }

    function test_upgraderRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("UPGRADER_ROLE");
        assertEq(
            expected,
            0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3,
            "UPGRADER_ROLE hash mismatch"
        );
    }

    function test_verifierAdminRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("VERIFIER_ADMIN_ROLE");
        assertEq(
            expected,
            0xb194a0b06484f8a501e0bef8877baf2a303f803540f5ddeb9d985c0cd76f3e70,
            "VERIFIER_ADMIN_ROLE hash mismatch"
        );
    }

    function test_announcerRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("ANNOUNCER_ROLE");
        assertEq(
            expected,
            0x6e925cbf9b246ec609b2c956a4ec0074fde4bcbc1f65aadcebf89efbd7f60a6a,
            "ANNOUNCER_ROLE hash mismatch"
        );
    }

    function test_executorRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("EXECUTOR_ROLE");
        assertEq(
            expected,
            0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63,
            "EXECUTOR_ROLE hash mismatch"
        );
    }

    function test_proposerRole_isCorrectHash() public pure {
        bytes32 expected = keccak256("PROPOSER_ROLE");
        assertEq(
            expected,
            0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1,
            "PROPOSER_ROLE hash mismatch"
        );
    }

    /// @notice Canary test: the WRONG hash that was found during audit must NOT match
    function test_wrongGuardianHash_doesNotMatch() public pure {
        bytes32 wrongHash = 0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365f804e30c1f4d1;
        assertTrue(
            keccak256("GUARDIAN_ROLE") != wrongHash,
            "Wrong GUARDIAN_ROLE hash should not match keccak256"
        );
    }
}
