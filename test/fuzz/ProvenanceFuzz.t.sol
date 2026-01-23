// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/provenance/ProvenancePrimitives.sol";

/**
 * @title ProvenanceFuzz
 * @notice Comprehensive fuzz tests for Provenance Blockchain integration
 * @dev Tests Tendermint BFT, Marker module, IBC, and cross-domain nullifiers
 */
contract ProvenanceFuzz is Test {
    using ProvenancePrimitives for *;

    // =========================================================================
    // CONSTANTS FOR TESTING
    // =========================================================================

    uint256 constant PROV_SECP256K1_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant QUORUM_THRESHOLD_BPS = 6667;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {}

    // =========================================================================
    // HASH FUNCTION TESTS
    // =========================================================================

    function testFuzz_SHA256Hash_Determinism(bytes memory data) public pure {
        bytes32 hash1 = ProvenancePrimitives.sha256Hash(data);
        bytes32 hash2 = ProvenancePrimitives.sha256Hash(data);
        assertEq(hash1, hash2, "SHA256 should be deterministic");
    }

    function testFuzz_SHA256Hash_NonZero(bytes memory data) public pure {
        vm.assume(data.length > 0);
        bytes32 hash = ProvenancePrimitives.sha256Hash(data);
        assertTrue(
            hash != bytes32(0),
            "SHA256 of non-empty data should be non-zero"
        );
    }

    function testFuzz_SHA256Hash_Collision(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));
        bytes32 hash1 = ProvenancePrimitives.sha256Hash(data1);
        bytes32 hash2 = ProvenancePrimitives.sha256Hash(data2);
        assertNotEq(
            hash1,
            hash2,
            "Different inputs should produce different SHA256 hashes"
        );
    }

    function testFuzz_PubkeyToAddress(
        bytes32 pubkeyPart1,
        bytes1 pubkeyByte
    ) public pure {
        bytes memory pubkey = abi.encodePacked(pubkeyByte, pubkeyPart1);
        bytes20 addr = ProvenancePrimitives.pubkeyToAddress(pubkey);
        // Address should be derived consistently
        bytes20 addr2 = ProvenancePrimitives.pubkeyToAddress(pubkey);
        assertEq(addr, addr2, "Address derivation should be deterministic");
    }

    // =========================================================================
    // BLOCK HEADER TESTS
    // =========================================================================

    function testFuzz_BlockHeaderHash_Determinism(
        int64 height,
        uint64 timestamp,
        bytes32 lastBlockId,
        bytes32 validatorsHash,
        bytes32 appHash
    ) public pure {
        vm.assume(height > 0);

        ProvenancePrimitives.BlockHeader memory header = ProvenancePrimitives
            .BlockHeader({
                height: height,
                timestamp: timestamp,
                lastBlockId: lastBlockId,
                dataHash: bytes32(0),
                validatorsHash: validatorsHash,
                nextValidatorsHash: validatorsHash,
                consensusHash: bytes32(0),
                appHash: appHash,
                lastResultsHash: bytes32(0),
                evidenceHash: bytes32(0),
                proposerAddress: new bytes(20)
            });

        bytes32 hash1 = ProvenancePrimitives.computeBlockHeaderHash(header);
        bytes32 hash2 = ProvenancePrimitives.computeBlockHeaderHash(header);

        assertEq(hash1, hash2, "Block header hash should be deterministic");
    }

    function testFuzz_BlockHeaderHash_DifferentHeights(
        int64 height1,
        int64 height2,
        bytes32 lastBlockId,
        bytes32 validatorsHash,
        bytes32 appHash
    ) public pure {
        vm.assume(height1 > 0 && height2 > 0 && height1 != height2);

        ProvenancePrimitives.BlockHeader memory header1 = ProvenancePrimitives
            .BlockHeader({
                height: height1,
                timestamp: 0,
                lastBlockId: lastBlockId,
                dataHash: bytes32(0),
                validatorsHash: validatorsHash,
                nextValidatorsHash: validatorsHash,
                consensusHash: bytes32(0),
                appHash: appHash,
                lastResultsHash: bytes32(0),
                evidenceHash: bytes32(0),
                proposerAddress: new bytes(20)
            });

        ProvenancePrimitives.BlockHeader memory header2 = ProvenancePrimitives
            .BlockHeader({
                height: height2,
                timestamp: 0,
                lastBlockId: lastBlockId,
                dataHash: bytes32(0),
                validatorsHash: validatorsHash,
                nextValidatorsHash: validatorsHash,
                consensusHash: bytes32(0),
                appHash: appHash,
                lastResultsHash: bytes32(0),
                evidenceHash: bytes32(0),
                proposerAddress: new bytes(20)
            });

        bytes32 hash1 = ProvenancePrimitives.computeBlockHeaderHash(header1);
        bytes32 hash2 = ProvenancePrimitives.computeBlockHeaderHash(header2);

        assertNotEq(
            hash1,
            hash2,
            "Different heights should produce different hashes"
        );
    }

    // =========================================================================
    // NULLIFIER TESTS
    // =========================================================================

    function testFuzz_ProvenanceNullifier_Determinism(
        bytes32 txHash,
        int64 blockHeight,
        bytes32 scopeId,
        string memory denom
    ) public pure {
        vm.assume(blockHeight > 0);

        bytes32 nf1 = ProvenancePrimitives.deriveProvenanceNullifier(
            txHash,
            blockHeight,
            scopeId,
            denom
        );
        bytes32 nf2 = ProvenancePrimitives.deriveProvenanceNullifier(
            txHash,
            blockHeight,
            scopeId,
            denom
        );

        assertEq(nf1, nf2, "Provenance nullifier should be deterministic");
    }

    function testFuzz_ProvenanceNullifier_Uniqueness(
        bytes32 txHash1,
        bytes32 txHash2,
        int64 blockHeight,
        bytes32 scopeId,
        string memory denom
    ) public pure {
        vm.assume(blockHeight > 0);
        vm.assume(txHash1 != txHash2);

        bytes32 nf1 = ProvenancePrimitives.deriveProvenanceNullifier(
            txHash1,
            blockHeight,
            scopeId,
            denom
        );
        bytes32 nf2 = ProvenancePrimitives.deriveProvenanceNullifier(
            txHash2,
            blockHeight,
            scopeId,
            denom
        );

        assertNotEq(
            nf1,
            nf2,
            "Different txHashes should produce different nullifiers"
        );
    }

    function testFuzz_ProvenanceNullifier_BlockHeightSensitive(
        bytes32 txHash,
        int64 blockHeight1,
        int64 blockHeight2,
        bytes32 scopeId,
        string memory denom
    ) public pure {
        vm.assume(
            blockHeight1 > 0 && blockHeight2 > 0 && blockHeight1 != blockHeight2
        );

        bytes32 nf1 = ProvenancePrimitives.deriveProvenanceNullifier(
            txHash,
            blockHeight1,
            scopeId,
            denom
        );
        bytes32 nf2 = ProvenancePrimitives.deriveProvenanceNullifier(
            txHash,
            blockHeight2,
            scopeId,
            denom
        );

        assertNotEq(
            nf1,
            nf2,
            "Different block heights should produce different nullifiers"
        );
    }

    function testFuzz_CrossDomainNullifier_Determinism(
        bytes32 provenanceNullifier,
        uint256 targetDomain
    ) public pure {
        bytes32 crossNf1 = ProvenancePrimitives.deriveCrossDomainNullifier(
            provenanceNullifier,
            targetDomain
        );
        bytes32 crossNf2 = ProvenancePrimitives.deriveCrossDomainNullifier(
            provenanceNullifier,
            targetDomain
        );

        assertEq(
            crossNf1,
            crossNf2,
            "Cross-domain nullifier should be deterministic"
        );
    }

    function testFuzz_CrossDomainNullifier_DomainSensitive(
        bytes32 provenanceNullifier,
        uint256 domain1,
        uint256 domain2
    ) public pure {
        vm.assume(domain1 != domain2);

        bytes32 crossNf1 = ProvenancePrimitives.deriveCrossDomainNullifier(
            provenanceNullifier,
            domain1
        );
        bytes32 crossNf2 = ProvenancePrimitives.deriveCrossDomainNullifier(
            provenanceNullifier,
            domain2
        );

        assertNotEq(
            crossNf1,
            crossNf2,
            "Different domains should produce different nullifiers"
        );
    }

    function testFuzz_PILBinding_Determinism(
        bytes32 provenanceNullifier,
        bytes32 pilDomain
    ) public pure {
        bytes32 binding1 = ProvenancePrimitives.derivePILBinding(
            provenanceNullifier,
            pilDomain
        );
        bytes32 binding2 = ProvenancePrimitives.derivePILBinding(
            provenanceNullifier,
            pilDomain
        );

        assertEq(binding1, binding2, "PIL binding should be deterministic");
    }

    function testFuzz_PILBinding_DifferentDomains(
        bytes32 provenanceNullifier,
        bytes32 pilDomain1,
        bytes32 pilDomain2
    ) public pure {
        vm.assume(pilDomain1 != pilDomain2);

        bytes32 binding1 = ProvenancePrimitives.derivePILBinding(
            provenanceNullifier,
            pilDomain1
        );
        bytes32 binding2 = ProvenancePrimitives.derivePILBinding(
            provenanceNullifier,
            pilDomain2
        );

        assertNotEq(
            binding1,
            binding2,
            "Different PIL domains should produce different bindings"
        );
    }

    // =========================================================================
    // MARKER MODULE TESTS
    // =========================================================================

    function testFuzz_MarkerHash_Determinism(
        string memory denom,
        uint256 supply,
        address manager,
        uint8 markerTypeRaw,
        uint8 statusRaw
    ) public pure {
        vm.assume(bytes(denom).length > 0 && bytes(denom).length <= 128);

        ProvenancePrimitives.MarkerType markerType = ProvenancePrimitives
            .MarkerType(markerTypeRaw % 3);
        ProvenancePrimitives.MarkerStatus status = ProvenancePrimitives
            .MarkerStatus(statusRaw % 6);

        ProvenancePrimitives.AccessGrant[]
            memory grants = new ProvenancePrimitives.AccessGrant[](0);

        ProvenancePrimitives.Marker memory marker = ProvenancePrimitives
            .Marker({
                denom: denom,
                supply: supply,
                markerType: markerType,
                status: status,
                manager: manager,
                accessList: grants,
                supplyFixed: false,
                allowGovernanceControl: false,
                markerHash: bytes32(0)
            });

        bytes32 hash1 = ProvenancePrimitives.computeMarkerHash(marker);
        bytes32 hash2 = ProvenancePrimitives.computeMarkerHash(marker);

        assertEq(hash1, hash2, "Marker hash should be deterministic");
    }

    function testFuzz_IsValidMarker(
        string memory denom,
        uint256 supply,
        address manager,
        uint8 statusRaw
    ) public pure {
        vm.assume(bytes(denom).length > 0 && bytes(denom).length <= 128);

        ProvenancePrimitives.MarkerStatus status = ProvenancePrimitives
            .MarkerStatus(statusRaw % 6);
        ProvenancePrimitives.AccessGrant[]
            memory grants = new ProvenancePrimitives.AccessGrant[](0);

        ProvenancePrimitives.Marker memory marker = ProvenancePrimitives
            .Marker({
                denom: denom,
                supply: supply,
                markerType: ProvenancePrimitives.MarkerType.COIN,
                status: status,
                manager: manager,
                accessList: grants,
                supplyFixed: false,
                allowGovernanceControl: false,
                markerHash: bytes32(0)
            });

        bool isValid = ProvenancePrimitives.isValidMarker(marker);

        // Should be valid if status is ACTIVE (index 3)
        if (status == ProvenancePrimitives.MarkerStatus.ACTIVE) {
            assertTrue(isValid, "Active marker should be valid");
        }
    }

    // =========================================================================
    // IBC TESTS
    // =========================================================================

    function testFuzz_IsValidIBCChannel(
        string memory channelId,
        string memory portId,
        string memory counterpartyChannelId,
        string memory counterpartyPortId,
        uint8 stateRaw
    ) public pure {
        vm.assume(bytes(channelId).length > 0 && bytes(channelId).length <= 64);
        vm.assume(bytes(portId).length > 0 && bytes(portId).length <= 64);
        vm.assume(bytes(counterpartyChannelId).length > 0);
        vm.assume(bytes(counterpartyPortId).length > 0);

        ProvenancePrimitives.ChannelState state = ProvenancePrimitives
            .ChannelState(stateRaw % 5);

        ProvenancePrimitives.IBCChannel memory channel = ProvenancePrimitives
            .IBCChannel({
                channelId: channelId,
                portId: portId,
                counterpartyChannelId: counterpartyChannelId,
                counterpartyPortId: counterpartyPortId,
                state: state,
                connectionHops: new bytes(0)
            });

        bool isValid = ProvenancePrimitives.isValidIBCChannel(channel);

        // Should be valid regardless of state if all fields are present
        assertTrue(isValid, "Channel with all fields should be valid");
    }

    function testFuzz_IsValidIBCPacket(
        uint64 sequence,
        string memory sourcePort,
        string memory sourceChannel,
        string memory destPort,
        string memory destChannel,
        bytes memory data,
        uint64 timeoutHeight,
        uint64 timeoutTimestamp
    ) public view {
        vm.assume(sequence > 0);
        vm.assume(bytes(sourcePort).length > 0);
        vm.assume(bytes(sourceChannel).length > 0);
        vm.assume(bytes(destPort).length > 0);
        vm.assume(bytes(destChannel).length > 0);
        vm.assume(data.length > 0);
        vm.assume(
            timeoutTimestamp == 0 || timeoutTimestamp > uint64(block.timestamp)
        );

        ProvenancePrimitives.IBCPacket memory packet = ProvenancePrimitives
            .IBCPacket({
                sequence: sequence,
                sourcePort: sourcePort,
                sourceChannel: sourceChannel,
                destPort: destPort,
                destChannel: destChannel,
                data: data,
                timeoutHeight: timeoutHeight,
                timeoutTimestamp: timeoutTimestamp
            });

        bool isValid = ProvenancePrimitives.isValidIBCPacket(
            packet,
            uint64(block.timestamp)
        );
        assertTrue(isValid, "Packet with valid timeout should be valid");
    }

    function testFuzz_PacketCommitment_Determinism(
        uint64 sequence,
        bytes memory data,
        uint64 timeoutHeight,
        uint64 timeoutTimestamp
    ) public pure {
        vm.assume(data.length > 0);

        ProvenancePrimitives.IBCPacket memory packet = ProvenancePrimitives
            .IBCPacket({
                sequence: sequence,
                sourcePort: "transfer",
                sourceChannel: "channel-0",
                destPort: "transfer",
                destChannel: "channel-1",
                data: data,
                timeoutHeight: timeoutHeight,
                timeoutTimestamp: timeoutTimestamp
            });

        bytes32 commitment1 = ProvenancePrimitives.computePacketCommitment(
            packet
        );
        bytes32 commitment2 = ProvenancePrimitives.computePacketCommitment(
            packet
        );

        assertEq(
            commitment1,
            commitment2,
            "Packet commitment should be deterministic"
        );
    }

    // =========================================================================
    // CONSENSUS TESTS
    // =========================================================================

    function testFuzz_GetTotalVotingPower(
        uint256 power1,
        uint256 power2,
        uint256 power3
    ) public pure {
        vm.assume(power1 < type(uint256).max / 4);
        vm.assume(power2 < type(uint256).max / 4);
        vm.assume(power3 < type(uint256).max / 4);

        ProvenancePrimitives.Validator[]
            memory validators = new ProvenancePrimitives.Validator[](3);
        validators[0] = ProvenancePrimitives.Validator({
            pubkey: new bytes(33),
            votingPower: power1,
            moniker: "val1",
            jailed: false,
            commission: 0
        });
        validators[1] = ProvenancePrimitives.Validator({
            pubkey: new bytes(33),
            votingPower: power2,
            moniker: "val2",
            jailed: false,
            commission: 0
        });
        validators[2] = ProvenancePrimitives.Validator({
            pubkey: new bytes(33),
            votingPower: power3,
            moniker: "val3",
            jailed: false,
            commission: 0
        });

        uint256 total = ProvenancePrimitives.getTotalVotingPower(validators);
        assertEq(
            total,
            power1 + power2 + power3,
            "Total should be sum of powers"
        );
    }

    // =========================================================================
    // SCOPE/METADATA TESTS
    // =========================================================================

    function testFuzz_ScopeHash_Determinism(
        bytes32 scopeId,
        bytes32 specificationId,
        address owner,
        bytes32 valueOwnerAddress
    ) public pure {
        address[] memory owners = new address[](1);
        owners[0] = owner;

        address[] memory dataAccess = new address[](0);

        ProvenancePrimitives.Scope memory scope = ProvenancePrimitives.Scope({
            scopeId: scopeId,
            specificationId: specificationId,
            owners: owners,
            dataAccess: dataAccess,
            valueOwnerAddress: valueOwnerAddress
        });

        bytes32 hash1 = ProvenancePrimitives.computeScopeHash(scope);
        bytes32 hash2 = ProvenancePrimitives.computeScopeHash(scope);

        assertEq(hash1, hash2, "Scope hash should be deterministic");
    }

    function testFuzz_IsValidScope(
        bytes32 scopeId,
        bytes32 specificationId,
        address owner
    ) public pure {
        vm.assume(scopeId != bytes32(0));
        vm.assume(owner != address(0));
        vm.assume(specificationId != bytes32(0));

        address[] memory owners = new address[](1);
        owners[0] = owner;
        address[] memory dataAccess = new address[](0);

        ProvenancePrimitives.Scope memory scope = ProvenancePrimitives.Scope({
            scopeId: scopeId,
            specificationId: specificationId,
            owners: owners,
            dataAccess: dataAccess,
            valueOwnerAddress: bytes32(uint256(uint160(owner)))
        });

        bool isValid = ProvenancePrimitives.isValidScope(scope);
        assertTrue(isValid, "Scope with valid fields should be valid");
    }

    function testFuzz_IsScopeOwner(
        bytes32 scopeId,
        bytes32 specificationId,
        address owner,
        address notOwner
    ) public pure {
        vm.assume(owner != address(0));
        vm.assume(notOwner != address(0));
        vm.assume(owner != notOwner);

        address[] memory owners = new address[](1);
        owners[0] = owner;
        address[] memory dataAccess = new address[](0);

        ProvenancePrimitives.Scope memory scope = ProvenancePrimitives.Scope({
            scopeId: scopeId,
            specificationId: specificationId,
            owners: owners,
            dataAccess: dataAccess,
            valueOwnerAddress: bytes32(uint256(uint160(owner)))
        });

        assertTrue(
            ProvenancePrimitives.isScopeOwner(scope, owner),
            "Owner should be scope owner"
        );
        assertFalse(
            ProvenancePrimitives.isScopeOwner(scope, notOwner),
            "Non-owner should not be scope owner"
        );
    }

    // =========================================================================
    // CROSS-DOMAIN PROOF TESTS
    // =========================================================================

    function testFuzz_CrossDomainProof_Structure(
        bytes32 proofHash,
        uint256 sourceChain,
        uint256 destChain,
        bytes32 commitment,
        bytes32 nullifier
    ) public pure {
        vm.assume(sourceChain != destChain);

        bytes memory scopeData = new bytes(32);
        bytes memory proofData = new bytes(32);

        ProvenancePrimitives.CrossDomainProof
            memory proof = ProvenancePrimitives.CrossDomainProof({
                proofHash: proofHash,
                sourceChain: sourceChain,
                destChain: destChain,
                commitment: commitment,
                nullifier: nullifier,
                scopeData: scopeData,
                proof: proofData
            });

        // Verify struct fields are set correctly
        assertEq(proof.proofHash, proofHash, "Proof hash should match");
        assertEq(proof.sourceChain, sourceChain, "Source chain should match");
        assertEq(proof.destChain, destChain, "Dest chain should match");
        assertEq(proof.commitment, commitment, "Commitment should match");
        assertEq(proof.nullifier, nullifier, "Nullifier should match");
    }

    // =========================================================================
    // INTEGRATION TESTS
    // =========================================================================

    function testFuzz_FullNullifierFlow(
        bytes32 txHash,
        int64 blockHeight,
        bytes32 scopeId,
        string memory denom,
        uint256 targetDomain,
        bytes32 pilDomain
    ) public pure {
        vm.assume(blockHeight > 0);

        // 1. Derive Provenance nullifier
        bytes32 provNf = ProvenancePrimitives.deriveProvenanceNullifier(
            txHash,
            blockHeight,
            scopeId,
            denom
        );

        // 2. Derive cross-domain nullifier
        bytes32 crossNf = ProvenancePrimitives.deriveCrossDomainNullifier(
            provNf,
            targetDomain
        );

        // 3. Derive PIL binding
        bytes32 pilBinding = ProvenancePrimitives.derivePILBinding(
            provNf,
            pilDomain
        );

        // All should be non-zero
        assertTrue(
            provNf != bytes32(0),
            "Provenance nullifier should be non-zero"
        );
        assertTrue(
            crossNf != bytes32(0),
            "Cross-domain nullifier should be non-zero"
        );
        assertTrue(pilBinding != bytes32(0), "PIL binding should be non-zero");

        // All should be unique
        assertNotEq(
            provNf,
            crossNf,
            "Provenance and cross-domain nullifiers should differ"
        );
        assertNotEq(
            provNf,
            pilBinding,
            "Provenance nullifier and PIL binding should differ"
        );
        assertNotEq(
            crossNf,
            pilBinding,
            "Cross-domain nullifier and PIL binding should differ"
        );
    }

    function testFuzz_IBCTransferFlow(
        string memory denom,
        uint256 amount,
        address sender,
        string memory receiver,
        string memory sourceChannel,
        uint64 timeoutTimestamp
    ) public pure {
        vm.assume(bytes(denom).length > 0);
        vm.assume(bytes(receiver).length > 0);
        vm.assume(bytes(sourceChannel).length > 0);
        vm.assume(amount > 0);
        vm.assume(timeoutTimestamp > 0);

        // Create transfer
        ProvenancePrimitives.IBCTransfer memory transfer = ProvenancePrimitives
            .IBCTransfer({
                denom: denom,
                amount: amount,
                sender: sender,
                receiver: receiver,
                sourceChannel: sourceChannel,
                timeoutTimestamp: timeoutTimestamp,
                transferHash: bytes32(0)
            });

        // Verify struct
        assertEq(transfer.denom, denom, "Denom should match");
        assertEq(transfer.amount, amount, "Amount should match");
        assertEq(transfer.sender, sender, "Sender should match");
    }

    function testFuzz_ValidatorSetRotation(
        uint256[5] memory powers
    ) public pure {
        // Bound powers to reasonable values
        for (uint i = 0; i < 5; i++) {
            powers[i] = bound(powers[i], 1, 1e18);
        }

        ProvenancePrimitives.Validator[]
            memory validators = new ProvenancePrimitives.Validator[](5);
        uint256 expectedTotal = 0;

        for (uint i = 0; i < 5; i++) {
            validators[i] = ProvenancePrimitives.Validator({
                pubkey: abi.encodePacked(bytes32(uint256(i + 1)), bytes1(0x02)),
                votingPower: powers[i],
                moniker: "validator",
                jailed: false,
                commission: 100 // 1%
            });
            expectedTotal += powers[i];
        }

        uint256 total = ProvenancePrimitives.getTotalVotingPower(validators);
        assertEq(total, expectedTotal, "Total power should match sum");
    }
}
