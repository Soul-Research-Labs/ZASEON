// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ProvenancePrimitives
 * @notice Core cryptographic primitives and data structures for Provenance Blockchain integration
 * @dev Provenance is a Cosmos SDK-based blockchain for financial services and asset tokenization
 * @author PIL Protocol Team
 * @custom:security-contact security@pil.network
 *
 * Provenance Blockchain Architecture:
 * - Cosmos SDK: Modular blockchain framework
 * - Tendermint BFT: Byzantine fault tolerant consensus (2/3+1 quorum)
 * - secp256k1: ECDSA signatures (Cosmos standard)
 * - IBC: Inter-Blockchain Communication for cross-chain transfers
 * - Marker Module: Asset tokenization and management
 * - Name Module: Hierarchical name service
 * - Attribute Module: On-chain metadata storage
 * - Metadata Module: Scope/record management for asset provenance
 * - Hash (nhash): Native staking/gas token
 */
library ProvenancePrimitives {
    // =========================================================================
    // CONSTANTS - SECP256K1 CURVE
    // =========================================================================

    /// @notice secp256k1 curve order (same as Ethereum)
    /// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    uint256 public constant SECP256K1_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice secp256k1 field prime
    /// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    uint256 public constant SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // =========================================================================
    // CONSTANTS - PROVENANCE BLOCKCHAIN
    // =========================================================================

    /// @notice Chain IDs
    string public constant MAINNET_CHAIN_ID = "pio-mainnet-1";
    string public constant TESTNET_CHAIN_ID = "pio-testnet-1";
    uint256 public constant MAINNET_NUMERIC_ID = 1;
    uint256 public constant TESTNET_NUMERIC_ID = 2;

    /// @notice Consensus parameters
    uint256 public constant BLOCK_TIME_SECONDS = 6; // ~6 second blocks
    uint256 public constant FINALITY_THRESHOLD_BPS = 6667; // 2/3+1 = 66.67%
    uint256 public constant MAX_VALIDATORS = 100;
    uint256 public constant UNBONDING_PERIOD = 21 days;

    /// @notice Native token
    string public constant NATIVE_DENOM = "nhash";
    uint256 public constant HASH_DECIMALS = 9; // 1 HASH = 10^9 nhash

    /// @notice Module prefixes for address derivation
    bytes public constant MARKER_MODULE_PREFIX = "marker";
    bytes public constant NAME_MODULE_PREFIX = "name";
    bytes public constant ATTRIBUTE_MODULE_PREFIX = "attribute";
    bytes public constant METADATA_MODULE_PREFIX = "metadata";

    // =========================================================================
    // STRUCTS - TENDERMINT CONSENSUS
    // =========================================================================

    /// @notice Tendermint validator
    struct Validator {
        bytes pubkey; // 33-byte compressed secp256k1
        uint256 votingPower;
        string moniker;
        bool jailed;
        uint256 commission; // Basis points
    }

    /// @notice Tendermint block header
    struct BlockHeader {
        int64 height;
        uint64 timestamp;
        bytes32 lastBlockId;
        bytes32 dataHash;
        bytes32 validatorsHash;
        bytes32 nextValidatorsHash;
        bytes32 consensusHash;
        bytes32 appHash;
        bytes32 lastResultsHash;
        bytes32 evidenceHash;
        bytes proposerAddress;
    }

    /// @notice Block commit with validator signatures
    struct Commit {
        int64 height;
        int32 round;
        bytes32 blockId;
        CommitSig[] signatures;
    }

    /// @notice Individual validator signature in commit
    struct CommitSig {
        uint8 blockIdFlag; // 0=absent, 1=commit, 2=nil
        bytes validatorAddress;
        uint64 timestamp;
        bytes signature;
    }

    // =========================================================================
    // STRUCTS - MARKER MODULE (Asset Tokenization)
    // =========================================================================

    /// @notice Marker types
    enum MarkerType {
        UNSPECIFIED,
        COIN, // Fungible token
        RESTRICTED // Restricted transfer (requires governance)
    }

    /// @notice Marker status
    enum MarkerStatus {
        UNSPECIFIED,
        PROPOSED,
        FINALIZED,
        ACTIVE,
        CANCELLED,
        DESTROYED
    }

    /// @notice Access type for marker permissions
    enum AccessType {
        UNSPECIFIED,
        MINT,
        BURN,
        DEPOSIT,
        WITHDRAW,
        DELETE,
        ADMIN,
        TRANSFER
    }

    /// @notice Marker (tokenized asset)
    struct Marker {
        string denom;
        uint256 supply;
        MarkerType markerType;
        MarkerStatus status;
        address manager;
        AccessGrant[] accessList;
        bool supplyFixed;
        bool allowGovernanceControl;
        bytes32 markerHash;
    }

    /// @notice Access grant for marker permissions
    struct AccessGrant {
        address grantee;
        AccessType[] permissions;
    }

    // =========================================================================
    // STRUCTS - NAME MODULE
    // =========================================================================

    /// @notice Name record in hierarchical name service
    struct NameRecord {
        string name;
        address owner;
        bool restricted;
        bytes32 nameHash;
    }

    // =========================================================================
    // STRUCTS - ATTRIBUTE MODULE
    // =========================================================================

    /// @notice Attribute type
    enum AttributeType {
        UNSPECIFIED,
        UUID,
        JSON,
        STRING,
        URI,
        INT,
        FLOAT,
        PROTO,
        BYTES
    }

    /// @notice On-chain attribute
    struct Attribute {
        string name;
        bytes value;
        AttributeType attributeType;
        address account;
        uint64 expirationDate;
        bytes32 attributeHash;
    }

    // =========================================================================
    // STRUCTS - METADATA MODULE (Scope/Record)
    // =========================================================================

    /// @notice Scope for grouping records
    struct Scope {
        bytes32 scopeId;
        bytes32 specificationId;
        address[] owners;
        address[] dataAccess;
        bytes32 valueOwnerAddress;
    }

    /// @notice Record within a scope
    struct Record {
        bytes32 sessionId;
        bytes32 specificationId;
        string name;
        RecordInput[] inputs;
        RecordOutput[] outputs;
        bytes32 recordHash;
    }

    /// @notice Record input
    struct RecordInput {
        bytes32 hash;
        string typeName;
        RecordInputStatus status;
    }

    /// @notice Record input status
    enum RecordInputStatus {
        UNSPECIFIED,
        PROPOSED,
        RECORD
    }

    /// @notice Record output
    struct RecordOutput {
        bytes32 hash;
        RecordOutputStatus status;
    }

    /// @notice Record output status
    enum RecordOutputStatus {
        UNSPECIFIED,
        PASS,
        SKIP,
        FAIL
    }

    // =========================================================================
    // STRUCTS - IBC
    // =========================================================================

    /// @notice IBC channel state
    enum ChannelState {
        UNINITIALIZED,
        INIT,
        TRYOPEN,
        OPEN,
        CLOSED
    }

    /// @notice IBC channel
    struct IBCChannel {
        string channelId;
        string portId;
        string counterpartyChannelId;
        string counterpartyPortId;
        ChannelState state;
        bytes connectionHops;
    }

    /// @notice IBC packet
    struct IBCPacket {
        uint64 sequence;
        string sourcePort;
        string sourceChannel;
        string destPort;
        string destChannel;
        bytes data;
        uint64 timeoutHeight;
        uint64 timeoutTimestamp;
    }

    /// @notice IBC transfer
    struct IBCTransfer {
        string denom;
        uint256 amount;
        address sender;
        string receiver; // Bech32 address
        string sourceChannel;
        uint64 timeoutTimestamp;
        bytes32 transferHash;
    }

    // =========================================================================
    // STRUCTS - CROSS-DOMAIN
    // =========================================================================

    /// @notice Provenance nullifier for cross-domain tracking
    struct ProvenanceNullifier {
        bytes32 nullifierHash;
        bytes32 txHash;
        int64 blockHeight;
        bytes32 scopeId;
        string denom;
    }

    /// @notice Cross-domain proof transfer
    struct CrossDomainProof {
        bytes32 proofHash;
        uint256 sourceChain;
        uint256 destChain;
        bytes32 commitment;
        bytes32 nullifier;
        bytes scopeData;
        bytes proof;
    }

    // =========================================================================
    // FUNCTIONS - HASH FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute SHA256 hash (Tendermint standard)
     * @param data Input data
     * @return Hash result
     */
    function sha256Hash(bytes memory data) internal pure returns (bytes32) {
        return sha256(data);
    }

    /**
     * @notice Compute Tendermint address from pubkey (first 20 bytes of SHA256)
     * @param pubkey 33-byte compressed secp256k1 public key
     * @return 20-byte Tendermint address
     */
    function pubkeyToAddress(
        bytes memory pubkey
    ) internal pure returns (bytes20) {
        require(pubkey.length == 33, "Invalid pubkey length");
        bytes32 hash = sha256(pubkey);
        return bytes20(hash);
    }

    /**
     * @notice Compute block header hash
     * @param header Block header
     * @return Header hash
     */
    function computeBlockHeaderHash(
        BlockHeader memory header
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    header.height,
                    header.timestamp,
                    header.lastBlockId,
                    header.dataHash,
                    header.validatorsHash,
                    header.nextValidatorsHash,
                    header.consensusHash,
                    header.appHash,
                    header.lastResultsHash,
                    header.evidenceHash
                )
            );
    }

    /**
     * @notice Compute marker hash
     * @param marker Marker data
     * @return Marker hash
     */
    function computeMarkerHash(
        Marker memory marker
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    marker.denom,
                    marker.supply,
                    uint8(marker.markerType),
                    uint8(marker.status),
                    marker.manager,
                    marker.supplyFixed
                )
            );
    }

    /**
     * @notice Compute scope hash
     * @param scope Scope data
     * @return Scope hash
     */
    function computeScopeHash(
        Scope memory scope
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    scope.scopeId,
                    scope.specificationId,
                    scope.valueOwnerAddress
                )
            );
    }

    // =========================================================================
    // FUNCTIONS - NULLIFIER DERIVATION
    // =========================================================================

    /**
     * @notice Derive Provenance nullifier from transaction
     * @param txHash Transaction hash
     * @param blockHeight Block height
     * @param scopeId Scope ID (for metadata)
     * @param denom Token denomination
     * @return Nullifier hash
     */
    function deriveProvenanceNullifier(
        bytes32 txHash,
        int64 blockHeight,
        bytes32 scopeId,
        string memory denom
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    txHash,
                    blockHeight,
                    scopeId,
                    denom,
                    "PROVENANCE_NULLIFIER"
                )
            );
    }

    /**
     * @notice Derive cross-domain nullifier for PIL binding
     * @param provenanceNullifier Original Provenance nullifier
     * @param targetDomain Target domain identifier
     * @return Cross-domain nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 provenanceNullifier,
        uint256 targetDomain
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(provenanceNullifier, targetDomain, "PROV2PIL")
            );
    }

    /**
     * @notice Derive PIL binding from Provenance nullifier
     * @param provenanceNullifier Provenance nullifier
     * @param pilDomain PIL domain ID
     * @return PIL binding hash
     */
    function derivePILBinding(
        bytes32 provenanceNullifier,
        bytes32 pilDomain
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(provenanceNullifier, pilDomain, "PIL_BINDING")
            );
    }

    // =========================================================================
    // FUNCTIONS - SIGNATURE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify secp256k1 signature (Cosmos standard)
     * @param messageHash Hash of the message
     * @param signature 65-byte signature (r, s, v)
     * @param signer Expected signer address
     * @return True if signature is valid
     */
    function verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address signer
    ) internal pure returns (bool) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        address recovered = ecrecover(messageHash, v, r, s);
        return recovered == signer && recovered != address(0);
    }

    /**
     * @notice Compute Cosmos signature hash (with amino prefix)
     * @param chainId Chain ID string
     * @param accountNumber Account number
     * @param sequence Transaction sequence
     * @param msgData Message data
     * @return Signature hash
     */
    function computeCosmosSignHash(
        string memory chainId,
        uint64 accountNumber,
        uint64 sequence,
        bytes memory msgData
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    '{"account_number":"',
                    uint2str(accountNumber),
                    '","chain_id":"',
                    chainId,
                    '","sequence":"',
                    uint2str(sequence),
                    '","msgs":[',
                    msgData,
                    "]}"
                )
            );
    }

    // =========================================================================
    // FUNCTIONS - CONSENSUS VALIDATION
    // =========================================================================

    /**
     * @notice Calculate total voting power from validators
     * @param validators Array of validators
     * @return Total voting power
     */
    function getTotalVotingPower(
        Validator[] memory validators
    ) internal pure returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            if (!validators[i].jailed) {
                total += validators[i].votingPower;
            }
        }
        return total;
    }

    /**
     * @notice Check if commit has quorum (2/3+1 voting power)
     * @param commit Block commit
     * @param validators Validator set
     * @return True if quorum reached
     */
    function hasQuorum(
        Commit memory commit,
        Validator[] memory validators
    ) internal pure returns (bool) {
        uint256 totalPower = getTotalVotingPower(validators);
        uint256 signedPower = 0;

        for (uint256 i = 0; i < commit.signatures.length; i++) {
            if (commit.signatures[i].blockIdFlag == 1) {
                // BLOCK_ID_FLAG_COMMIT
                // Find validator and add their power
                for (uint256 j = 0; j < validators.length; j++) {
                    bytes20 valAddr = pubkeyToAddress(validators[j].pubkey);
                    if (
                        keccak256(abi.encodePacked(valAddr)) ==
                        keccak256(commit.signatures[i].validatorAddress)
                    ) {
                        if (!validators[j].jailed) {
                            signedPower += validators[j].votingPower;
                        }
                        break;
                    }
                }
            }
        }

        // 2/3+1 threshold
        return signedPower * 10000 > totalPower * FINALITY_THRESHOLD_BPS;
    }

    // =========================================================================
    // FUNCTIONS - MARKER VALIDATION
    // =========================================================================

    /**
     * @notice Validate marker structure
     * @param marker Marker to validate
     * @return True if marker is valid
     */
    function isValidMarker(Marker memory marker) internal pure returns (bool) {
        // Denom must not be empty
        if (bytes(marker.denom).length == 0) return false;

        // Manager must be set for non-proposed markers
        if (
            marker.status != MarkerStatus.PROPOSED &&
            marker.manager == address(0)
        ) {
            return false;
        }

        // Supply must be positive for active markers
        if (marker.status == MarkerStatus.ACTIVE && marker.supply == 0) {
            return false;
        }

        return true;
    }

    /**
     * @notice Check if account has specific access on marker
     * @param marker Marker
     * @param account Account to check
     * @param accessType Required access type
     * @return True if account has access
     */
    function hasMarkerAccess(
        Marker memory marker,
        address account,
        AccessType accessType
    ) internal pure returns (bool) {
        for (uint256 i = 0; i < marker.accessList.length; i++) {
            if (marker.accessList[i].grantee == account) {
                AccessType[] memory perms = marker.accessList[i].permissions;
                for (uint256 j = 0; j < perms.length; j++) {
                    if (
                        perms[j] == accessType || perms[j] == AccessType.ADMIN
                    ) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // =========================================================================
    // FUNCTIONS - IBC VALIDATION
    // =========================================================================

    /**
     * @notice Validate IBC channel
     * @param channel Channel to validate
     * @return True if channel is valid
     */
    function isValidIBCChannel(
        IBCChannel memory channel
    ) internal pure returns (bool) {
        if (bytes(channel.channelId).length == 0) return false;
        if (bytes(channel.portId).length == 0) return false;
        if (channel.state == ChannelState.UNINITIALIZED) return false;
        return true;
    }

    /**
     * @notice Validate IBC packet
     * @param packet Packet to validate
     * @param currentTime Current timestamp
     * @return True if packet is valid
     */
    function isValidIBCPacket(
        IBCPacket memory packet,
        uint64 currentTime
    ) internal pure returns (bool) {
        if (packet.sequence == 0) return false;
        if (bytes(packet.sourceChannel).length == 0) return false;
        if (bytes(packet.destChannel).length == 0) return false;
        if (
            packet.timeoutTimestamp != 0 &&
            packet.timeoutTimestamp < currentTime
        ) {
            return false;
        }
        return true;
    }

    /**
     * @notice Compute IBC packet commitment
     * @param packet IBC packet
     * @return Packet commitment hash
     */
    function computePacketCommitment(
        IBCPacket memory packet
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    packet.timeoutTimestamp,
                    packet.timeoutHeight,
                    sha256(packet.data)
                )
            );
    }

    // =========================================================================
    // FUNCTIONS - SCOPE VALIDATION
    // =========================================================================

    /**
     * @notice Validate scope structure
     * @param scope Scope to validate
     * @return True if scope is valid
     */
    function isValidScope(Scope memory scope) internal pure returns (bool) {
        if (scope.scopeId == bytes32(0)) return false;
        if (scope.specificationId == bytes32(0)) return false;
        if (scope.owners.length == 0) return false;
        return true;
    }

    /**
     * @notice Check if address is scope owner
     * @param scope Scope
     * @param account Account to check
     * @return True if account is owner
     */
    function isScopeOwner(
        Scope memory scope,
        address account
    ) internal pure returns (bool) {
        for (uint256 i = 0; i < scope.owners.length; i++) {
            if (scope.owners[i] == account) {
                return true;
            }
        }
        return false;
    }

    // =========================================================================
    // FUNCTIONS - ENCODING
    // =========================================================================

    /**
     * @notice Encode cross-domain proof
     * @param proof Cross-domain proof
     * @return Encoded proof bytes
     */
    function encodeCrossDomainProof(
        CrossDomainProof memory proof
    ) internal pure returns (bytes memory) {
        return
            abi.encode(
                proof.proofHash,
                proof.sourceChain,
                proof.destChain,
                proof.commitment,
                proof.nullifier,
                proof.scopeData,
                proof.proof
            );
    }

    /**
     * @notice Decode cross-domain proof
     * @param encoded Encoded proof bytes
     * @return Decoded proof
     */
    function decodeCrossDomainProof(
        bytes memory encoded
    ) internal pure returns (CrossDomainProof memory) {
        (
            bytes32 proofHash,
            uint256 sourceChain,
            uint256 destChain,
            bytes32 commitment,
            bytes32 nullifier,
            bytes memory scopeData,
            bytes memory proof
        ) = abi.decode(
                encoded,
                (bytes32, uint256, uint256, bytes32, bytes32, bytes, bytes)
            );

        return
            CrossDomainProof({
                proofHash: proofHash,
                sourceChain: sourceChain,
                destChain: destChain,
                commitment: commitment,
                nullifier: nullifier,
                scopeData: scopeData,
                proof: proof
            });
    }

    // =========================================================================
    // FUNCTIONS - UTILITY
    // =========================================================================

    /**
     * @notice Convert uint to string
     * @param value Number to convert
     * @return String representation
     */
    function uint2str(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @notice Get network ID based on chain
     * @param isMainnet True for mainnet
     * @return Numeric network ID
     */
    function getNetworkId(bool isMainnet) internal pure returns (uint256) {
        return isMainnet ? MAINNET_NUMERIC_ID : TESTNET_NUMERIC_ID;
    }
}
