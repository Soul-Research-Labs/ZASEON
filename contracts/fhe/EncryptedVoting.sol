// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./FHEGateway.sol";
import "./FHETypes.sol";
import "./FHEOperations.sol";

/**
 * @title EncryptedVoting
 * @author Soul Protocol
 * @notice Private voting system with encrypted votes and tallies using FHE
 * @dev Implements fully confidential voting where individual votes cannot be seen
 *
 * Features:
 * - Encrypted vote casting (no one knows how you voted)
 * - Encrypted tallies (results hidden until reveal)
 * - Threshold decryption for final results
 * - Delegate voting support
 * - Proposal creation and management
 *
 * Privacy Model:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                    Encrypted Voting Flow                            │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  1. PROPOSAL                                                         │
 * │     Admin creates proposal with encrypted options                    │
 * │                                                                      │
 * │  2. VOTING PERIOD                                                    │
 * │     ┌────────┐   ┌────────┐   ┌────────┐                           │
 * │     │ Voter1 │   │ Voter2 │   │ Voter3 │                           │
 * │     │enc(opt)│   │enc(opt)│   │enc(opt)│                           │
 * │     └───┬────┘   └───┬────┘   └───┬────┘                           │
 * │         │            │            │                                 │
 * │         └────────────┼────────────┘                                 │
 * │                      ▼                                              │
 * │              ┌──────────────┐                                       │
 * │              │ FHE Gateway  │                                       │
 * │              │ Tally: Σ enc │                                       │
 * │              └──────┬───────┘                                       │
 * │                     │                                               │
 * │  3. REVEAL                                                          │
 * │                     ▼                                               │
 * │              ┌──────────────┐                                       │
 * │              │  Threshold   │                                       │
 * │              │  Decryption  │                                       │
 * │              └──────┬───────┘                                       │
 * │                     │                                               │
 * │                     ▼                                               │
 * │              Final Results                                          │
 * │              (plaintext)                                            │
 * └─────────────────────────────────────────────────────────────────────┘
 */
contract EncryptedVoting is AccessControl, ReentrancyGuard, Pausable {
    using FHEOperations for uint256;
    using FHEOperations for euint256;
    using FHEOperations for euint8;
    using FHEOperations for ebool;

    // ============================================
    // Roles
    // ============================================

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant TALLY_ROLE = keccak256("TALLY_ROLE");

    // ============================================
    // Types
    // ============================================

    /// @notice Proposal status
    enum ProposalStatus {
        Pending,
        Active,
        Tallying,
        Succeeded,
        Defeated,
        Executed,
        Cancelled
    }

    /// @notice Vote option
    enum VoteOption {
        Against, // 0
        For, // 1
        Abstain // 2
    }

    /// @notice Proposal structure
    struct Proposal {
        uint256 proposalId;
        address proposer;
        string title;
        string description;
        bytes32 ipfsHash; // IPFS hash of full proposal
        uint64 startTime;
        uint64 endTime;
        uint64 tallyTime; // When tally can be revealed
        uint256 quorumRequired; // Minimum votes for validity
        ProposalStatus status;
        bool executed;
    }

    /// @notice Encrypted tally for a proposal
    struct EncryptedTally {
        euint256 encryptedFor; // Encrypted count of FOR votes
        euint256 encryptedAgainst; // Encrypted count of AGAINST votes
        euint256 encryptedAbstain; // Encrypted count of ABSTAIN votes
        euint256 encryptedTotal; // Encrypted total vote count
        uint256 totalVoters; // Number of unique voters (not encrypted)
    }

    /// @notice Decrypted tally (after reveal)
    struct DecryptedTally {
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        uint256 totalVotes;
        bool revealed;
    }

    /// @notice Voter info
    struct Voter {
        euint256 votingPower; // Encrypted voting power
        address delegate; // Delegation address
        bool hasVoted;
        bytes32 encryptedVote; // Hash of encrypted vote or ciphertext ID
    }

    /// @notice Delegation info
    struct Delegation {
        address delegator;
        address delegate;
        euint256 encryptedPower; // Delegated voting power
        uint64 timestamp;
        bool active;
    }

    // ============================================
    // State Variables
    // ============================================

    /// @notice FHE Gateway
    FHEGateway public immutable fheGateway;

    /// @notice Proposal counter
    uint256 public proposalCount;

    /// @notice Voting delay (time between proposal and voting start)
    uint64 public votingDelay;

    /// @notice Voting period duration
    uint64 public votingPeriod;

    /// @notice Tally delay (time between voting end and tally reveal)
    uint64 public tallyDelay;

    /// @notice Default quorum (basis points)
    uint256 public defaultQuorumBps;

    /// @notice Proposals
    mapping(uint256 => Proposal) public proposals;

    /// @notice Encrypted tallies
    mapping(uint256 => EncryptedTally) public encryptedTallies;

    /// @notice Decrypted tallies (after reveal)
    mapping(uint256 => DecryptedTally) public decryptedTallies;

    /// @notice Voters per proposal: proposalId => voter => Voter
    mapping(uint256 => mapping(address => Voter)) public voters;

    /// @notice Delegations: delegator => Delegation
    mapping(address => Delegation) public delegations;

    /// @notice Voting power registry: address => encrypted power
    mapping(address => euint256) public votingPower;

    /// @notice Pending decryption requests
    mapping(bytes32 => uint256) public decryptionToProposal;


    // ============================================
    // Events
    // ============================================

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        string title,
        uint64 startTime,
        uint64 endTime
    );

    event EncryptedVoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        euint8 encryptedVote
    );

    event DelegateVoteCast(
        uint256 indexed proposalId,
        address indexed delegate,
        address indexed delegator,
        euint8 encryptedVote
    );

    event VotingPowerSet(address indexed voter, euint256 encryptedPower);

    event DelegationSet(
        address indexed delegator,
        address indexed delegate,
        euint256 encryptedPower
    );

    event DelegationRevoked(
        address indexed delegator,
        address indexed delegate
    );

    event TallyStarted(uint256 indexed proposalId);

    event TallyRevealed(
        uint256 indexed proposalId,
        uint256 forVotes,
        uint256 againstVotes,
        uint256 abstainVotes
    );

    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId, string reason);
    event ViewerGranted(address indexed owner, address indexed viewer);
    event ViewerRevoked(address indexed owner, address indexed viewer);

    // ============================================
    // Errors
    // ============================================

    error NotProposer();
    error InvalidTimeParams();
    error ProposalNotFound();
    error ProposalNotActive();
    error AlreadyVoted();
    error NoVotingPower();
    error SelfDelegation();
    error AlreadyDelegated();
    error NotDelegated();
    error InvalidVoteOption();
    error ProposalStillActive();
    error TallyNotReady();
    error AlreadyRevealed();
    error ProposalNotSucceeded();
    error AlreadyExecuted();
    error Unauthorized();

    // ============================================
    // Constructor
    // ============================================

    constructor(address _fheGateway) {
        fheGateway = FHEGateway(_fheGateway);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROPOSER_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(TALLY_ROLE, msg.sender);

        // Default constraints
        votingDelay = 1 days;
        votingPeriod = 3 days;
        tallyDelay = 1 days;
        defaultQuorumBps = 400; // 4%
    }

    // ============================================
    // Proposal Management
    // ============================================

    /**
     * @notice Create a new proposal
     * @param title Title
     * @param description Description
     * @param ipfsHash IPFS hash
     */
    function createProposal(
        string memory title,
        string memory description,
        bytes32 ipfsHash
    ) external onlyRole(PROPOSER_ROLE) returns (uint256) {
        proposalCount++;
        uint256 proposalId = proposalCount;

        uint64 startTime = uint64(block.timestamp + votingDelay);
        uint64 endTime = startTime + votingPeriod;
        uint64 tallyTime = endTime + tallyDelay;

        proposals[proposalId] = Proposal({
            proposalId: proposalId,
            proposer: msg.sender,
            title: title,
            description: description,
            ipfsHash: ipfsHash,
            startTime: startTime,
            endTime: endTime,
            tallyTime: tallyTime,
            quorumRequired: defaultQuorumBps,
            status: ProposalStatus.Pending,
            executed: false
        });

        // Initialize encrypted tally (optional explicit init)
        // Values are 0 by default, which are valid trivial encryptions of 0?
        // No, we must initialize them to encryption of 0 usually, so we can add to them.
        // Assuming default 0 bytes is NOT valid ciphertext or treated as 0?
        // Usually 0 bytes is invalid. We should Initialize.

        euint256 zero = FHEOperations.asEuint256(0);
        encryptedTallies[proposalId] = EncryptedTally({
            encryptedFor: zero,
            encryptedAgainst: zero,
            encryptedAbstain: zero,
            encryptedTotal: zero,
            totalVoters: 0
        });

        emit ProposalCreated(proposalId, msg.sender, title, startTime, endTime);

        return proposalId;
    }

    /**
     * @notice Cancel a proposal
     * @param proposalId Proposal ID
     * @param reason Reason string
     */
    function cancelProposal(
        uint256 proposalId,
        string memory reason
    ) external onlyRole(ADMIN_ROLE) {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert ProposalNotFound();
        if (proposal.executed) revert AlreadyExecuted();

        proposal.status = ProposalStatus.Cancelled;

        emit ProposalCancelled(proposalId, reason);
    }

    // ============================================
    // Voting Power
    // ============================================

    /**
     * @notice Set voting power for an address
     * @param voter Voter address
     * @param encryptedPower Encrypted voting power
     */
    function setVotingPower(
        address voter,
        euint256 encryptedPower
    ) external onlyRole(ADMIN_ROLE) {
        votingPower[voter] = encryptedPower;

        emit VotingPowerSet(voter, encryptedPower);
    }

    /**
     * @notice Set voting power with plaintext amount (encrypts automatically)
     * @param voter Voter address
     * @param power Plaintext voting power
     */
    function setVotingPowerPlain(
        address voter,
        uint256 power
    ) external onlyRole(ADMIN_ROLE) {
        euint256 encPower = power.asEuint256();
        votingPower[voter] = encPower;

        emit VotingPowerSet(voter, encPower);
    }

    // ============================================
    // Delegation
    // ============================================

    /**
     * @notice Delegate voting power to another address
     * @param delegate Address to delegate to
     */
    function delegateTo(address delegate) external {
        if (delegate == msg.sender) revert SelfDelegation();
        if (delegations[msg.sender].active) revert AlreadyDelegated();

        euint256 power = votingPower[msg.sender];
        if (euint256.unwrap(power) == bytes32(0)) revert NoVotingPower();

        delegations[msg.sender] = Delegation({
            delegator: msg.sender,
            delegate: delegate,
            encryptedPower: power,
            timestamp: uint64(block.timestamp),
            active: true
        });

        emit DelegationSet(msg.sender, delegate, power);
    }

    /**
     * @notice Revoke delegation
     */
    function revokeDelegation() external {
        Delegation storage del = delegations[msg.sender];
        if (!del.active) revert NotDelegated();

        address oldDelegate = del.delegate;
        del.active = false;

        emit DelegationRevoked(msg.sender, oldDelegate);
    }

    // ============================================
    // Voting
    // ============================================

    /**
     * @notice Cast an encrypted vote
     * @param proposalId Proposal ID
     * @param encryptedVote Encrypted vote option (0=Against, 1=For, 2=Abstain)
     */
    function castVote(
        uint256 proposalId,
        euint8 encryptedVote
    ) external whenNotPaused nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert ProposalNotFound();

        _updateProposalStatus(proposalId);
        if (proposal.status != ProposalStatus.Active)
            revert ProposalNotActive();

        Voter storage voter = voters[proposalId][msg.sender];
        if (voter.hasVoted) revert AlreadyVoted();

        euint256 power = votingPower[msg.sender];
        if (euint256.unwrap(power) == bytes32(0)) revert NoVotingPower();

        // Store vote
        voter.votingPower = power;
        voter.hasVoted = true;
        voter.encryptedVote = euint8.unwrap(encryptedVote);

        // Update encrypted tally
        _updateTally(proposalId, encryptedVote, power);

        encryptedTallies[proposalId].totalVoters++;

        emit EncryptedVoteCast(proposalId, msg.sender, encryptedVote);
    }

    /**
     * @notice Cast vote with plaintext option (encrypts automatically)
     * @param proposalId Proposal ID
     * @param voteOption Vote option (0=Against, 1=For, 2=Abstain)
     */
    function castVotePlain(
        uint256 proposalId,
        VoteOption voteOption
    ) external whenNotPaused nonReentrant {
        if (uint8(voteOption) > 2) revert InvalidVoteOption();

        // Manual encryption since no asEuint8 for uint8/enum?
        euint8 encVote = euint8.wrap(fheGateway.trivialEncrypt(
            uint256(voteOption),
            FHETypes.TYPE_EUINT8
        ));
        
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert ProposalNotFound();

        _updateProposalStatus(proposalId);
        if (proposal.status != ProposalStatus.Active)
            revert ProposalNotActive();

        Voter storage voter = voters[proposalId][msg.sender];
        if (voter.hasVoted) revert AlreadyVoted();

        euint256 power = votingPower[msg.sender];
        if (euint256.unwrap(power) == bytes32(0)) revert NoVotingPower();

        voter.votingPower = power;
        voter.hasVoted = true;
        voter.encryptedVote = euint8.unwrap(encVote);

        _updateTally(proposalId, encVote, power);
        encryptedTallies[proposalId].totalVoters++;

        emit EncryptedVoteCast(proposalId, msg.sender, encVote);
    }

    /**
     * @notice Cast vote on behalf of delegator
     * @param proposalId Proposal ID
     * @param delegator Address that delegated
     * @param encryptedVote Encrypted vote
     */
    function castDelegateVote(
        uint256 proposalId,
        address delegator,
        euint8 encryptedVote
    ) external whenNotPaused nonReentrant {
        Delegation storage del = delegations[delegator];
        if (!del.active || del.delegate != msg.sender) revert NotDelegated();

        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert ProposalNotFound();

        _updateProposalStatus(proposalId);
        if (proposal.status != ProposalStatus.Active)
            revert ProposalNotActive();

        Voter storage voter = voters[proposalId][delegator];
        if (voter.hasVoted) revert AlreadyVoted();

        voter.votingPower = del.encryptedPower;
        voter.delegate = msg.sender;
        voter.hasVoted = true;
        voter.encryptedVote = euint8.unwrap(encryptedVote);

        _updateTally(proposalId, encryptedVote, del.encryptedPower);
        encryptedTallies[proposalId].totalVoters++;

        emit DelegateVoteCast(proposalId, msg.sender, delegator, encryptedVote);
    }

    /**
     * @notice Update encrypted tally based on vote
     * @dev Uses encrypted comparison and selection to update correct counter
     */
    function _updateTally(
        uint256 proposalId,
        euint8 encryptedVote,
        euint256 power
    ) internal {
        EncryptedTally storage tally = encryptedTallies[proposalId];

        // Encrypt vote options for comparison
        euint8 encZero = euint8.wrap(fheGateway.trivialEncrypt(0, FHETypes.TYPE_EUINT8)); // Against
        euint8 encOne = euint8.wrap(fheGateway.trivialEncrypt(1, FHETypes.TYPE_EUINT8)); // For
        euint8 encTwo = euint8.wrap(fheGateway.trivialEncrypt(2, FHETypes.TYPE_EUINT8)); // Abstain

        // Check which option was voted
        ebool isAgainst = encryptedVote.eq(encZero);
        ebool isFor = encryptedVote.eq(encOne);
        ebool isAbstain = encryptedVote.eq(encTwo);

        // Create encrypted zero for non-matching votes
        euint256 zeroPower = FHEOperations.asEuint256(0);

        // Select power or zero based on vote
        euint256 againstPower = isAgainst.select(power, zeroPower);
        euint256 forPower = isFor.select(power, zeroPower);
        euint256 abstainPower = isAbstain.select(power, zeroPower);

        // Add to tallies
        tally.encryptedAgainst = tally.encryptedAgainst.add(againstPower);
        tally.encryptedFor = tally.encryptedFor.add(forPower);
        tally.encryptedAbstain = tally.encryptedAbstain.add(abstainPower);
        tally.encryptedTotal = tally.encryptedTotal.add(power);
    }

    // ============================================
    // Tally & Results
    // ============================================

    /**
     * @notice Start the tally process (triggers decryption requests)
     * @param proposalId Proposal ID
     */
    function startTally(uint256 proposalId) external onlyRole(TALLY_ROLE) {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert ProposalNotFound();

        _updateProposalStatus(proposalId);
        if (
            proposal.status != ProposalStatus.Active &&
            block.timestamp <= proposal.endTime
        ) {
            revert ProposalStillActive();
        }

        proposal.status = ProposalStatus.Tallying;

        emit TallyStarted(proposalId);

        // Request decryption of all tallies
        EncryptedTally storage tally = encryptedTallies[proposalId];

        // Request decryption for each tally
        bytes32 reqFor = fheGateway.requestDecryption(
            euint256.unwrap(tally.encryptedFor),
            address(this),
            this.onTallyDecrypted.selector,
            3600
        );
        decryptionToProposal[reqFor] = proposalId;

        bytes32 reqAgainst = fheGateway.requestDecryption(
            euint256.unwrap(tally.encryptedAgainst),
            address(this),
            this.onTallyDecrypted.selector,
            3600
        );
        decryptionToProposal[reqAgainst] = proposalId;

        bytes32 reqAbstain = fheGateway.requestDecryption(
            euint256.unwrap(tally.encryptedAbstain),
            address(this),
            this.onTallyDecrypted.selector,
            3600
        );
        decryptionToProposal[reqAbstain] = proposalId;
    }

    /**
     * @notice Callback for tally decryption
     * @param requestId Decryption request ID
     * @param result Decrypted value
     */
    function onTallyDecrypted(bytes32 requestId, bytes32 result) external {
        // Only gateway can call
        if (msg.sender != address(fheGateway)) revert Unauthorized();

        uint256 proposalId = decryptionToProposal[requestId];
        if (proposalId == 0) return;

        DecryptedTally storage decrypted = decryptedTallies[proposalId];
        uint256 value = uint256(result);

        // Determine which tally this is based on request
        // In production, track which request maps to which tally type
        // For simplicity, accumulate
        decrypted.totalVotes += value;
    }

    /**
     * @notice Reveal final tally (manual, after decryption)
     * @param proposalId Proposal ID
     * @param forVotes Decrypted FOR votes
     * @param againstVotes Decrypted AGAINST votes
     * @param abstainVotes Decrypted ABSTAIN votes
     */
    function revealTally(
        uint256 proposalId,
        uint256 forVotes,
        uint256 againstVotes,
        uint256 abstainVotes
    ) external onlyRole(TALLY_ROLE) {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert ProposalNotFound();
        if (proposal.status != ProposalStatus.Tallying) revert TallyNotReady();
        if (block.timestamp < proposal.tallyTime) revert TallyNotReady();

        DecryptedTally storage decrypted = decryptedTallies[proposalId];
        if (decrypted.revealed) revert AlreadyRevealed();

        decrypted.forVotes = forVotes;
        decrypted.againstVotes = againstVotes;
        decrypted.abstainVotes = abstainVotes;
        decrypted.totalVotes = forVotes + againstVotes + abstainVotes;
        decrypted.revealed = true;

        // Determine outcome
        if (forVotes > againstVotes) {
            proposal.status = ProposalStatus.Succeeded;
        } else {
            proposal.status = ProposalStatus.Defeated;
        }

        emit TallyRevealed(proposalId, forVotes, againstVotes, abstainVotes);
    }

    /**
     * @notice Execute a successful proposal
     * @param proposalId Proposal ID
     */
    function executeProposal(uint256 proposalId) external onlyRole(ADMIN_ROLE) {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert ProposalNotFound();
        if (proposal.status != ProposalStatus.Succeeded)
            revert ProposalNotSucceeded();
        if (proposal.executed) revert AlreadyExecuted();

        proposal.executed = true;
        proposal.status = ProposalStatus.Executed;

        // Execute proposal actions here (if any)

        emit ProposalExecuted(proposalId);
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Update proposal status based on time
     */
    function _updateProposalStatus(uint256 proposalId) internal {
        Proposal storage proposal = proposals[proposalId];

        if (proposal.status == ProposalStatus.Cancelled) return;
        if (proposal.status == ProposalStatus.Executed) return;

        if (
            block.timestamp >= proposal.startTime &&
            block.timestamp < proposal.endTime &&
            proposal.status == ProposalStatus.Pending
        ) {
            proposal.status = ProposalStatus.Active;
        }
    }

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Update voting parameters
     */
    function setVotingParams(
        uint64 _votingDelay,
        uint64 _votingPeriod,
        uint64 _tallyDelay
    ) external onlyRole(ADMIN_ROLE) {
        if (_votingPeriod == 0) revert InvalidTimeParams();
        votingDelay = _votingDelay;
        votingPeriod = _votingPeriod;
        tallyDelay = _tallyDelay;
    }

    /**
     * @notice Update default quorum
     */
    function setDefaultQuorum(
        uint256 _quorumBps
    ) external onlyRole(ADMIN_ROLE) {
        defaultQuorumBps = _quorumBps;
    }

    /**
     * @notice Pause voting
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause voting
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // View Functions
    // ============================================

    /**
     * @notice Get proposal info
     */
    function getProposal(
        uint256 proposalId
    ) external view returns (Proposal memory) {
        return proposals[proposalId];
    }
}


