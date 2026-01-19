// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title NetworkStressTester
 * @notice Comprehensive stress testing framework for PIL network
 * @dev Designed for testing network resilience under extreme conditions
 *
 * Features:
 * 1. Load generation with configurable intensity
 * 2. Chaos engineering scenarios
 * 3. Performance benchmarking
 * 4. Resource exhaustion testing
 * 5. Concurrent operation simulation
 */
contract NetworkStressTester is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant STRESS_OPERATOR_ROLE =
        keccak256("STRESS_OPERATOR_ROLE");
    bytes32 public constant CHAOS_CONTROLLER_ROLE =
        keccak256("CHAOS_CONTROLLER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              STRUCTURES
    //////////////////////////////////////////////////////////////*/

    enum TestScenario {
        HighVolume, // Maximum throughput testing
        Burst, // Sudden load spikes
        Sustained, // Long-running constant load
        Chaos, // Random failure injection
        Concurrent, // Parallel operation stress
        ResourceExhaustion, // Memory/storage limits
        LatencySpike, // Delayed response simulation
        PartitionTolerance // Network partition simulation
    }

    struct StressTest {
        uint256 testId;
        TestScenario scenario;
        uint256 intensity; // 1-100 scale
        uint256 duration; // Block count
        uint256 startBlock;
        uint256 endBlock;
        uint256 operationsTotal;
        uint256 operationsSuccess;
        uint256 operationsFailed;
        uint256 gasUsed;
        bool completed;
        bool passed;
    }

    struct PerformanceMetrics {
        uint256 avgGasPerOp;
        uint256 maxGasPerOp;
        uint256 minGasPerOp;
        uint256 throughput; // Ops per block
        uint256 successRate; // Percentage * 100
        uint256 latencyBlocks;
    }

    struct ChaosConfig {
        bool enabled;
        uint256 failureRate; // Percentage * 100 (e.g., 500 = 5%)
        uint256 delayBlocks;
        bool randomRevert;
        bool gasExhaustion;
        bool storageCorruption;
    }

    /*//////////////////////////////////////////////////////////////
                             STATE
    //////////////////////////////////////////////////////////////*/

    // Test tracking
    mapping(uint256 => StressTest) public stressTests;
    uint256 public totalTests;
    uint256 public activeTestId;

    // Performance tracking
    mapping(uint256 => PerformanceMetrics) public testMetrics;
    uint256[] private gasHistory;
    uint256 private constant MAX_GAS_HISTORY = 1000;

    // Chaos configuration
    ChaosConfig public chaosConfig;
    uint256 private chaosNonce;

    // Benchmarks
    uint256 public baselineGas;
    uint256 public peakThroughput;
    uint256 public maxSuccessRate;

    // Load generation
    mapping(bytes32 => bytes32) public loadStorage; // For storage stress
    uint256 public loadCounter;

    // Target contracts
    address[] public targetContracts;
    mapping(address => bool) public isTargetContract;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event StressTestStarted(
        uint256 indexed testId,
        TestScenario scenario,
        uint256 intensity
    );
    event StressTestCompleted(
        uint256 indexed testId,
        bool passed,
        PerformanceMetrics metrics
    );
    event ChaosEvent(string description, uint256 timestamp);
    event PerformanceSnapshot(
        uint256 gasUsed,
        uint256 throughput,
        uint256 successRate
    );
    event LoadGenerated(uint256 operations, uint256 gasUsed);
    event BenchmarkUpdated(uint256 baselineGas, uint256 peakThroughput);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(STRESS_OPERATOR_ROLE, msg.sender);
        _grantRole(CHAOS_CONTROLLER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         STRESS TEST MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Start a new stress test
     * @param scenario Type of stress test
     * @param intensity Intensity level 1-100
     * @param durationBlocks Duration in blocks
     */
    function startStressTest(
        TestScenario scenario,
        uint256 intensity,
        uint256 durationBlocks
    ) external onlyRole(STRESS_OPERATOR_ROLE) whenNotPaused returns (uint256) {
        require(intensity >= 1 && intensity <= 100, "Invalid intensity");
        require(durationBlocks > 0, "Invalid duration");
        require(
            activeTestId == 0 || stressTests[activeTestId].completed,
            "Test already running"
        );

        totalTests++;
        uint256 testId = totalTests;

        stressTests[testId] = StressTest({
            testId: testId,
            scenario: scenario,
            intensity: intensity,
            duration: durationBlocks,
            startBlock: block.number,
            endBlock: block.number + durationBlocks,
            operationsTotal: 0,
            operationsSuccess: 0,
            operationsFailed: 0,
            gasUsed: 0,
            completed: false,
            passed: false
        });

        activeTestId = testId;

        emit StressTestStarted(testId, scenario, intensity);
        return testId;
    }

    /**
     * @notice Execute a stress test iteration
     * @param testId Test to execute
     * @param iterations Number of iterations to run
     */
    function executeStressIteration(
        uint256 testId,
        uint256 iterations
    ) external onlyRole(STRESS_OPERATOR_ROLE) nonReentrant {
        StressTest storage test = stressTests[testId];
        require(!test.completed, "Test completed");
        require(block.number <= test.endBlock, "Test duration exceeded");

        uint256 gasStart = gasleft();

        for (uint256 i = 0; i < iterations; i++) {
            test.operationsTotal++;

            bool success = _executeScenarioOperation(
                test.scenario,
                test.intensity
            );

            if (success) {
                test.operationsSuccess++;
            } else {
                test.operationsFailed++;
            }
        }

        uint256 gasUsed = gasStart - gasleft();
        test.gasUsed += gasUsed;

        // Track gas history
        _recordGas(gasUsed / iterations);

        emit LoadGenerated(iterations, gasUsed);
    }

    /**
     * @notice Complete and evaluate a stress test
     * @param testId Test to complete
     */
    function completeStressTest(
        uint256 testId
    ) external onlyRole(STRESS_OPERATOR_ROLE) {
        StressTest storage test = stressTests[testId];
        require(!test.completed, "Already completed");

        test.completed = true;

        // Calculate metrics
        PerformanceMetrics memory metrics = _calculateMetrics(test);
        testMetrics[testId] = metrics;

        // Determine pass/fail
        test.passed = _evaluateTest(test, metrics);

        // Update benchmarks
        if (metrics.throughput > peakThroughput) {
            peakThroughput = metrics.throughput;
        }
        if (metrics.successRate > maxSuccessRate) {
            maxSuccessRate = metrics.successRate;
        }

        if (activeTestId == testId) {
            activeTestId = 0;
        }

        emit StressTestCompleted(testId, test.passed, metrics);
    }

    /*//////////////////////////////////////////////////////////////
                         SCENARIO OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Execute an operation based on scenario type
     */
    function _executeScenarioOperation(
        TestScenario scenario,
        uint256 intensity
    ) internal returns (bool) {
        // Check for chaos interference
        if (chaosConfig.enabled && _shouldInjectFailure()) {
            emit ChaosEvent("Injected failure", block.timestamp);
            return false;
        }

        if (scenario == TestScenario.HighVolume) {
            return _executeHighVolumeOp(intensity);
        } else if (scenario == TestScenario.Burst) {
            return _executeBurstOp(intensity);
        } else if (scenario == TestScenario.Sustained) {
            return _executeSustainedOp(intensity);
        } else if (scenario == TestScenario.Chaos) {
            return _executeChaosOp(intensity);
        } else if (scenario == TestScenario.Concurrent) {
            return _executeConcurrentOp(intensity);
        } else if (scenario == TestScenario.ResourceExhaustion) {
            return _executeResourceOp(intensity);
        } else if (scenario == TestScenario.LatencySpike) {
            return _executeLatencyOp(intensity);
        } else if (scenario == TestScenario.PartitionTolerance) {
            return _executePartitionOp(intensity);
        }

        return false;
    }

    /**
     * @dev High volume operation - maximum throughput
     */
    function _executeHighVolumeOp(uint256 intensity) internal returns (bool) {
        // Generate load proportional to intensity
        uint256 ops = intensity;

        for (uint256 i = 0; i < ops; i++) {
            loadCounter++;
            bytes32 key = keccak256(
                abi.encodePacked(loadCounter, block.timestamp)
            );
            bytes32 value = keccak256(abi.encodePacked(key, msg.sender));
            loadStorage[key] = value;
        }

        return true;
    }

    /**
     * @dev Burst operation - sudden spike simulation
     */
    function _executeBurstOp(uint256 intensity) internal returns (bool) {
        // Simulate burst by doing more work occasionally
        bool isBurst = uint256(
            keccak256(abi.encodePacked(block.timestamp, loadCounter))
        ) %
            10 ==
            0;

        uint256 ops = isBurst ? intensity * 5 : intensity / 2;

        for (uint256 i = 0; i < ops; i++) {
            loadCounter++;
            loadStorage[bytes32(loadCounter)] = bytes32(block.timestamp);
        }

        return true;
    }

    /**
     * @dev Sustained operation - constant load
     */
    function _executeSustainedOp(uint256 intensity) internal returns (bool) {
        // Consistent workload
        for (uint256 i = 0; i < intensity; i++) {
            loadCounter++;

            // Do some computation
            bytes32 hash = keccak256(abi.encodePacked(loadCounter));
            for (uint256 j = 0; j < 5; j++) {
                hash = keccak256(abi.encodePacked(hash));
            }

            loadStorage[bytes32(loadCounter)] = hash;
        }

        return true;
    }

    /**
     * @dev Chaos operation - random behavior
     */
    function _executeChaosOp(uint256 intensity) internal returns (bool) {
        chaosNonce++;
        uint256 randomOp = uint256(
            keccak256(abi.encodePacked(chaosNonce, block.timestamp))
        ) % 5;

        if (randomOp == 0) {
            // Memory stress
            bytes memory data = new bytes(intensity * 100);
            for (uint256 i = 0; i < data.length && i < 1000; i++) {
                data[i] = bytes1(uint8(i % 256));
            }
        } else if (randomOp == 1) {
            // Storage stress
            for (uint256 i = 0; i < intensity; i++) {
                loadStorage[bytes32(loadCounter + i)] = bytes32(uint256(i));
            }
            loadCounter += intensity;
        } else if (randomOp == 2) {
            // Computation stress
            uint256 result = 0;
            for (uint256 i = 0; i < intensity * 10; i++) {
                result = result + i * i;
            }
        } else if (randomOp == 3) {
            // Potential revert (controlled)
            if (chaosConfig.randomRevert && chaosNonce % 10 == 0) {
                return false;
            }
        }
        // randomOp == 4: No-op

        return true;
    }

    /**
     * @dev Concurrent operation simulation
     */
    function _executeConcurrentOp(uint256 intensity) internal returns (bool) {
        // Simulate multiple "users" by using different key spaces
        uint256 users = intensity / 10 + 1;

        for (uint256 user = 0; user < users; user++) {
            bytes32 userKey = keccak256(abi.encodePacked(user, "user"));

            for (uint256 i = 0; i < 10; i++) {
                bytes32 key = keccak256(
                    abi.encodePacked(userKey, loadCounter, i)
                );
                loadStorage[key] = bytes32(block.timestamp);
            }
        }

        loadCounter += users * 10;
        return true;
    }

    /**
     * @dev Resource exhaustion testing
     */
    function _executeResourceOp(uint256 intensity) internal returns (bool) {
        // Storage exhaustion test
        for (uint256 i = 0; i < intensity * 5; i++) {
            loadCounter++;
            bytes32 key = bytes32(loadCounter);

            // Write to storage
            loadStorage[key] = keccak256(
                abi.encodePacked(key, block.timestamp)
            );
        }

        return true;
    }

    /**
     * @dev Latency simulation
     */
    function _executeLatencyOp(uint256 intensity) internal returns (bool) {
        // Simulate latency by doing computation
        bytes32 hash = bytes32(block.timestamp);

        for (uint256 i = 0; i < intensity * 20; i++) {
            hash = keccak256(abi.encodePacked(hash, i));
        }

        loadStorage[bytes32(loadCounter)] = hash;
        loadCounter++;

        return true;
    }

    /**
     * @dev Partition tolerance simulation
     */
    function _executePartitionOp(uint256 intensity) internal returns (bool) {
        // Simulate partition by random success/failure
        chaosNonce++;

        // Higher intensity = more failures (simulating more partitions)
        uint256 failureChance = intensity;
        uint256 random = uint256(keccak256(abi.encodePacked(chaosNonce))) % 100;

        if (random < failureChance) {
            return false; // Simulated partition
        }

        loadCounter++;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          CHAOS ENGINEERING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Enable chaos mode for testing
     */
    function enableChaos(
        uint256 failureRate,
        uint256 delayBlocks,
        bool randomRevert,
        bool gasExhaustion,
        bool storageCorruption
    ) external onlyRole(CHAOS_CONTROLLER_ROLE) {
        require(failureRate <= 5000, "Failure rate too high"); // Max 50%

        chaosConfig = ChaosConfig({
            enabled: true,
            failureRate: failureRate,
            delayBlocks: delayBlocks,
            randomRevert: randomRevert,
            gasExhaustion: gasExhaustion,
            storageCorruption: storageCorruption
        });

        emit ChaosEvent("Chaos mode enabled", block.timestamp);
    }

    /**
     * @notice Disable chaos mode
     */
    function disableChaos() external onlyRole(CHAOS_CONTROLLER_ROLE) {
        chaosConfig.enabled = false;
        emit ChaosEvent("Chaos mode disabled", block.timestamp);
    }

    /**
     * @dev Check if failure should be injected
     */
    function _shouldInjectFailure() internal returns (bool) {
        chaosNonce++;
        uint256 random = uint256(
            keccak256(abi.encodePacked(chaosNonce, block.timestamp, msg.sender))
        ) % 10000;
        return random < chaosConfig.failureRate;
    }

    /*//////////////////////////////////////////////////////////////
                         METRICS & EVALUATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Calculate performance metrics for a test
     */
    function _calculateMetrics(
        StressTest storage test
    ) internal view returns (PerformanceMetrics memory) {
        uint256 avgGas = test.operationsTotal > 0
            ? test.gasUsed / test.operationsTotal
            : 0;
        uint256 throughput = test.duration > 0
            ? test.operationsTotal / test.duration
            : 0;
        uint256 successRate = test.operationsTotal > 0
            ? (test.operationsSuccess * 10000) / test.operationsTotal
            : 0;

        uint256 minGas = type(uint256).max;
        uint256 maxGas = 0;

        for (uint256 i = 0; i < gasHistory.length; i++) {
            if (gasHistory[i] < minGas) minGas = gasHistory[i];
            if (gasHistory[i] > maxGas) maxGas = gasHistory[i];
        }

        if (minGas == type(uint256).max) minGas = 0;

        return
            PerformanceMetrics({
                avgGasPerOp: avgGas,
                maxGasPerOp: maxGas,
                minGasPerOp: minGas,
                throughput: throughput,
                successRate: successRate,
                latencyBlocks: test.endBlock > test.startBlock
                    ? test.endBlock - test.startBlock
                    : 0
            });
    }

    /**
     * @dev Evaluate if a test passed
     */
    function _evaluateTest(
        StressTest storage test,
        PerformanceMetrics memory metrics
    ) internal view returns (bool) {
        // Different criteria based on scenario
        if (test.scenario == TestScenario.HighVolume) {
            // Should achieve at least 90% success rate
            return metrics.successRate >= 9000;
        } else if (test.scenario == TestScenario.Burst) {
            // Should handle bursts with 85% success
            return metrics.successRate >= 8500;
        } else if (test.scenario == TestScenario.Sustained) {
            // High reliability for sustained load
            return metrics.successRate >= 9500;
        } else if (test.scenario == TestScenario.Chaos) {
            // Chaos mode - just needs to survive
            return metrics.successRate >= 5000;
        } else if (test.scenario == TestScenario.Concurrent) {
            return metrics.successRate >= 9000;
        } else if (test.scenario == TestScenario.ResourceExhaustion) {
            // Should not crash
            return metrics.successRate >= 8000;
        } else if (test.scenario == TestScenario.LatencySpike) {
            return metrics.successRate >= 9000;
        } else if (test.scenario == TestScenario.PartitionTolerance) {
            // Partition tolerance allows more failures
            return metrics.successRate >= 3000;
        }

        return metrics.successRate >= 8000;
    }

    /**
     * @dev Record gas usage
     */
    function _recordGas(uint256 gasUsed) internal {
        if (gasHistory.length >= MAX_GAS_HISTORY) {
            // Remove oldest entry
            for (uint256 i = 0; i < gasHistory.length - 1; i++) {
                gasHistory[i] = gasHistory[i + 1];
            }
            gasHistory.pop();
        }
        gasHistory.push(gasUsed);
    }

    /*//////////////////////////////////////////////////////////////
                         TARGET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a target contract for stress testing
     */
    function addTargetContract(
        address target
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(target != address(0), "Invalid address");
        require(!isTargetContract[target], "Already added");

        targetContracts.push(target);
        isTargetContract[target] = true;
    }

    /**
     * @notice Remove a target contract
     */
    function removeTargetContract(
        address target
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isTargetContract[target], "Not a target");

        isTargetContract[target] = false;

        for (uint256 i = 0; i < targetContracts.length; i++) {
            if (targetContracts[i] == target) {
                targetContracts[i] = targetContracts[
                    targetContracts.length - 1
                ];
                targetContracts.pop();
                break;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          BENCHMARKING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Run a baseline benchmark
     */
    function runBaseline() external onlyRole(STRESS_OPERATOR_ROLE) {
        uint256 gasStart = gasleft();

        // Standard operation set
        for (uint256 i = 0; i < 100; i++) {
            loadCounter++;
            loadStorage[bytes32(loadCounter)] = bytes32(block.timestamp);
        }

        baselineGas = gasStart - gasleft();

        emit BenchmarkUpdated(baselineGas, peakThroughput);
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get test details
     */
    function getTest(uint256 testId) external view returns (StressTest memory) {
        return stressTests[testId];
    }

    /**
     * @notice Get metrics for a test
     */
    function getMetrics(
        uint256 testId
    ) external view returns (PerformanceMetrics memory) {
        return testMetrics[testId];
    }

    /**
     * @notice Get current chaos config
     */
    function getChaosConfig() external view returns (ChaosConfig memory) {
        return chaosConfig;
    }

    /**
     * @notice Get target contracts
     */
    function getTargetContracts() external view returns (address[] memory) {
        return targetContracts;
    }

    /**
     * @notice Check if a test is currently running
     */
    function isTestRunning() external view returns (bool) {
        return activeTestId != 0 && !stressTests[activeTestId].completed;
    }
}
