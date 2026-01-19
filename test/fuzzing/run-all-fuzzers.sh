#!/bin/bash
# PIL v2 Extensive Fuzzing Suite
# Run all Echidna fuzzing tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="$SCRIPT_DIR/echidna.config.yaml"
RESULTS_DIR="$PROJECT_ROOT/fuzzing-results"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Contracts to fuzz
CONTRACTS=(
    "EchidnaPC3"
    "EchidnaPBP"
    "EchidnaEASC"
    "EchidnaCDNA"
    "EchidnaTimelock"
    "EchidnaVerifierRegistry"
    "EchidnaOrchestrator"
    "EchidnaVerifiers"
    "EchidnaAtomicSwap"
    "EchidnaCompliance"
    "EchidnaCrossChainHub"
    "EchidnaIntegration"
)

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         PIL v2 Extensive Fuzzing Suite                       ║${NC}"
echo -e "${BLUE}║         Running ${#CONTRACTS[@]} Echidna Fuzzing Contracts                  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check for echidna
if ! command -v echidna &> /dev/null; then
    echo -e "${RED}Error: echidna is not installed${NC}"
    echo "Install with: pip install echidna-test"
    echo "Or: brew install echidna (macOS)"
    exit 1
fi

echo -e "${YELLOW}Echidna version:${NC} $(echidna --version 2>/dev/null || echo 'unknown')"
echo ""

# Track results
PASSED=0
FAILED=0
SKIPPED=0

# Run each fuzzer
for CONTRACT in "${CONTRACTS[@]}"; do
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Running:${NC} $CONTRACT"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    LOG_FILE="$RESULTS_DIR/${CONTRACT}_$(date +%Y%m%d_%H%M%S).log"
    
    cd "$PROJECT_ROOT"
    
    if echidna . \
        --contract "$CONTRACT" \
        --config "$CONFIG_FILE" \
        --crytic-args "--solc-remaps @openzeppelin/=node_modules/@openzeppelin/" \
        2>&1 | tee "$LOG_FILE"; then
        echo -e "${GREEN}✓ $CONTRACT passed${NC}"
        ((PASSED++))
    else
        if grep -q "no contract found" "$LOG_FILE"; then
            echo -e "${YELLOW}⊘ $CONTRACT skipped (contract not found)${NC}"
            ((SKIPPED++))
        else
            echo -e "${RED}✗ $CONTRACT failed${NC}"
            ((FAILED++))
        fi
    fi
    
    echo ""
done

# Summary
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     FUZZING SUMMARY                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "${GREEN}Passed:${NC}  $PASSED"
echo -e "${RED}Failed:${NC}  $FAILED"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
echo -e "${BLUE}Total:${NC}   ${#CONTRACTS[@]}"
echo ""
echo -e "Results saved to: ${YELLOW}$RESULTS_DIR${NC}"

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Some fuzzing tests found issues!${NC}"
    exit 1
fi

echo -e "${GREEN}All fuzzing tests completed successfully!${NC}"
