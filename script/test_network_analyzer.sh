#!/bin/bash

# Test script for Network Analyzer
# This script performs basic functionality tests

set -euo pipefail

# Test configuration
TEST_DIR="/tmp/network_analyzer_test"
TEST_DURATION=30
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_ANALYZER="$SCRIPT_DIR/network_analyzer.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Print test header
print_header() {
    echo
    echo "=========================================="
    echo "    Network Analyzer Test Suite"
    echo "=========================================="
    echo
}

# Print test result
print_result() {
    local test_name="$1"
    local result="$2"
    local message="$3"
    
    if [[ "$result" == "PASS" ]]; then
        echo -e "${GREEN}[PASS]${NC} $test_name: $message"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}[FAIL]${NC} $test_name: $message"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Check script existence and permissions
test_script_exists() {
    echo "Testing script existence and permissions..."
    
    if [[ -f "$NETWORK_ANALYZER" ]]; then
        if [[ -x "$NETWORK_ANALYZER" ]]; then
            print_result "Script Permissions" "PASS" "Network analyzer script is executable"
        else
            print_result "Script Permissions" "FAIL" "Network analyzer script is not executable"
        fi
    else
        print_result "Script Existence" "FAIL" "Network analyzer script not found"
    fi
}

# Test 2: Check configuration file
test_config_file() {
    echo "Testing configuration file..."
    
    local config_file="$SCRIPT_DIR/network_config.conf"
    if [[ -f "$config_file" ]]; then
        if grep -q "\[monitoring\]" "$config_file"; then
            print_result "Configuration File" "PASS" "Configuration file exists and has required sections"
        else
            print_result "Configuration File" "FAIL" "Configuration file missing required sections"
        fi
    else
        print_result "Configuration File" "FAIL" "Configuration file not found"
    fi
}

# Test 3: Check Python processor
test_python_processor() {
    echo "Testing Python processor..."
    
    local python_script="$SCRIPT_DIR/network_processor.py"
    if [[ -f "$python_script" ]]; then
        if python3 -m py_compile "$python_script"; then
            print_result "Python Processor" "PASS" "Python processor script is valid"
        else
            print_result "Python Processor" "FAIL" "Python processor script has syntax errors"
        fi
    else
        print_result "Python Processor" "FAIL" "Python processor script not found"
    fi
}

# Test 4: Check help output
test_help_output() {
    echo "Testing help output..."
    
    if timeout 10 "$NETWORK_ANALYZER" --help > /dev/null 2>&1; then
        print_result "Help Output" "PASS" "Help command works"
    else
        print_result "Help Output" "FAIL" "Help command failed"
    fi
}

# Test 5: Check version output
test_version_output() {
    echo "Testing version output..."
    
    if timeout 10 "$NETWORK_ANALYZER" --version > /dev/null 2>&1; then
        print_result "Version Output" "PASS" "Version command works"
    else
        print_result "Version Output" "FAIL" "Version command failed"
    fi
}

# Test 6: Check status without daemon
test_status_no_daemon() {
    echo "Testing status without daemon..."
    
    local output
    output=$("$NETWORK_ANALYZER" --status 2>&1 || true)
    if [[ "$output" == *"not running"* ]]; then
        print_result "Status Check" "PASS" "Status correctly reports daemon not running"
    else
        print_result "Status Check" "FAIL" "Status check failed or gave unexpected output"
    fi
}

# Test 7: Check cleanup functionality
test_cleanup() {
    echo "Testing cleanup functionality..."
    
    # Create test directory and files
    mkdir -p "$TEST_DIR"
    echo "test data" > "$TEST_DIR/old_file.txt"
    
    # Set file to be old (simulate with touch)
    touch -d "8 days ago" "$TEST_DIR/old_file.txt"
    
    # Run cleanup
    if timeout 10 "$NETWORK_ANALYZER" --cleanup > /dev/null 2>&1; then
        print_result "Cleanup Function" "PASS" "Cleanup command executed successfully"
    else
        print_result "Cleanup Function" "FAIL" "Cleanup command failed"
    fi
    
    # Cleanup test directory
    rm -rf "$TEST_DIR"
}

# Test 8: Check prerequisites
test_prerequisites() {
    echo "Testing prerequisites..."
    
    local missing_tools=()
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    # Check if running as root (for full functionality)
    if [[ $EUID -ne 0 ]]; then
        print_result "Root Privileges" "FAIL" "Not running as root - some tests may fail"
    else
        print_result "Root Privileges" "PASS" "Running with root privileges"
    fi
    
    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        print_result "Prerequisites" "PASS" "All required tools available"
    else
        print_result "Prerequisites" "FAIL" "Missing tools: ${missing_tools[*]}"
    fi
}

# Test 9: Test dry run (without actual execution)
test_dry_run() {
    echo "Testing dry run configuration..."
    
    # Create minimal test configuration
    local test_config="$TEST_DIR/test_config.conf"
    mkdir -p "$TEST_DIR"
    
    cat > "$test_config" << EOF
[monitoring]
lsock_interval=5
traffic_interval=5
analysis_duration=10
auto_start=false

[output]
output_dir=$TEST_DIR
log_level=ERROR
export_format=json
EOF
    
    # Test configuration loading (this will fail for non-root but that's expected)
    if timeout 15 "$NETWORK_ANALYZER" -c "$test_config" --help > /dev/null 2>&1; then
        print_result "Configuration Loading" "PASS" "Configuration can be loaded"
    else
        print_result "Configuration Loading" "FAIL" "Configuration loading failed"
    fi
    
    # Cleanup
    rm -rf "$TEST_DIR"
}

# Test 10: Test Python processor standalone
test_python_standalone() {
    echo "Testing Python processor standalone..."
    
    # Create test data
    mkdir -p "$TEST_DIR"
    cat > "$TEST_DIR/test_lsock.txt" << EOF
=== 2024-12-28 15:30:00 ===
tcp 127.0.0.1:22 0.0.0.0:0 LISTEN 1234/sshd
tcp 127.0.0.1:80 0.0.0.0:0 LISTEN 5678/nginx
EOF
    
    # Test Python processor
    local python_script="$SCRIPT_DIR/network_processor.py"
    if timeout 10 python3 "$python_script" --input "$TEST_DIR/test_lsock.txt" --output-dir "$TEST_DIR" --type lsock --format json > /dev/null 2>&1; then
        print_result "Python Standalone" "PASS" "Python processor works standalone"
    else
        print_result "Python Standalone" "FAIL" "Python processor failed standalone test"
    fi
    
    # Cleanup
    rm -rf "$TEST_DIR"
}

# Run all tests
run_all_tests() {
    print_header
    
    echo "Running Network Analyzer test suite..."
    echo "Test directory: $TEST_DIR"
    echo "Test duration: $TEST_DURATION seconds"
    echo
    
    test_script_exists
    test_config_file
    test_python_processor
    test_help_output
    test_version_output
    test_status_no_daemon
    test_cleanup
    test_prerequisites
    test_dry_run
    test_python_standalone
    
    echo
    echo "=========================================="
    echo "           Test Results Summary"
    echo "=========================================="
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo -e "Total tests:  $((TESTS_PASSED + TESTS_FAILED))"
    echo
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        echo "Network Analyzer appears to be working correctly."
        exit 0
    else
        echo -e "${RED}Some tests failed.${NC}"
        echo "Please check the issues above before using Network Analyzer."
        exit 1
    fi
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_all_tests
fi 