#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Sigul Component Testing Script
#
# This script provides detailed testing and debugging capabilities for individual
# Sigul components to help isolate and resolve deployment issues.
#
# Usage:
#   ./local-testing/test-components.sh <component> [test-type] [options]
#
# Components:
#   server      Test Sigul server component
#   bridge      Test Sigul bridge component
#   client      Test Sigul client component
#   certs       Test certificate generation and validation
#   network     Test network connectivity between components
#   all         Test all components in sequence
#
# Test Types:
#   build       Test container build process
#   config      Test configuration generation
#   startup     Test component startup and initialization
#   health      Test component health and status
#   logs        Analyze component logs for issues
#   detailed    Run comprehensive tests with detailed output

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.sigul.yml"
ENV_FILE="${SCRIPT_DIR}/.env"
TEST_RESULTS_DIR="${SCRIPT_DIR}/test-results-$(date +%Y%m%d-%H%M%S)"

# Platform configuration for ARM64
PLATFORM="linux/arm64"
PLATFORM_ID="linux-arm64"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test status tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNINGS=0

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')] ${NC}$*"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN:${NC} $*"
    ((WARNINGS++))
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $*" >&2
}

success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] SUCCESS:${NC} $*"
}

debug() {
    echo -e "${PURPLE}[$(date '+%H:%M:%S')] DEBUG:${NC} $*"
}

info() {
    echo -e "${CYAN}[$(date '+%H:%M:%S')] INFO:${NC} $*"
}

# Test result functions
test_start() {
    local test_name="$1"
    echo ""
    log "🧪 Starting test: $test_name"
    ((TOTAL_TESTS++))
}

test_pass() {
    local test_name="$1"
    success "✅ PASS: $test_name"
    ((PASSED_TESTS++))
}

test_fail() {
    local test_name="$1"
    local reason="${2:-Unknown reason}"
    error "❌ FAIL: $test_name - $reason"
    ((FAILED_TESTS++))
}

# Function to determine which Docker Compose command to use
get_docker_compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        echo "docker compose"
    fi
}

# Load environment if exists
load_environment() {
    if [[ -f "$ENV_FILE" ]]; then
        set -a
        # shellcheck disable=SC1090
        source "$ENV_FILE"
        set +a
        debug "Environment loaded from $ENV_FILE"
    else
        warn "Environment file not found: $ENV_FILE"
    fi
}

# Create test results directory
setup_test_results() {
    mkdir -p "$TEST_RESULTS_DIR"
    log "Test results will be saved to: $TEST_RESULTS_DIR"
}

# Show usage information
show_usage() {
    cat << EOF
Sigul Component Testing Script

USAGE:
    $0 <component> [test-type] [options]

COMPONENTS:
    server              Test Sigul server component
    bridge              Test Sigul bridge component
    client              Test Sigul client component
    certs               Test certificate generation and validation
    network             Test network connectivity between components
    all                 Test all components in sequence

TEST TYPES:
    build               Test container build process
    config              Test configuration generation
    startup             Test component startup and initialization
    health              Test component health and status
    logs                Analyze component logs for issues
    detailed            Run comprehensive tests with detailed output

OPTIONS:
    --verbose           Enable verbose output
    --debug             Enable debug mode
    --save-logs         Save all logs to test results directory
    --help              Show this help message

EXAMPLES:
    $0 server build                 # Test server container build
    $0 bridge startup --verbose     # Test bridge startup with verbose output
    $0 certs detailed               # Run detailed certificate tests
    $0 network                      # Test network connectivity
    $0 all --save-logs              # Test all components and save logs

EOF
}

# Test container build process
test_build() {
    local component="$1"
    test_start "Build test for $component"

    local dockerfile="Dockerfile.${component}"
    local image_tag="${component}-${PLATFORM_ID}-image:test"

    if [[ ! -f "$PROJECT_ROOT/$dockerfile" ]]; then
        test_fail "Build test for $component" "Dockerfile not found: $dockerfile"
        return 1
    fi

    log "Building $component container..."
    cd "$PROJECT_ROOT"

    export DOCKER_BUILDKIT=1
    export BUILDKIT_PROGRESS=plain

    if docker build \
        --platform "$PLATFORM" \
        -f "$dockerfile" \
        -t "$image_tag" \
        . > "$TEST_RESULTS_DIR/${component}-build.log" 2>&1; then
        test_pass "Build test for $component"

        # Verify image exists
        if docker images "$image_tag" --format "table {{.Repository}}:{{.Tag}}" | grep -q "$image_tag"; then
            success "Image $image_tag created successfully"
        else
            test_fail "Build test for $component" "Image not found after build"
            return 1
        fi
    else
        test_fail "Build test for $component" "Docker build failed"
        error "Build log saved to: $TEST_RESULTS_DIR/${component}-build.log"
        return 1
    fi
}

# Test configuration generation
test_config() {
    local component="$1"
    test_start "Configuration test for $component"

    load_environment

    # Test environment variables
    case "$component" in
        server)
            if [[ -n "${SIGUL_SERVER_IMAGE:-}" ]]; then
                success "Server image configured: $SIGUL_SERVER_IMAGE"
            else
                test_fail "Configuration test for $component" "SIGUL_SERVER_IMAGE not set"
                return 1
            fi
            ;;
        bridge)
            if [[ -n "${SIGUL_BRIDGE_IMAGE:-}" ]]; then
                success "Bridge image configured: $SIGUL_BRIDGE_IMAGE"
            else
                test_fail "Configuration test for $component" "SIGUL_BRIDGE_IMAGE not set"
                return 1
            fi
            ;;
        client)
            if [[ -n "${SIGUL_CLIENT_IMAGE:-}" ]]; then
                success "Client image configured: $SIGUL_CLIENT_IMAGE"
            else
                test_fail "Configuration test for $component" "SIGUL_CLIENT_IMAGE not set"
                return 1
            fi
            ;;
    esac

    # Test required environment variables
    local required_vars=("NSS_PASSWORD" "DEBUG")
    for var in "${required_vars[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            debug "$var is set"
        else
            warn "$var is not set"
        fi
    done

    test_pass "Configuration test for $component"
}

# Test component startup
test_startup() {
    local component="$1"
    test_start "Startup test for $component"

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)
    local container_name="sigul-${component}"

    load_environment

    # Stop container if running
    $compose_cmd -f "$COMPOSE_FILE" stop "$container_name" 2>/dev/null || true

    # Start container
    log "Starting $container_name..."
    if $compose_cmd -f "$COMPOSE_FILE" up -d "$container_name"; then
        success "Container $container_name started"
    else
        test_fail "Startup test for $component" "Failed to start container"
        return 1
    fi

    # Wait for initialization
    log "Waiting for $component to initialize..."
    sleep 15

    # Check if container is still running
    if $compose_cmd -f "$COMPOSE_FILE" ps "$container_name" --format "table {{.Status}}" | grep -q "Up"; then
        test_pass "Startup test for $component"
    else
        test_fail "Startup test for $component" "Container not running after startup"

        # Collect logs for debugging
        log "Collecting logs for failed startup..."
        $compose_cmd -f "$COMPOSE_FILE" logs "$container_name" > "$TEST_RESULTS_DIR/${component}-startup-failed.log" 2>&1
        error "Startup logs saved to: $TEST_RESULTS_DIR/${component}-startup-failed.log"
        return 1
    fi
}

# Test component health
test_health() {
    local component="$1"
    test_start "Health test for $component"

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)
    local container_name="sigul-${component}"

    # Check container status
    local status
    status=$($compose_cmd -f "$COMPOSE_FILE" ps "$container_name" --format "table {{.Status}}" | tail -n +2)

    if [[ "$status" =~ "Up" ]]; then
        success "Container $container_name is running"
    else
        test_fail "Health test for $component" "Container not running: $status"
        return 1
    fi

    # Component-specific health checks
    case "$component" in
        server)
            if $compose_cmd -f "$COMPOSE_FILE" exec -T "$container_name" pgrep -f "sigul_server" >/dev/null 2>&1; then
                success "Server process is running"
            else
                test_fail "Health test for $component" "Server process not found"
                return 1
            fi
            ;;
        bridge)
            if $compose_cmd -f "$COMPOSE_FILE" exec -T "$container_name" pgrep -f "sigul_bridge" >/dev/null 2>&1; then
                success "Bridge process is running"
            else
                test_fail "Health test for $component" "Bridge process not found"
                return 1
            fi

            # Test bridge port
            if $compose_cmd -f "$COMPOSE_FILE" exec -T "$container_name" nc -z localhost 44334 2>/dev/null; then
                success "Bridge port 44334 is accessible"
            else
                warn "Bridge port 44334 is not accessible"
            fi
            ;;
        client)
            # For client, just check if initialization completed
            if $compose_cmd -f "$COMPOSE_FILE" exec -T "$container_name" test -f /var/sigul/config/client.conf 2>/dev/null; then
                success "Client configuration exists"
            else
                test_fail "Health test for $component" "Client configuration not found"
                return 1
            fi
            ;;
    esac

    # Check directory structure
    if $compose_cmd -f "$COMPOSE_FILE" exec -T "$container_name" test -d /var/sigul 2>/dev/null; then
        success "Sigul directory structure exists"

        # List directory contents
        debug "Sigul directory contents:"
        $compose_cmd -f "$COMPOSE_FILE" exec -T "$container_name" ls -la /var/sigul/ 2>/dev/null || true
    else
        warn "Sigul directory structure missing"
    fi

    test_pass "Health test for $component"
}

# Analyze component logs
test_logs() {
    local component="$1"
    test_start "Log analysis for $component"

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)
    local container_name="sigul-${component}"
    local log_file="$TEST_RESULTS_DIR/${component}-logs.txt"

    # Get logs
    if $compose_cmd -f "$COMPOSE_FILE" logs "$container_name" > "$log_file" 2>&1; then
        success "Logs collected for $component"
    else
        test_fail "Log analysis for $component" "Failed to collect logs"
        return 1
    fi

    # Analyze logs for errors
    local error_count
    error_count=$(grep -i "error" "$log_file" | wc -l)

    local warning_count
    warning_count=$(grep -i "warning\|warn" "$log_file" | wc -l)

    info "Log analysis results:"
    info "  Errors found: $error_count"
    info "  Warnings found: $warning_count"

    if [[ $error_count -gt 0 ]]; then
        warn "Errors found in logs:"
        grep -i "error" "$log_file" | head -5 || true
    fi

    if [[ $warning_count -gt 0 ]]; then
        debug "Warnings found in logs:"
        grep -i "warning\|warn" "$log_file" | head -3 || true
    fi

    # Look for successful initialization patterns
    case "$component" in
        server)
            if grep -q "server.*start\|initialization.*complete\|ready" "$log_file"; then
                success "Server initialization messages found"
            else
                warn "No clear server initialization success messages found"
            fi
            ;;
        bridge)
            if grep -q "bridge.*start\|initialization.*complete\|listening" "$log_file"; then
                success "Bridge initialization messages found"
            else
                warn "No clear bridge initialization success messages found"
            fi
            ;;
    esac

    test_pass "Log analysis for $component"
}

# Test certificate generation and validation
test_certificates() {
    test_start "Certificate generation and validation"

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Test CA setup
    log "Testing CA certificate setup..."
    if [[ -f "$PROJECT_ROOT/pki/setup-ca.sh" ]]; then
        success "CA setup script found"

        # Check if script is executable
        if [[ -x "$PROJECT_ROOT/pki/setup-ca.sh" ]]; then
            success "CA setup script is executable"
        else
            warn "CA setup script is not executable"
        fi
    else
        test_fail "Certificate test" "CA setup script not found"
        return 1
    fi

    # Test certificate generation script
    if [[ -f "$PROJECT_ROOT/pki/generate-component-cert.sh" ]]; then
        success "Certificate generation script found"
    else
        test_fail "Certificate test" "Certificate generation script not found"
        return 1
    fi

    # Test certificate templates
    local templates=("server.conf.template" "bridge.conf.template")
    for template in "${templates[@]}"; do
        if [[ -f "$PROJECT_ROOT/pki/$template" ]]; then
            success "Certificate template found: $template"
        else
            warn "Certificate template missing: $template"
        fi
    done

    # Test certificates in running containers
    local containers=("sigul-server" "sigul-bridge")
    for container in "${containers[@]}"; do
        if $compose_cmd -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -q "${container#sigul-}"; then
            log "Checking certificates in $container..."

            if $compose_cmd -f "$COMPOSE_FILE" exec -T "$container" test -d /var/sigul/secrets/certificates 2>/dev/null; then
                success "$container: Certificate directory exists"

                local cert_count
                cert_count=$($compose_cmd -f "$COMPOSE_FILE" exec -T "$container" ls /var/sigul/secrets/certificates/ 2>/dev/null | wc -l)
                info "$container: Certificate count: $cert_count"
            else
                warn "$container: Certificate directory missing"
            fi
        else
            debug "$container: Not running, skipping certificate check"
        fi
    done

    test_pass "Certificate generation and validation"
}

# Test network connectivity
test_network() {
    test_start "Network connectivity test"

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Start network tester
    $compose_cmd -f "$COMPOSE_FILE" --profile testing up -d network-tester
    sleep 5

    # Test DNS resolution
    log "Testing DNS resolution..."
    if $compose_cmd -f "$COMPOSE_FILE" exec -T network-tester nslookup sigul-bridge >/dev/null 2>&1; then
        success "DNS resolution: sigul-bridge"
    else
        test_fail "Network test" "DNS resolution failed for sigul-bridge"
        return 1
    fi

    if $compose_cmd -f "$COMPOSE_FILE" exec -T network-tester nslookup sigul-server >/dev/null 2>&1; then
        success "DNS resolution: sigul-server"
    else
        warn "DNS resolution failed for sigul-server"
    fi

    # Test network connectivity
    log "Testing network connectivity..."
    if $compose_cmd -f "$COMPOSE_FILE" exec -T network-tester nc -z sigul-bridge 44334 2>/dev/null; then
        success "Bridge port 44334: Accessible from network-tester"
    else
        test_fail "Network test" "Bridge port 44334 not accessible"
        return 1
    fi

    # Test inter-container connectivity
    log "Testing inter-container connectivity..."
    if $compose_cmd -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -q "server"; then
        # Test server to bridge connectivity (if both are running)
        if $compose_cmd -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -q "bridge"; then
            # Note: Server connects to bridge, not the other way around
            success "Both server and bridge are running"
        fi
    fi

    # Test network isolation
    log "Testing network isolation..."
    local network_name
    network_name=$($compose_cmd -f "$COMPOSE_FILE" config | grep -A 5 "networks:" | grep -v "networks:" | head -1 | awk '{print $1}' | tr -d ':')

    if [[ -n "$network_name" ]]; then
        success "Network configuration found: $network_name"
    else
        warn "Network configuration not found"
    fi

    test_pass "Network connectivity test"
}

# Run detailed tests for a component
test_detailed() {
    local component="$1"

    log "Running detailed tests for $component..."

    # Run all test types for the component
    test_build "$component"
    test_config "$component"
    test_startup "$component"
    sleep 10  # Give time for full initialization
    test_health "$component"
    test_logs "$component"

    success "Detailed tests completed for $component"
}

# Test all components
test_all() {
    log "Running tests for all components..."

    # Test certificates first
    test_certificates

    # Test individual components
    local components=("server" "bridge" "client")
    for component in "${components[@]}"; do
        log "Testing $component component..."
        test_build "$component"
        test_config "$component"
    done

    # Test startup in order (server, bridge, client)
    test_startup "server"
    sleep 10
    test_startup "bridge"
    sleep 10

    # Test health
    for component in "server" "bridge"; do
        test_health "$component"
        test_logs "$component"
    done

    # Test network connectivity
    test_network

    success "All component tests completed"
}

# Generate test summary
generate_summary() {
    local summary_file="$TEST_RESULTS_DIR/test-summary.txt"

    cat > "$summary_file" << EOF
Sigul Component Test Summary
============================
Date: $(date)
Platform: $PLATFORM
Test Results Directory: $TEST_RESULTS_DIR

Test Results:
- Total Tests: $TOTAL_TESTS
- Passed: $PASSED_TESTS
- Failed: $FAILED_TESTS
- Warnings: $WARNINGS

Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

EOF

    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo "❌ Some tests failed. Check individual test logs for details." >> "$summary_file"
    else
        echo "✅ All tests passed successfully!" >> "$summary_file"
    fi

    # Display summary
    echo ""
    echo "=================================="
    log "Test Summary"
    echo "=================================="
    cat "$summary_file"
    echo "=================================="
    echo ""

    success "Test summary saved to: $summary_file"
}

# Main function
main() {
    local component="${1:-}"
    local test_type="${2:-health}"
    local verbose=false
    local debug_mode=false
    local save_logs=false

    # Parse options
    shift 2 2>/dev/null || shift $# # Remove component and test_type if they exist

    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose)
                verbose=true
                shift
                ;;
            --debug)
                debug_mode=true
                verbose=true
                shift
                ;;
            --save-logs)
                save_logs=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Validate arguments
    if [[ -z "$component" ]]; then
        error "Component required"
        show_usage
        exit 1
    fi

    # Setup test environment
    setup_test_results
    load_environment

    log "Starting component tests..."
    log "Component: $component"
    log "Test type: $test_type"
    log "Platform: $PLATFORM"

    # Check prerequisites
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running"
        exit 1
    fi

    # Execute tests based on component and test type
    case "$component" in
        server|bridge|client)
            case "$test_type" in
                build)
                    test_build "$component"
                    ;;
                config)
                    test_config "$component"
                    ;;
                startup)
                    test_startup "$component"
                    ;;
                health)
                    test_health "$component"
                    ;;
                logs)
                    test_logs "$component"
                    ;;
                detailed)
                    test_detailed "$component"
                    ;;
                *)
                    error "Unknown test type: $test_type"
                    show_usage
                    exit 1
                    ;;
            esac
            ;;
        certs)
            test_certificates
            ;;
        network)
            test_network
            ;;
        all)
            test_all
            ;;
        *)
            error "Unknown component: $component"
            show_usage
            exit 1
            ;;
    esac

    # Generate summary
    generate_summary

    # Exit with appropriate code
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Execute main function
main "$@"
