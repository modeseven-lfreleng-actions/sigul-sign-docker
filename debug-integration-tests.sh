#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Local Debug Script for Sigul Integration Tests
#
# This script replicates the GitHub workflow steps locally for debugging
# the functional test failures. It mirrors the exact steps from the
# build-test.yaml workflow's functional-tests job.
#
# Usage:
#   ./debug-integration-tests.sh [OPTIONS]
#
# Options:
#   --verbose       Enable verbose output
#   --cleanup       Clean up existing infrastructure first
#   --keep-running  Don't clean up after tests (for debugging)
#   --help          Show this help message

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Default options
VERBOSE_MODE=false
CLEANUP_FIRST=false
KEEP_RUNNING=false
SHOW_HELP=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $*"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN:${NC} $*"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $*" >&2
}

success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS:${NC} $*"
}

verbose() {
    if [[ "${VERBOSE_MODE}" == "true" ]]; then
        echo -e "${PURPLE}[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG:${NC} $*"
    fi
}

# Help function
show_help() {
    cat << EOF
Local Debug Script for Sigul Integration Tests

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --verbose       Enable verbose output
    --cleanup       Clean up existing infrastructure first
    --keep-running  Don't clean up after tests (for debugging)
    --help          Show this help message

DESCRIPTION:
    This script replicates the GitHub workflow steps locally for debugging
    integration test failures. It will:

    1. Detect the local platform architecture
    2. Set up environment variables for container images
    3. Deploy fresh Sigul infrastructure (or use existing)
    4. Run integration tests with detailed logging
    5. Capture and display debug information

REQUIREMENTS:
    - Docker running locally
    - Container images built and tagged locally:
      - client-linux-{amd64,arm64}-image:test
      - server-linux-{amd64,arm64}-image:test
      - bridge-linux-{amd64,arm64}-image:test

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose)
                VERBOSE_MODE=true
                shift
                ;;
            --cleanup)
                CLEANUP_FIRST=true
                shift
                ;;
            --keep-running)
                KEEP_RUNNING=true
                shift
                ;;
            --help)
                SHOW_HELP=true
                shift
                ;;
            *)
                error "Unknown option: $1"
                echo
                show_help
                exit 1
                ;;
        esac
    done
}

# Detect runner architecture (mirrors GitHub workflow)
detect_runner_architecture() {
    log "Detecting runner architecture..."

    local arch
    arch=$(uname -m)

    case $arch in
        x86_64)
            export PLATFORM_ID="linux-amd64"
            export DOCKER_PLATFORM="linux/amd64"
            ;;
        aarch64|arm64)
            export PLATFORM_ID="linux-arm64"
            export DOCKER_PLATFORM="linux/arm64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac

    success "Detected runner architecture: $arch -> $PLATFORM_ID"
    verbose "PLATFORM_ID=${PLATFORM_ID}"
    verbose "DOCKER_PLATFORM=${DOCKER_PLATFORM}"
}

# Set up environment variables for container images
setup_environment() {
    log "Setting up environment variables..."

    # Set container image names based on detected platform
    export SIGUL_CLIENT_IMAGE="client-${PLATFORM_ID}-image:test"
    export SIGUL_SERVER_IMAGE="server-${PLATFORM_ID}-image:test"
    export SIGUL_BRIDGE_IMAGE="bridge-${PLATFORM_ID}-image:test"

    # Set platform info for deployment script
    export SIGUL_RUNNER_PLATFORM="${PLATFORM_ID}"
    export SIGUL_DOCKER_PLATFORM="${DOCKER_PLATFORM}"
    export SIGUL_PLATFORM_ID="${PLATFORM_ID}"

    verbose "SIGUL_CLIENT_IMAGE=${SIGUL_CLIENT_IMAGE}"
    verbose "SIGUL_SERVER_IMAGE=${SIGUL_SERVER_IMAGE}"
    verbose "SIGUL_BRIDGE_IMAGE=${SIGUL_BRIDGE_IMAGE}"

    success "Environment variables configured"
}

# Verify container images exist locally
verify_container_images() {
    log "Verifying container images exist locally..."

    local missing_images=()

    for image in "$SIGUL_CLIENT_IMAGE" "$SIGUL_SERVER_IMAGE" "$SIGUL_BRIDGE_IMAGE"; do
        if ! docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "^${image}$"; then
            missing_images+=("$image")
        else
            verbose "Found image: $image"
        fi
    done

    if [[ ${#missing_images[@]} -gt 0 ]]; then
        error "Missing container images:"
        for image in "${missing_images[@]}"; do
            error "  - $image"
        done
        echo
        error "Please build the missing images first. You can use:"
        error "  docker build -f Dockerfile.client -t client-${PLATFORM_ID}-image:test ."
        error "  docker build -f Dockerfile.server -t server-${PLATFORM_ID}-image:test ."
        error "  docker build -f Dockerfile.bridge -t bridge-${PLATFORM_ID}-image:test ."
        exit 1
    fi

    success "All required container images found"
}

# Clean up existing infrastructure
cleanup_existing_infrastructure() {
    if [[ "$CLEANUP_FIRST" == "true" ]]; then
        log "Cleaning up existing infrastructure..."

        # Stop and remove containers
        local containers=(
            "sigul-server"
            "sigul-bridge"
            "sigul-client-test"
            "sigul-client-integration"
        )

        for container in "${containers[@]}"; do
            if docker ps -a --format "{{.Names}}" | grep -q "^${container}$"; then
                verbose "Removing container: $container"
                docker rm -f "$container" >/dev/null 2>&1 || true
            fi
        done

        # Clean up networks
        if docker network ls --format "{{.Name}}" | grep -q "sigul"; then
            docker network ls --filter "name=sigul" --format "{{.Name}}" | \
                xargs -r docker network rm >/dev/null 2>&1 || true
        fi

        # Clean up volumes
        if docker volume ls --format "{{.Name}}" | grep -q "sigul"; then
            docker volume ls --filter "name=sigul" --format "{{.Name}}" | \
                xargs -r docker volume rm >/dev/null 2>&1 || true
        fi

        success "Existing infrastructure cleaned up"
    else
        log "Skipping cleanup (use --cleanup to clean up existing infrastructure)"
    fi
}

# Deploy Sigul infrastructure (mirrors GitHub workflow step)
deploy_sigul_infrastructure() {
    log "Deploying Sigul infrastructure for functional tests..."

    local deploy_script="scripts/deploy-sigul-infrastructure.sh"

    if [[ ! -f "$deploy_script" ]]; then
        error "Deployment script not found: $deploy_script"
        exit 1
    fi

    chmod +x "$deploy_script"

    verbose "Running deployment script with verbose mode..."
    verbose "Platform: ${PLATFORM_ID} (${DOCKER_PLATFORM})"

    if [[ "$VERBOSE_MODE" == "true" ]]; then
        "./$deploy_script" --verbose --debug
    else
        "./$deploy_script"
    fi

    success "Sigul infrastructure deployed"
}

# Run integration tests with enhanced logging
run_integration_tests() {
    log "Running integration tests with enhanced logging..."

    local test_script="scripts/run-integration-tests.sh"

    if [[ ! -f "$test_script" ]]; then
        error "Integration test script not found: $test_script"
        exit 1
    fi

    chmod +x "$test_script"

    # Create debug directory for capturing logs
    local debug_dir="${PROJECT_ROOT}/debug"
    mkdir -p "$debug_dir"

    log "Starting integration tests..."
    log "Debug output will be captured in: $debug_dir"

    # Run the tests with enhanced logging and capture output
    local test_exit_code=0
    local test_output_file="${debug_dir}/integration-test-output.log"
    local test_start_time
    test_start_time=$(date +%s)

    if [[ "$VERBOSE_MODE" == "true" ]]; then
        if "./$test_script" --verbose 2>&1 | tee "$test_output_file"; then
            test_exit_code=0
        else
            test_exit_code=$?
        fi
    else
        if "./$test_script" 2>&1 | tee "$test_output_file"; then
            test_exit_code=0
        else
            test_exit_code=$?
        fi
    fi

    local test_end_time
    test_end_time=$(date +%s)
    local test_duration=$((test_end_time - test_start_time))

    # Capture container logs for debugging
    capture_debug_information "$debug_dir"

    if [[ $test_exit_code -eq 0 ]]; then
        success "Integration tests completed successfully (${test_duration}s)"
    else
        error "Integration tests failed with exit code: $test_exit_code (${test_duration}s)"

        # Show tail of test output for immediate feedback
        log "Last 20 lines of test output:"
        tail -20 "$test_output_file" || true
    fi

    return $test_exit_code
}

# Capture debug information from containers and environment
capture_debug_information() {
    local debug_dir="$1"

    log "Capturing debug information..."

    # Container logs
    local containers=("sigul-server" "sigul-bridge" "sigul-client-test" "sigul-client-integration")
    for container in "${containers[@]}"; do
        if docker ps -a --format "{{.Names}}" | grep -q "^${container}$"; then
            verbose "Capturing logs for: $container"
            docker logs "$container" > "${debug_dir}/${container}-logs.txt" 2>&1 || true
        fi
    done

    # Container status
    docker ps -a > "${debug_dir}/container-status.txt" 2>&1 || true

    # Network information
    docker network ls > "${debug_dir}/networks.txt" 2>&1 || true
    if docker network ls --format "{{.Name}}" | grep -q "sigul"; then
        docker network inspect sigul-sign-docker_sigul-network > "${debug_dir}/sigul-network-inspect.txt" 2>&1 || true
    fi

    # Volume information
    docker volume ls > "${debug_dir}/volumes.txt" 2>&1 || true

    # Image information
    docker images | grep -E "(client|server|bridge)" > "${debug_dir}/images.txt" 2>&1 || true

    # Test artifacts
    if [[ -d "${PROJECT_ROOT}/test-artifacts" ]]; then
        cp -r "${PROJECT_ROOT}/test-artifacts" "${debug_dir}/" 2>/dev/null || true
    fi

    # Test workspace
    if [[ -d "${PROJECT_ROOT}/test-workspace" ]]; then
        cp -r "${PROJECT_ROOT}/test-workspace" "${debug_dir}/" 2>/dev/null || true
    fi

    # Environment information
    env | grep -E "(SIGUL|DOCKER|NSS)" > "${debug_dir}/environment.txt" 2>&1 || true

    success "Debug information captured in: $debug_dir"
}

# Clean up after tests (unless --keep-running is specified)
cleanup_after_tests() {
    if [[ "$KEEP_RUNNING" == "true" ]]; then
        warn "Keeping infrastructure running for debugging (--keep-running specified)"
        log "To manually clean up later, run:"
        log "  docker rm -f sigul-server sigul-bridge sigul-client-test sigul-client-integration"
        log "  docker network rm sigul-sign-docker_sigul-network"
    else
        log "Cleaning up test infrastructure..."

        # Stop integration test client container
        docker rm -f "sigul-client-integration" 2>/dev/null || true

        success "Test cleanup completed"
    fi
}

# Show debug summary
show_debug_summary() {
    local debug_dir="${PROJECT_ROOT}/debug"

    log "=== DEBUG SUMMARY ==="
    log "Debug files location: $debug_dir"

    if [[ -f "${debug_dir}/integration-test-output.log" ]]; then
        log "Integration test output: ${debug_dir}/integration-test-output.log"
    fi

    log "Container logs available in debug directory:"
    local containers=("sigul-server" "sigul-bridge" "sigul-client-test" "sigul-client-integration")
    for container in "${containers[@]}"; do
        if [[ -f "${debug_dir}/${container}-logs.txt" ]]; then
            log "  - ${container}-logs.txt"
        fi
    done

    if [[ -f "${debug_dir}/test-summary.txt" ]]; then
        log "Test summary: ${debug_dir}/test-summary.txt"
        echo
        log "=== TEST SUMMARY ==="
        cat "${debug_dir}/test-summary.txt" 2>/dev/null || true
    fi

    # Show current container status
    log "Current container status:"
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(sigul|NAME)" || true
}

# Main function
main() {
    parse_args "$@"

    if [[ "${SHOW_HELP}" == "true" ]]; then
        show_help
        exit 0
    fi

    log "=== Sigul Integration Tests Local Debug ==="
    log "Verbose mode: ${VERBOSE_MODE}"
    log "Cleanup first: ${CLEANUP_FIRST}"
    log "Keep running: ${KEEP_RUNNING}"
    log "Project root: ${PROJECT_ROOT}"

    # Step 1: Architecture detection (mirrors GitHub workflow)
    detect_runner_architecture

    # Step 2: Environment setup
    setup_environment

    # Step 3: Verify container images exist
    verify_container_images

    # Step 4: Optional cleanup
    cleanup_existing_infrastructure

    # Step 5: Deploy infrastructure (mirrors GitHub workflow)
    deploy_sigul_infrastructure

    # Step 6: Run integration tests with logging
    local test_result=0
    if run_integration_tests; then
        success "=== Integration Tests Passed ==="
    else
        test_result=$?
        error "=== Integration Tests Failed ==="
    fi

    # Step 7: Cleanup (optional)
    cleanup_after_tests

    # Step 8: Show debug summary
    show_debug_summary

    if [[ $test_result -eq 0 ]]; then
        success "Local debug session completed successfully"
        exit 0
    else
        error "Local debug session completed with test failures"
        error "Check the debug files for detailed analysis"
        exit $test_result
    fi
}

# Execute main function with all arguments
main "$@"
