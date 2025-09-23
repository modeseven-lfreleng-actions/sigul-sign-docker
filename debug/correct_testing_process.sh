#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Sigul Correct Testing Process Script
#
# This script demonstrates the CORRECT way to test the Sigul stack locally
# to mirror CI/CD behavior and avoid SSL certificate issues caused by
# persistent container state.
#
# Usage:
#   ./debug/correct_testing_process.sh [--verbose] [--platform PLATFORM]
#
# Options:
#   --verbose       Enable verbose output
#   --platform      Specify platform (linux-amd64 or linux-arm64, auto-detected if not specified)
#   --help          Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default options
VERBOSE_MODE=false
SHOW_HELP=false
PLATFORM=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')] INFO:${NC} $*"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN:${NC} $*"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $*"
}

success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] SUCCESS:${NC} $*"
}

verbose() {
    if [[ "${VERBOSE_MODE}" == "true" ]]; then
        echo -e "${PURPLE}[$(date '+%H:%M:%S')] DEBUG:${NC} $*"
    fi
}

show_help() {
    cat << 'EOF'
Sigul Correct Testing Process Script

USAGE:
    ./debug/correct_testing_process.sh [OPTIONS]

OPTIONS:
    --verbose       Enable verbose output
    --platform      Specify platform (linux-amd64 or linux-arm64)
    --help          Show this help message

DESCRIPTION:
    This script demonstrates the CORRECT way to test Sigul locally to match
    CI/CD behavior. It ensures fresh container deployments with automatic
    certificate synchronization, avoiding SSL issues from persistent containers.

    The process:
    1. Complete environment cleanup (removes persistent state)
    2. Fresh infrastructure deployment (mirrors CI/CD)
    3. SSL topology verification (certificates should be auto-synchronized)
    4. Integration test execution (should work without manual SSL fixes)

CRITICAL PRINCIPLE:
    Never debug SSL issues against persistent containers. Always deploy fresh.

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
            --platform)
                PLATFORM="$2"
                shift 2
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

# Auto-detect platform if not specified
detect_platform() {
    if [[ -z "$PLATFORM" ]]; then
        local arch
        arch=$(uname -m)
        case "$arch" in
            x86_64|amd64)
                PLATFORM="linux-amd64"
                ;;
            aarch64|arm64)
                PLATFORM="linux-arm64"
                ;;
            *)
                error "Unsupported architecture: $arch"
                exit 1
                ;;
        esac
        verbose "Auto-detected platform: $PLATFORM"
    fi
}

# Step 1: Complete environment cleanup
cleanup_environment() {
    log "Step 1: Complete Environment Cleanup"
    log "Removing all persistent container state to ensure fresh deployment..."

    # Stop and remove containers with volumes
    verbose "Stopping Docker Compose services..."
    local cleanup_result=0

    # Try with environment variables if they exist
    if docker compose -f "${PROJECT_ROOT}/docker-compose.sigul.yml" ps >/dev/null 2>&1; then
        export SIGUL_SERVER_IMAGE="${SIGUL_SERVER_IMAGE:-server-${PLATFORM}-image:test}"
        export SIGUL_BRIDGE_IMAGE="${SIGUL_BRIDGE_IMAGE:-bridge-${PLATFORM}-image:test}"

        docker compose -f "${PROJECT_ROOT}/docker-compose.sigul.yml" down -v --remove-orphans || cleanup_result=1
    else
        verbose "No active compose services found"
    fi

    # Additional cleanup
    verbose "Removing any remaining containers..."
    docker rm -f sigul-server sigul-bridge sigul-client-integration 2>/dev/null || true

    verbose "Pruning system resources..."
    docker system prune -f >/dev/null 2>&1 || true
    docker volume prune -f >/dev/null 2>&1 || true

    # Clean test artifacts from previous runs
    rm -rf "${PROJECT_ROOT}/test-artifacts" 2>/dev/null || true

    if [[ $cleanup_result -eq 0 ]]; then
        success "✓ Environment cleanup completed"
    else
        warn "Environment cleanup completed with warnings (this is usually normal)"
    fi
}

# Step 2: Fresh infrastructure deployment
deploy_fresh_infrastructure() {
    log "Step 2: Fresh Infrastructure Deployment"
    log "Deploying containers from scratch with automatic certificate synchronization..."

    # Set required environment variables
    export SIGUL_RUNNER_PLATFORM="$PLATFORM"
    export SIGUL_SERVER_IMAGE="server-${PLATFORM}-image:test"
    export SIGUL_BRIDGE_IMAGE="bridge-${PLATFORM}-image:test"

    verbose "Platform: $PLATFORM"
    verbose "Server image: $SIGUL_SERVER_IMAGE"
    verbose "Bridge image: $SIGUL_BRIDGE_IMAGE"

    # Deploy infrastructure
    local deploy_script="${PROJECT_ROOT}/scripts/deploy-sigul-infrastructure.sh"

    if [[ ! -x "$deploy_script" ]]; then
        chmod +x "$deploy_script"
    fi

    local deploy_args=""
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        deploy_args="--verbose"
    fi

    if "$deploy_script" $deploy_args; then
        success "✓ Fresh infrastructure deployment completed"
    else
        error "✗ Infrastructure deployment failed"
        return 1
    fi
}

# Step 3: SSL topology verification
verify_ssl_topology() {
    log "Step 3: SSL Topology Verification"
    log "Verifying that certificates were automatically synchronized during deployment..."

    # Check that containers are running
    for container in sigul-bridge sigul-server; do
        if ! docker ps --filter "name=${container}" --filter "status=running" --format "{{.Names}}" | grep -q "^${container}$"; then
            error "Container $container is not running"
            return 1
        fi
    done

    # Verify bridge NSS database contents
    log "Bridge NSS Database:"
    local bridge_certs
    bridge_certs=$(docker exec sigul-bridge certutil -L -d /var/sigul/nss/bridge 2>/dev/null || echo "FAILED")

    if [[ "$bridge_certs" == "FAILED" ]]; then
        error "✗ Cannot read bridge NSS database"
        return 1
    fi

    echo "$bridge_certs" | while IFS= read -r line; do
        verbose "  $line"
    done

    # Check for required certificates in bridge
    local bridge_has_server
    bridge_has_server=$(echo "$bridge_certs" | grep -c "sigul-server-cert" || echo "0")

    if [[ "$bridge_has_server" -gt 0 ]]; then
        success "✓ Bridge has server certificate (backend SSL ready)"
    else
        warn "✗ Bridge missing server certificate (backend SSL may fail)"
    fi

    # Note: Client certificate won't exist until client container is created
    verbose "Client certificate will be synchronized when client container starts"

    # Verify server NSS database contents
    log "Server NSS Database:"
    local server_certs
    server_certs=$(docker exec sigul-server certutil -L -d /var/sigul/nss/server 2>/dev/null || echo "FAILED")

    if [[ "$server_certs" == "FAILED" ]]; then
        error "✗ Cannot read server NSS database"
        return 1
    fi

    echo "$server_certs" | while IFS= read -r line; do
        verbose "  $line"
    done

    # Check for required certificates in server
    local server_has_bridge
    server_has_bridge=$(echo "$server_certs" | grep -c "sigul-bridge-cert" || echo "0")

    if [[ "$server_has_bridge" -gt 0 ]]; then
        success "✓ Server has bridge certificate (backend SSL ready)"
    else
        error "✗ Server missing bridge certificate (backend SSL will fail)"
        return 1
    fi

    # Verify socket topology
    log "Socket Topology:"
    local bridge_sockets
    bridge_sockets=$(docker exec sigul-bridge ss -tlnp 2>/dev/null | grep -E "4433[34]" || echo "")

    if echo "$bridge_sockets" | grep -q ":44334"; then
        success "✓ Bridge listening on port 44334 (client access)"
    else
        error "✗ Bridge not listening on port 44334"
        return 1
    fi

    if echo "$bridge_sockets" | grep -q ":44333"; then
        success "✓ Bridge listening on port 44333 (server backend)"
    else
        error "✗ Bridge not listening on port 44333"
        return 1
    fi

    # Check server connection to bridge
    local server_connections
    server_connections=$(docker exec sigul-server ss -tn 2>/dev/null | grep ":44333" || echo "")

    if [[ -n "$server_connections" ]]; then
        success "✓ Server connected to bridge on port 44333"
    else
        warn "⚠ Server not yet connected to bridge (may still be initializing)"
    fi

    success "SSL topology verification completed"
}

# Step 4: Integration test execution
run_integration_tests() {
    log "Step 4: Integration Test Execution"
    log "Running integration tests against fresh infrastructure..."

    # Set client image environment
    export SIGUL_CLIENT_IMAGE="client-${PLATFORM}-image:test"

    verbose "Client image: $SIGUL_CLIENT_IMAGE"

    # Verify client image exists
    if ! docker image inspect "$SIGUL_CLIENT_IMAGE" >/dev/null 2>&1; then
        error "Client image not found: $SIGUL_CLIENT_IMAGE"
        error "Available client images:"
        docker images | grep client || echo "  (none found)"
        return 1
    fi

    # Run integration tests
    local test_script="${PROJECT_ROOT}/scripts/run-integration-tests.sh"

    if [[ ! -x "$test_script" ]]; then
        chmod +x "$test_script"
    fi

    local test_args=""
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        test_args="--verbose"
    fi

    log "Executing integration tests..."
    log "This will create a fresh client container and test end-to-end functionality"

    if timeout 180 "$test_script" $test_args; then
        success "✓ Integration tests completed successfully"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            error "✗ Integration tests timed out after 3 minutes"
        else
            error "✗ Integration tests failed (exit code: $exit_code)"
        fi

        # Show what to investigate next
        log "Troubleshooting guidance:"

        if grep -q "Unexpected EOF in NSPR" "${PROJECT_ROOT}/test-artifacts"/*.log 2>/dev/null; then
            error "  SSL errors detected - this should NOT happen with fresh containers"
            error "  This indicates a problem with the automatic certificate synchronization"
        elif grep -q "EOFError\|getpass" "${PROJECT_ROOT}/test-artifacts"/*.log 2>/dev/null; then
            warn "  Authentication/password errors detected"
            warn "  Focus on admin user creation and password handling"
        else
            warn "  Check test-artifacts/ directory for detailed logs"
        fi

        return 1
    fi
}

# Main execution function
main() {
    parse_args "$@"

    if [[ "$SHOW_HELP" == "true" ]]; then
        show_help
        exit 0
    fi

    detect_platform

    log "=== Sigul Correct Testing Process ==="
    log "Platform: $PLATFORM"
    log "Verbose mode: $VERBOSE_MODE"
    log "Project root: $PROJECT_ROOT"
    echo

    log "🎯 CRITICAL PRINCIPLE: Fresh containers only - never debug against persistent state"
    echo

    local start_time
    start_time=$(date +%s)

    # Execute the correct testing process
    if cleanup_environment && \
       deploy_fresh_infrastructure && \
       verify_ssl_topology && \
       run_integration_tests; then

        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        echo
        success "🎉 Correct testing process completed successfully in ${duration}s"
        success "This demonstrates the proper way to test Sigul locally"

        return 0
    else
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        echo
        error "❌ Testing process failed after ${duration}s"
        error "Review the specific step that failed and check test artifacts"

        return 1
    fi
}

# Execute main function
main "$@"
