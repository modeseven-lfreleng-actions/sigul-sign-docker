#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Quick Test Script for Sigul Communication Issues
#
# This is a simplified version of the comprehensive debugging script
# designed for immediate testing and issue reproduction.
#
# Usage:
#   ./debug/quick-test.sh

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Simple logging functions
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')] INFO:${NC} $*"
}

success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] SUCCESS:${NC} $*"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN:${NC} $*"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $*" >&2
}

# Detect platform architecture
detect_platform() {
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64)
            echo "linux-amd64"
            ;;
        aarch64|arm64)
            echo "linux-arm64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

PLATFORM=$(detect_platform)

cleanup() {
    log "Cleaning up containers..."
    docker stop sigul-server sigul-bridge sigul-client-test 2>/dev/null || true
    docker rm sigul-server sigul-bridge sigul-client-test 2>/dev/null || true
}

# Trap cleanup on exit
trap cleanup EXIT

main() {
    echo -e "\n${BLUE}=== Sigul Quick Communication Test ===${NC}"
    log "Platform: $PLATFORM"
    log "Project: $PROJECT_ROOT"

    cd "$PROJECT_ROOT"

    # Clean up any existing containers
    cleanup

    # Build containers
    log "Building containers..."
    docker build -f Dockerfile.client -t "client-${PLATFORM}-image:test" . >/dev/null 2>&1
    docker build -f Dockerfile.server -t "server-${PLATFORM}-image:test" . >/dev/null 2>&1
    docker build -f Dockerfile.bridge -t "bridge-${PLATFORM}-image:test" . >/dev/null 2>&1
    success "Containers built"

    # Set environment variables
    export SIGUL_CLIENT_IMAGE="client-${PLATFORM}-image:test"
    export SIGUL_SERVER_IMAGE="server-${PLATFORM}-image:test"
    export SIGUL_BRIDGE_IMAGE="bridge-${PLATFORM}-image:test"

    # Deploy infrastructure
    log "Deploying Sigul infrastructure..."
    if ./scripts/deploy-sigul-infrastructure.sh --verbose >/dev/null 2>&1; then
        success "Infrastructure deployed"
    else
        error "Infrastructure deployment failed"
        echo "Check deployment logs:"
        echo "  docker logs sigul-server"
        echo "  docker logs sigul-bridge"
        exit 1
    fi

    # Wait for services
    log "Waiting for services to stabilize..."
    sleep 10

    # Check container status
    log "Container status:"
    docker ps --filter name=sigul --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

    # Test network connectivity
    log "Testing network connectivity..."

    if docker exec sigul-server ping -c 2 sigul-bridge >/dev/null 2>&1; then
        success "Server can ping bridge"
    else
        error "Server cannot ping bridge"
    fi

    if docker exec sigul-server nc -zv sigul-bridge 44334 2>/dev/null; then
        success "Bridge port 44334 is accessible from server"
    else
        warn "Bridge port 44334 is not accessible from server"
    fi

    # Start client container
    log "Starting client container..."
    SIGUL_NETWORK=$(docker network ls --filter name=sigul --format "{{.Name}}" | head -1)

    docker run -d \
        --name sigul-client-test \
        --network "$SIGUL_NETWORK" \
        "$SIGUL_CLIENT_IMAGE" \
        sleep infinity

    # Initialize client
    log "Initializing client..."
    if docker exec sigul-client-test /usr/local/bin/sigul-init.sh --role client >/dev/null 2>&1; then
        success "Client initialized"
    else
        error "Client initialization failed"
        echo "Check client logs: docker logs sigul-client-test"
        exit 1
    fi

    # Test sigul commands
    log "Testing sigul client commands..."

    # Load admin password
    if [[ -f "pki/admin_password" ]]; then
        ADMIN_PASSWORD=$(cat pki/admin_password)
        log "Admin password loaded"
    else
        error "Admin password file not found at pki/admin_password"
        exit 1
    fi

    # Test basic connectivity
    echo -e "\n${YELLOW}=== Testing Sigul Commands ===${NC}"

    # Test 1: List users
    echo -n "Testing list-users command... "
    if docker exec sigul-client-test sigul -c /var/sigul/config/client.conf list-users --password "$ADMIN_PASSWORD" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        echo "Command failed with exit code: $?"
        echo "Getting debug info..."

        echo -e "\n${YELLOW}Client container logs:${NC}"
        docker logs sigul-client-test --tail 10

        echo -e "\n${YELLOW}Bridge container logs:${NC}"
        docker logs sigul-bridge --tail 10

        echo -e "\n${YELLOW}Server container logs:${NC}"
        docker logs sigul-server --tail 10

        echo -e "\n${YELLOW}Network connectivity:${NC}"
        docker exec sigul-client-test ping -c 2 sigul-bridge || true
        docker exec sigul-client-test nc -zv sigul-bridge 44334 || true

        echo -e "\n${YELLOW}Client configuration:${NC}"
        docker exec sigul-client-test cat /var/sigul/config/client.conf

        echo -e "\n${YELLOW}Client NSS certificates:${NC}"
        docker exec sigul-client-test certutil -L -d /var/sigul/nss/client || true

        exit 1
    fi

    # Test 2: List keys
    echo -n "Testing list-keys command... "
    if docker exec sigul-client-test sigul -c /var/sigul/config/client.conf list-keys --password "$ADMIN_PASSWORD" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
    fi

    echo -e "\n${GREEN}=== Quick Test Complete ===${NC}"
    success "Basic sigul client communication is working!"

    log "To continue debugging, run:"
    log "  ./debug/reproduce-communication-issue.sh --full --verbose"

    log "To run integration tests manually:"
    log "  ./scripts/run-integration-tests.sh --verbose"

    log "To inspect containers:"
    log "  docker exec -it sigul-client-test bash"
    log "  docker exec -it sigul-server bash"
    log "  docker exec -it sigul-bridge bash"
}

main "$@"
