#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Simple Client Connection Test
#
# This script tests basic client-server connectivity through the bridge
# to isolate SSL issues from authentication issues.
#
# Usage:
#   ./debug/test_client_connection.sh [--verbose]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default options
VERBOSE_MODE=false

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

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose)
                VERBOSE_MODE=true
                shift
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Check if infrastructure is running
check_infrastructure() {
    log "Checking infrastructure status..."

    local missing_containers=()

    for container in sigul-server sigul-bridge; do
        if ! docker ps --filter "name=${container}" --filter "status=running" --format "{{.Names}}" | grep -q "^${container}$"; then
            missing_containers+=("${container}")
        else
            verbose "✓ Container ${container} is running"
        fi
    done

    if [[ ${#missing_containers[@]} -gt 0 ]]; then
        error "Required containers not running: ${missing_containers[*]}"
        error "Please deploy the infrastructure first:"
        error "  ./scripts/deploy-sigul-infrastructure.sh"
        return 1
    fi

    success "Infrastructure containers are running"
}

# Test SSL certificate status
test_ssl_certificates() {
    log "Testing SSL certificate configuration..."

    # Check bridge certificates
    local bridge_certs
    bridge_certs=$(docker exec sigul-bridge certutil -L -d /var/sigul/nss/bridge 2>/dev/null || echo "FAILED")

    if [[ "$bridge_certs" == "FAILED" ]]; then
        error "Cannot read bridge NSS database"
        return 1
    fi

    # Check for required certificates
    local has_bridge_cert
    has_bridge_cert=$(echo "$bridge_certs" | grep -c "sigul-bridge-cert" || echo "0")
    local has_server_cert
    has_server_cert=$(echo "$bridge_certs" | grep -c "sigul-server-cert" || echo "0")
    local has_ca_cert
    has_ca_cert=$(echo "$bridge_certs" | grep -c "sigul-ca-cert" || echo "0")

    verbose "Bridge certificate status:"
    verbose "  Bridge cert: $([[ $has_bridge_cert -gt 0 ]] && echo "✓" || echo "✗")"
    verbose "  Server cert: $([[ $has_server_cert -gt 0 ]] && echo "✓" || echo "✗")"
    verbose "  CA cert: $([[ $has_ca_cert -gt 0 ]] && echo "✓" || echo "✗")"

    if [[ $has_bridge_cert -gt 0 ]] && [[ $has_server_cert -gt 0 ]] && [[ $has_ca_cert -gt 0 ]]; then
        success "Bridge SSL certificates are properly configured"
    else
        warn "Bridge SSL certificates may be incomplete"
        warn "Run: ./debug/fix_backend_ssl_certs.sh"
    fi

    # Check server certificates
    local server_certs
    server_certs=$(docker exec sigul-server certutil -L -d /var/sigul/nss/server 2>/dev/null || echo "FAILED")

    if [[ "$server_certs" == "FAILED" ]]; then
        error "Cannot read server NSS database"
        return 1
    fi

    local server_has_server_cert
    server_has_server_cert=$(echo "$server_certs" | grep -c "sigul-server-cert" || echo "0")
    local server_has_bridge_cert
    server_has_bridge_cert=$(echo "$server_certs" | grep -c "sigul-bridge-cert" || echo "0")
    local server_has_ca_cert
    server_has_ca_cert=$(echo "$server_certs" | grep -c "sigul-ca-cert" || echo "0")

    verbose "Server certificate status:"
    verbose "  Server cert: $([[ $server_has_server_cert -gt 0 ]] && echo "✓" || echo "✗")"
    verbose "  Bridge cert: $([[ $server_has_bridge_cert -gt 0 ]] && echo "✓" || echo "✗")"
    verbose "  CA cert: $([[ $server_has_ca_cert -gt 0 ]] && echo "✓" || echo "✗")"

    if [[ $server_has_server_cert -gt 0 ]] && [[ $server_has_bridge_cert -gt 0 ]] && [[ $server_has_ca_cert -gt 0 ]]; then
        success "Server SSL certificates are properly configured"
    else
        warn "Server SSL certificates may be incomplete"
        warn "Run: ./debug/fix_backend_ssl_certs.sh"
    fi
}

# Test network connectivity
test_network_connectivity() {
    log "Testing network connectivity..."

    # Test bridge listening ports
    local bridge_ports
    bridge_ports=$(docker exec sigul-bridge ss -tlnp 2>/dev/null | grep -E "4433[34]" || echo "")

    if echo "$bridge_ports" | grep -q ":44334"; then
        success "✓ Bridge listening on port 44334 (client access)"
    else
        error "✗ Bridge not listening on port 44334"
        return 1
    fi

    if echo "$bridge_ports" | grep -q ":44333"; then
        success "✓ Bridge listening on port 44333 (server backend)"
    else
        error "✗ Bridge not listening on port 44333"
        return 1
    fi

    # Test server connection to bridge
    local server_connections
    server_connections=$(docker exec sigul-server ss -tn 2>/dev/null | grep ":44333" || echo "")

    if [[ -n "$server_connections" ]]; then
        success "✓ Server connected to bridge on port 44333"
        verbose "Connection: $server_connections"
    else
        warn "⚠ Server not connected to bridge on port 44333"
    fi
}

# Create a minimal client container for testing
create_test_client() {
    log "Creating minimal test client container..."

    # Check if client container already exists
    if docker ps -a --filter "name=sigul-client-test" --format "{{.Names}}" | grep -q "sigul-client-test"; then
        verbose "Removing existing test client container"
        docker rm -f sigul-client-test >/dev/null 2>&1 || true
    fi

    # Detect platform
    local arch
    arch=$(uname -m)
    local platform
    case "$arch" in
        x86_64|amd64)
            platform="linux-amd64"
            ;;
        aarch64|arm64)
            platform="linux-arm64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            return 1
            ;;
    esac

    local client_image="client-${platform}-image:test"

    # Verify client image exists
    if ! docker image inspect "$client_image" >/dev/null 2>&1; then
        error "Client image not found: $client_image"
        error "Available client images:"
        docker images | grep client || echo "  (none found)"
        return 1
    fi

    verbose "Using client image: $client_image"

    # Create test client container
    local container_id
    container_id=$(docker run -d \
        --name sigul-client-test \
        --network sigul-sign-docker_sigul-network \
        --env SIGUL_ROLE=client \
        --env SIGUL_BRIDGE_HOSTNAME=sigul-bridge \
        --env SIGUL_BRIDGE_PORT=44334 \
        --env SIGUL_DEBUG_MODE=true \
        "$client_image" sleep 300)

    if [[ -n "$container_id" ]]; then
        success "Test client container created: ${container_id:0:12}"

        # Wait for container to be ready
        local max_wait=30
        local count=0
        while [[ $count -lt $max_wait ]]; do
            if docker exec sigul-client-test test -f /var/sigul/nss/client/cert9.db 2>/dev/null; then
                success "Test client initialization completed"
                return 0
            fi
            sleep 1
            count=$((count + 1))
        done

        warn "Test client initialization timed out"
        return 1
    else
        error "Failed to create test client container"
        return 1
    fi
}

# Test basic client connection
test_client_connection() {
    log "Testing basic client-server connection..."

    # Import client certificate to bridge
    log "Importing client certificate to bridge..."

    # Export client certificate
    local client_cert_file="/tmp/test-client-cert.pem"
    if docker exec sigul-client-test certutil -L -d /var/sigul/nss/client -n sigul-client-cert -a > "$client_cert_file" 2>/dev/null; then
        verbose "✓ Exported client certificate"
    else
        error "Failed to export client certificate"
        return 1
    fi

    # Import to bridge
    if docker cp "$client_cert_file" sigul-bridge:/tmp/ && \
       docker exec sigul-bridge sh -c 'echo $(cat /var/sigul/secrets/bridge_nss_password) | certutil -A -d /var/sigul/nss/bridge -n sigul-client-cert -t "P,," -a -i /tmp/test-client-cert.pem -f /dev/stdin' 2>/dev/null; then
        success "✓ Client certificate imported to bridge"
    else
        warn "Client certificate import to bridge failed (may already exist)"
    fi

    # Clean up
    rm -f "$client_cert_file"
    docker exec sigul-bridge rm -f /tmp/test-client-cert.pem 2>/dev/null || true

    # Test simple connection (this will likely fail at auth, but should not fail at SSL)
    log "Testing client connection to bridge..."

    local connection_test
    connection_test=$(docker exec sigul-client-test timeout 10 sh -c '
        echo "test connection" | openssl s_client -connect sigul-bridge:44334 \
        -cert /var/sigul/secrets/certificates/client.crt \
        -key /var/sigul/secrets/certificates/client-key.pem \
        -CAfile /var/sigul/secrets/certificates/ca.crt \
        -verify_return_error -quiet 2>&1 | head -5
    ' 2>&1 || echo "CONNECTION_FAILED")

    if echo "$connection_test" | grep -q "verify return:1" || echo "$connection_test" | grep -q "Verify return code: 0"; then
        success "✓ SSL connection to bridge succeeded"
        verbose "Connection test output: $connection_test"
    elif echo "$connection_test" | grep -q "CONNECTION_FAILED"; then
        error "✗ Connection to bridge failed"
        verbose "Connection test output: $connection_test"
        return 1
    else
        warn "⚠ Connection test completed with unknown result"
        verbose "Connection test output: $connection_test"
    fi

    # Test sigul command (this will likely fail at auth level, which is expected)
    log "Testing sigul command execution..."

    local sigul_test
    sigul_test=$(docker exec sigul-client-test timeout 10 sigul -c /var/sigul/config/client.conf --help 2>&1 || echo "COMMAND_FAILED")

    if echo "$sigul_test" | grep -q "Usage:" || echo "$sigul_test" | grep -q "options:"; then
        success "✓ Sigul command executed successfully"
    elif echo "$sigul_test" | grep -q "COMMAND_FAILED"; then
        warn "⚠ Sigul command failed to execute"
        verbose "Sigul test output: $sigul_test"
    else
        warn "⚠ Sigul command completed with unknown result"
        verbose "Sigul test output: $sigul_test"
    fi
}

# Clean up test client
cleanup_test_client() {
    log "Cleaning up test client container..."

    if docker ps -a --filter "name=sigul-client-test" --format "{{.Names}}" | grep -q "sigul-client-test"; then
        docker rm -f sigul-client-test >/dev/null 2>&1 || true
        success "Test client container removed"
    fi
}

# Main execution function
main() {
    parse_args "$@"

    log "=== Sigul Client Connection Test ==="
    log "Verbose mode: $VERBOSE_MODE"
    log "Project root: $PROJECT_ROOT"
    echo

    local start_time
    start_time=$(date +%s)

    # Execute test sequence
    if check_infrastructure && \
       test_ssl_certificates && \
       test_network_connectivity && \
       create_test_client && \
       test_client_connection; then

        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        echo
        success "🎉 Client connection test completed successfully in ${duration}s"
        success "SSL layer appears to be working correctly"
        success "Authentication layer issues should be investigated next"

        cleanup_test_client
        return 0
    else
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        echo
        error "❌ Client connection test failed after ${duration}s"
        error "Check the specific failure above for next steps"

        cleanup_test_client
        return 1
    fi
}

# Handle script interruption
trap cleanup_test_client EXIT

# Execute main function
main "$@"
