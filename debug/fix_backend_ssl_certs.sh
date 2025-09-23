#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Sigul Backend SSL Certificate Exchange Fix
#
# This script fixes the missing certificate exchange between server and bridge
# containers by manually importing the required peer certificates into their
# respective NSS databases.
#
# Usage:
#   ./debug/fix_backend_ssl_certs.sh [--verbose] [--dry-run]
#
# Options:
#   --verbose       Enable verbose output
#   --dry-run       Show what would be done without executing
#   --help          Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default options
VERBOSE_MODE=false
DRY_RUN=false
SHOW_HELP=false

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
Sigul Backend SSL Certificate Exchange Fix

USAGE:
    ./debug/fix_backend_ssl_certs.sh [OPTIONS]

OPTIONS:
    --verbose       Enable verbose output
    --dry-run       Show what would be done without executing
    --help          Show this help message

DESCRIPTION:
    This script fixes the missing SSL certificate exchange between server and
    bridge containers. It exports certificates from each container and imports
    them into the peer's NSS database with the correct trust attributes.

    The script performs these operations:
    1. Export server certificate from server container
    2. Import server certificate into bridge NSS database (peer trust)
    3. Export bridge certificate from bridge container
    4. Import bridge certificate into server NSS database (peer trust)

    This enables mutual TLS authentication for the backend connection between
    server and bridge on port 44333.

REQUIREMENTS:
    - sigul-server and sigul-bridge containers must be running
    - NSS databases must be initialized in both containers
    - Both containers must have their own certificates generated

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
            --dry-run)
                DRY_RUN=true
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

# Check if containers are running
check_containers() {
    log "Checking container status..."

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

    success "All required containers are running"
}

# Check NSS database status
check_nss_databases() {
    log "Checking NSS database status..."

    local server_certs
    local bridge_certs

    # Check server NSS database
    server_certs=$(docker exec sigul-server certutil -L -d /var/sigul/nss/server 2>/dev/null || echo "FAILED")
    if [[ "$server_certs" == "FAILED" ]]; then
        error "Cannot read server NSS database"
        return 1
    fi

    verbose "Server NSS database contents:"
    echo "$server_certs" | while IFS= read -r line; do
        verbose "  $line"
    done

    # Check bridge NSS database
    bridge_certs=$(docker exec sigul-bridge certutil -L -d /var/sigul/nss/bridge 2>/dev/null || echo "FAILED")
    if [[ "$bridge_certs" == "FAILED" ]]; then
        error "Cannot read bridge NSS database"
        return 1
    fi

    verbose "Bridge NSS database contents:"
    echo "$bridge_certs" | while IFS= read -r line; do
        verbose "  $line"
    done

    # Check for required own certificates
    if ! echo "$server_certs" | grep -q "sigul-server-cert"; then
        error "Server missing its own certificate (sigul-server-cert)"
        return 1
    fi

    if ! echo "$bridge_certs" | grep -q "sigul-bridge-cert"; then
        error "Bridge missing its own certificate (sigul-bridge-cert)"
        return 1
    fi

    # Check if peer certificates already exist
    local server_has_bridge
    server_has_bridge=$(echo "$server_certs" | grep -c "sigul-bridge-cert" || echo "0")
    local bridge_has_server
    bridge_has_server=$(echo "$bridge_certs" | grep -c "sigul-server-cert" || echo "0")

    if [[ "$server_has_bridge" -gt 0 ]] && [[ "$bridge_has_server" -gt 0 ]]; then
        success "SSL certificate exchange already completed - no action needed"
        return 2
    fi

    verbose "Certificate exchange status:"
    verbose "  Server has bridge cert: $([[ $server_has_bridge -gt 0 ]] && echo "YES" || echo "NO")"
    verbose "  Bridge has server cert: $([[ $bridge_has_server -gt 0 ]] && echo "YES" || echo "NO")"

    success "NSS databases ready for certificate exchange"
}

# Export certificate from container
export_certificate() {
    local container="$1"
    local cert_nickname="$2"
    local output_file="$3"

    verbose "Exporting certificate $cert_nickname from $container..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Would export $cert_nickname from $container to $output_file"
        return 0
    fi

    # Export certificate in PEM format
    if docker exec "$container" certutil -L -d "/var/sigul/nss/${container#sigul-}" -n "$cert_nickname" -a > "$output_file" 2>/dev/null; then
        verbose "✓ Exported $cert_nickname from $container ($(wc -c < "$output_file") bytes)"
        return 0
    else
        error "Failed to export $cert_nickname from $container"
        return 1
    fi
}

# Import certificate to container
import_certificate() {
    local container="$1"
    local cert_file="$2"
    local cert_nickname="$3"
    local trust_flags="$4"

    verbose "Importing certificate $cert_nickname to $container with trust $trust_flags..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Would import $cert_file to $container as $cert_nickname with trust $trust_flags"
        return 0
    fi

    # Copy certificate file to container
    if ! docker cp "$cert_file" "$container:/tmp/"; then
        error "Failed to copy $cert_file to $container"
        return 1
    fi

    local cert_basename
    cert_basename=$(basename "$cert_file")

    # Get NSS password for the container
    local nss_password
    if ! nss_password=$(docker exec "$container" cat "/var/sigul/secrets/${container#sigul-}_nss_password" 2>/dev/null); then
        error "Failed to read NSS password from $container"
        return 1
    fi

    # Import certificate with proper trust flags
    if echo "$nss_password" | docker exec -i "$container" certutil -A -d "/var/sigul/nss/${container#sigul-}" \
        -n "$cert_nickname" \
        -t "$trust_flags" \
        -a -i "/tmp/$cert_basename" \
        -f /dev/stdin 2>/dev/null; then

        verbose "✓ Imported $cert_nickname to $container"

        # Clean up temporary file
        docker exec "$container" rm -f "/tmp/$cert_basename" 2>/dev/null || true

        return 0
    else
        error "Failed to import $cert_nickname to $container"
        # Clean up temporary file
        docker exec "$container" rm -f "/tmp/$cert_basename" 2>/dev/null || true
        return 1
    fi
}

# Perform certificate exchange
perform_certificate_exchange() {
    log "Performing SSL certificate exchange..."

    local temp_dir="/tmp/sigul-cert-exchange-$$"
    mkdir -p "$temp_dir"

    local server_cert_file="$temp_dir/server.crt"
    local bridge_cert_file="$temp_dir/bridge.crt"

    # Export server certificate
    if ! export_certificate "sigul-server" "sigul-server-cert" "$server_cert_file"; then
        error "Failed to export server certificate"
        rm -rf "$temp_dir"
        return 1
    fi

    # Export bridge certificate
    if ! export_certificate "sigul-bridge" "sigul-bridge-cert" "$bridge_cert_file"; then
        error "Failed to export bridge certificate"
        rm -rf "$temp_dir"
        return 1
    fi

    # Import server certificate to bridge (peer trust for SSL authentication)
    if ! import_certificate "sigul-bridge" "$server_cert_file" "sigul-server-cert" "P,,"; then
        error "Failed to import server certificate to bridge"
        rm -rf "$temp_dir"
        return 1
    fi

    # Import bridge certificate to server (peer trust for SSL authentication)
    if ! import_certificate "sigul-server" "$bridge_cert_file" "sigul-bridge-cert" "P,,"; then
        error "Failed to import bridge certificate to server"
        rm -rf "$temp_dir"
        return 1
    fi

    # Clean up temporary files
    rm -rf "$temp_dir"

    success "SSL certificate exchange completed successfully"
}

# Verify certificate exchange
verify_certificate_exchange() {
    log "Verifying SSL certificate exchange..."

    local server_certs
    local bridge_certs

    # Re-read NSS databases
    server_certs=$(docker exec sigul-server certutil -L -d /var/sigul/nss/server 2>/dev/null)
    bridge_certs=$(docker exec sigul-bridge certutil -L -d /var/sigul/nss/bridge 2>/dev/null)

    # Check that peer certificates now exist
    local server_has_bridge
    server_has_bridge=$(echo "$server_certs" | grep -c "sigul-bridge-cert" || echo "0")
    local bridge_has_server
    bridge_has_server=$(echo "$bridge_certs" | grep -c "sigul-server-cert" || echo "0")

    if [[ "$server_has_bridge" -gt 0 ]] && [[ "$bridge_has_server" -gt 0 ]]; then
        success "✓ Certificate exchange verification passed"

        log "Updated NSS database contents:"
        log "Server NSS Database:"
        echo "$server_certs" | while IFS= read -r line; do
            log "  $line"
        done

        log "Bridge NSS Database:"
        echo "$bridge_certs" | while IFS= read -r line; do
            log "  $line"
        done

        return 0
    else
        error "✗ Certificate exchange verification failed"
        error "  Server has bridge cert: $([[ $server_has_bridge -gt 0 ]] && echo "YES" || echo "NO")"
        error "  Bridge has server cert: $([[ $bridge_has_server -gt 0 ]] && echo "YES" || echo "NO")"
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

    log "=== Sigul Backend SSL Certificate Exchange Fix ==="
    log "Verbose mode: $VERBOSE_MODE"
    log "Dry run mode: $DRY_RUN"
    log "Project root: $PROJECT_ROOT"
    echo

    local start_time
    start_time=$(date +%s)

    # Execute certificate exchange process
    if check_containers && check_nss_databases; then
        local nss_check_result=$?

        if [[ $nss_check_result -eq 2 ]]; then
            # Certificates already exchanged
            return 0
        fi

        if perform_certificate_exchange && verify_certificate_exchange; then
            local end_time
            end_time=$(date +%s)
            local duration=$((end_time - start_time))

            echo
            success "🎉 SSL certificate exchange completed successfully in ${duration}s"
            success "Backend SSL connections (server ↔ bridge) should now work"

            return 0
        else
            local end_time
            end_time=$(date +%s)
            local duration=$((end_time - start_time))

            echo
            error "❌ SSL certificate exchange failed after ${duration}s"
            error "Manual intervention may be required"

            return 1
        fi
    else
        error "Pre-flight checks failed - cannot proceed with certificate exchange"
        return 1
    fi
}

# Execute main function
main "$@"
