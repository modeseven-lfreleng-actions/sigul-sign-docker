#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Comprehensive Local Debugging Script for Sigul Communication Issues
#
# This script reproduces the Sigul client-server communication issues seen
# in GitHub Actions CI/CD and provides detailed debugging information.
#
# Usage:
#   ./debug/reproduce-communication-issue.sh [OPTIONS]
#
# Options:
#   --quick             Quick test (build and basic communication test)
#   --full              Full integration test reproduction
#   --debug-certs       Focus on certificate/PKI debugging
#   --debug-network     Focus on network connectivity debugging
#   --clean-start       Clean all containers and volumes before starting
#   --verbose           Enable maximum verbosity
#   --help              Show this help message

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEBUG_DIR="${SCRIPT_DIR}"
LOG_DIR="${DEBUG_DIR}/logs-$(date +%Y%m%d-%H%M%S)"

# Test modes
QUICK_TEST=false
FULL_TEST=false
DEBUG_CERTS=false
DEBUG_NETWORK=false
CLEAN_START=false
VERBOSE_MODE=false
SHOW_HELP=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Enhanced logging functions
timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    echo -e "${BLUE}[$(timestamp)] INFO:${NC} $*" | tee -a "${LOG_DIR}/debug.log"
}

success() {
    echo -e "${GREEN}[$(timestamp)] SUCCESS:${NC} $*" | tee -a "${LOG_DIR}/debug.log"
}

warn() {
    echo -e "${YELLOW}[$(timestamp)] WARN:${NC} $*" | tee -a "${LOG_DIR}/debug.log"
}

error() {
    echo -e "${RED}[$(timestamp)] ERROR:${NC} $*" | tee -a "${LOG_DIR}/debug.log" >&2
}

debug() {
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        echo -e "${PURPLE}[$(timestamp)] DEBUG:${NC} $*" | tee -a "${LOG_DIR}/debug.log"
    fi
}

section() {
    echo -e "\n${CYAN}[$(timestamp)] === $* ===${NC}" | tee -a "${LOG_DIR}/debug.log"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_TEST=true
            shift
            ;;
        --full)
            FULL_TEST=true
            shift
            ;;
        --debug-certs)
            DEBUG_CERTS=true
            shift
            ;;
        --debug-network)
            DEBUG_NETWORK=true
            shift
            ;;
        --clean-start)
            CLEAN_START=true
            shift
            ;;
        --verbose)
            VERBOSE_MODE=true
            shift
            ;;
        --help)
            SHOW_HELP=true
            shift
            ;;
        *)
            error "Unknown option: $1"
            SHOW_HELP=true
            shift
            ;;
    esac
done

# Show help if requested or no options provided
if [[ "$SHOW_HELP" == "true" ]] || [[ "$QUICK_TEST" == "false" && "$FULL_TEST" == "false" && "$DEBUG_CERTS" == "false" && "$DEBUG_NETWORK" == "false" ]]; then
    cat << EOF
Comprehensive Local Debugging Script for Sigul Communication Issues

This script reproduces the Sigul client-server communication issues seen
in GitHub Actions CI/CD and provides detailed debugging information.

Usage:
    $0 [OPTIONS]

Options:
    --quick             Quick test (build and basic communication test)
    --full              Full integration test reproduction
    --debug-certs       Focus on certificate/PKI debugging
    --debug-network     Focus on network connectivity debugging
    --clean-start       Clean all containers and volumes before starting
    --verbose           Enable maximum verbosity
    --help              Show this help message

Examples:
    $0 --quick --verbose           # Quick test with detailed output
    $0 --full --clean-start        # Full reproduction from clean state
    $0 --debug-certs               # Focus on certificate issues
    $0 --debug-network             # Focus on network connectivity

The script will create detailed logs in: ${DEBUG_DIR}/logs-TIMESTAMP/

EOF
    exit 0
fi

# Create logging directory
mkdir -p "$LOG_DIR"

# Set default if no specific test mode chosen
if [[ "$QUICK_TEST" == "false" && "$FULL_TEST" == "false" && "$DEBUG_CERTS" == "false" && "$DEBUG_NETWORK" == "false" ]]; then
    QUICK_TEST=true
fi

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
debug "Detected platform: $PLATFORM"

# Clean up function
cleanup() {
    section "Cleanup"

    log "Stopping any running containers..."
    docker stop sigul-server sigul-bridge sigul-client-debug 2>/dev/null || true
    docker rm sigul-server sigul-bridge sigul-client-debug 2>/dev/null || true

    if [[ "$CLEAN_START" == "true" ]]; then
        log "Cleaning up volumes and networks..."
        docker volume rm $(docker volume ls -q --filter name=sigul) 2>/dev/null || true
        docker network rm $(docker network ls -q --filter name=sigul) 2>/dev/null || true
    fi

    success "Cleanup completed"
}

# Build containers if needed
build_containers() {
    section "Building Containers"

    log "Building Sigul containers for platform: $PLATFORM"

    # Build client
    log "Building client container..."
    docker build -f Dockerfile.client -t "client-${PLATFORM}-image:debug" . 2>&1 | tee "${LOG_DIR}/build-client.log"

    # Build server
    log "Building server container..."
    docker build -f Dockerfile.server -t "server-${PLATFORM}-image:debug" . 2>&1 | tee "${LOG_DIR}/build-server.log"

    # Build bridge
    log "Building bridge container..."
    docker build -f Dockerfile.bridge -t "bridge-${PLATFORM}-image:debug" . 2>&1 | tee "${LOG_DIR}/build-bridge.log"

    success "Container builds completed"
}

# Deploy infrastructure
deploy_infrastructure() {
    section "Deploying Infrastructure"

    cd "$PROJECT_ROOT"

    # Set environment variables
    export SIGUL_CLIENT_IMAGE="client-${PLATFORM}-image:debug"
    export SIGUL_SERVER_IMAGE="server-${PLATFORM}-image:debug"
    export SIGUL_BRIDGE_IMAGE="bridge-${PLATFORM}-image:debug"

    log "Deploying Sigul infrastructure..."
    debug "Client image: $SIGUL_CLIENT_IMAGE"
    debug "Server image: $SIGUL_SERVER_IMAGE"
    debug "Bridge image: $SIGUL_BRIDGE_IMAGE"

    # Use the deployment script
    ./scripts/deploy-sigul-infrastructure.sh --verbose 2>&1 | tee "${LOG_DIR}/deploy.log"

    success "Infrastructure deployment completed"
}

# Debug certificates and PKI
debug_certificates() {
    section "Certificate and PKI Debugging"

    log "Analyzing certificate setup in containers..."

    for container in sigul-server sigul-bridge; do
        if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
            log "Debugging certificates in container: $container"

            # Check certificate files
            echo "=== Certificate files in $container ===" >> "${LOG_DIR}/certs-${container}.log"
            docker exec "$container" find /var/sigul/secrets/certificates -type f -exec ls -la {} \; 2>&1 >> "${LOG_DIR}/certs-${container}.log" || true

            # Check NSS database
            echo "=== NSS database in $container ===" >> "${LOG_DIR}/certs-${container}.log"
            docker exec "$container" find /var/sigul/nss -type f -exec ls -la {} \; 2>&1 >> "${LOG_DIR}/certs-${container}.log" || true

            # Check certificate validity
            echo "=== Certificate validation in $container ===" >> "${LOG_DIR}/certs-${container}.log"
            docker exec "$container" find /var/sigul/secrets/certificates -name "*.crt" -exec openssl x509 -in {} -text -noout \; 2>&1 >> "${LOG_DIR}/certs-${container}.log" || true

            # Check NSS certificate listing
            echo "=== NSS certificate listing in $container ===" >> "${LOG_DIR}/certs-${container}.log"
            docker exec "$container" sh -c 'if [ -f /var/sigul/secrets/nss-passwords/server_nss_password ]; then certutil -L -d /var/sigul/nss/server; elif [ -f /var/sigul/secrets/nss-passwords/bridge_nss_password ]; then certutil -L -d /var/sigul/nss/bridge; fi' 2>&1 >> "${LOG_DIR}/certs-${container}.log" || true

            log "Certificate analysis for $container saved to: ${LOG_DIR}/certs-${container}.log"
        else
            warn "Container $container is not running - skipping certificate debug"
        fi
    done
}

# Debug network connectivity
debug_network() {
    section "Network Connectivity Debugging"

    log "Analyzing network connectivity between containers..."

    # Get network information
    log "Docker network information:"
    docker network ls | tee "${LOG_DIR}/networks.log"

    # Get detailed network info for sigul network
    SIGUL_NETWORK=$(docker network ls --filter name=sigul --format "{{.Name}}" | head -1)
    if [[ -n "$SIGUL_NETWORK" ]]; then
        log "Detailed network info for: $SIGUL_NETWORK"
        docker network inspect "$SIGUL_NETWORK" > "${LOG_DIR}/network-${SIGUL_NETWORK}.json"
        debug "Network details saved to: ${LOG_DIR}/network-${SIGUL_NETWORK}.json"
    fi

    # Test connectivity between containers
    if docker ps --filter "name=sigul-server" --filter "status=running" | grep -q "sigul-server"; then
        log "Testing network connectivity from server container..."

        # Get server container IP
        SERVER_IP=$(docker inspect sigul-server --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
        log "Server container IP: $SERVER_IP"

        # Test from server to bridge
        if docker ps --filter "name=sigul-bridge" --filter "status=running" | grep -q "sigul-bridge"; then
            BRIDGE_IP=$(docker inspect sigul-bridge --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
            log "Bridge container IP: $BRIDGE_IP"

            log "Testing connectivity from server to bridge..."
            docker exec sigul-server ping -c 3 "$BRIDGE_IP" 2>&1 | tee "${LOG_DIR}/ping-server-to-bridge.log" || warn "Ping from server to bridge failed"

            log "Testing port connectivity from server to bridge port 44334..."
            docker exec sigul-server timeout 10 nc -zv "$BRIDGE_IP" 44334 2>&1 | tee "${LOG_DIR}/netcat-server-to-bridge.log" || warn "Port 44334 not accessible from server"
        fi
    fi
}

# Test client communication
test_client_communication() {
    section "Client Communication Testing"

    log "Starting client container for communication testing..."

    # Start client container with debugging
    docker run -d \
        --name sigul-client-debug \
        --network "$(docker network ls --filter name=sigul --format '{{.Name}}' | head -1)" \
        -e SIGUL_DEBUG=1 \
        -v "$(pwd)/test-workspace:/workspace" \
        "$SIGUL_CLIENT_IMAGE" \
        sleep infinity

    log "Initializing client container..."
    docker exec sigul-client-debug /usr/local/bin/sigul-init.sh --role client --verbose 2>&1 | tee "${LOG_DIR}/client-init.log"

    log "Testing basic sigul client connectivity..."

    # Load admin password
    if [[ -f "pki/admin_password" ]]; then
        ADMIN_PASSWORD=$(cat pki/admin_password)
        debug "Loaded admin password"
    else
        error "Admin password file not found"
        return 1
    fi

    # Test basic commands
    local test_commands=(
        "sigul -c /var/sigul/config/client.conf list-users --password $ADMIN_PASSWORD"
        "sigul -c /var/sigul/config/client.conf list-keys --password $ADMIN_PASSWORD"
    )

    for cmd in "${test_commands[@]}"; do
        log "Testing command: $cmd"

        if docker exec sigul-client-debug $cmd 2>&1 | tee "${LOG_DIR}/client-cmd-$(echo "$cmd" | sed 's/[^a-zA-Z0-9]/_/g').log"; then
            success "Command succeeded: $cmd"
        else
            error "Command failed: $cmd"

            # Get additional debugging info
            log "Getting client container logs for debugging..."
            docker logs sigul-client-debug --tail 50 > "${LOG_DIR}/client-debug-logs.log"

            log "Checking client configuration..."
            docker exec sigul-client-debug cat /var/sigul/config/client.conf > "${LOG_DIR}/client-config.log"

            log "Checking client NSS database..."
            docker exec sigul-client-debug certutil -L -d /var/sigul/nss/client > "${LOG_DIR}/client-nss-certs.log" 2>&1 || true
        fi
    done
}

# Collect comprehensive diagnostics
collect_diagnostics() {
    section "Collecting Comprehensive Diagnostics"

    log "Gathering system and container diagnostics..."

    # System info
    uname -a > "${LOG_DIR}/system-info.log"
    docker version > "${LOG_DIR}/docker-version.log" 2>&1
    docker info > "${LOG_DIR}/docker-info.log" 2>&1

    # Container status
    docker ps -a > "${LOG_DIR}/containers.log"
    docker images > "${LOG_DIR}/images.log"
    docker volume ls > "${LOG_DIR}/volumes.log"
    docker network ls > "${LOG_DIR}/networks.log"

    # Container logs
    for container in sigul-server sigul-bridge sigul-client-debug; do
        if docker ps -a --filter "name=$container" | grep -q "$container"; then
            log "Collecting logs for container: $container"
            docker logs "$container" > "${LOG_DIR}/logs-${container}.log" 2>&1
            docker inspect "$container" > "${LOG_DIR}/inspect-${container}.json"
        fi
    done

    # Configuration files
    if docker ps --filter "name=sigul-server" --filter "status=running" | grep -q "sigul-server"; then
        docker exec sigul-server find /var/sigul/config -type f -exec cat {} \; > "${LOG_DIR}/server-configs.log" 2>&1 || true
    fi

    if docker ps --filter "name=sigul-bridge" --filter "status=running" | grep -q "sigul-bridge"; then
        docker exec sigul-bridge find /var/sigul/config -type f -exec cat {} \; > "${LOG_DIR}/bridge-configs.log" 2>&1 || true
    fi

    success "Diagnostics collected in: $LOG_DIR"
}

# Generate summary report
generate_report() {
    section "Generating Summary Report"

    local report_file="${LOG_DIR}/SUMMARY_REPORT.md"

    cat > "$report_file" << EOF
# Sigul Communication Issue Debug Report

**Generated:** $(date)
**Platform:** $PLATFORM
**Project Root:** $PROJECT_ROOT
**Log Directory:** $LOG_DIR

## Test Configuration

- Quick Test: $QUICK_TEST
- Full Test: $FULL_TEST
- Debug Certificates: $DEBUG_CERTS
- Debug Network: $DEBUG_NETWORK
- Clean Start: $CLEAN_START
- Verbose Mode: $VERBOSE_MODE

## Key Findings

### Container Status
\`\`\`
$(docker ps -a --filter name=sigul 2>/dev/null || echo "No sigul containers found")
\`\`\`

### Network Status
\`\`\`
$(docker network ls --filter name=sigul 2>/dev/null || echo "No sigul networks found")
\`\`\`

### Volume Status
\`\`\`
$(docker volume ls --filter name=sigul 2>/dev/null || echo "No sigul volumes found")
\`\`\`

## Log Files

The following log files were generated during this debug session:

EOF

    # List all log files
    find "$LOG_DIR" -name "*.log" -o -name "*.json" | sort | while read -r logfile; do
        echo "- \`$(basename "$logfile")\`: $(wc -l < "$logfile") lines" >> "$report_file"
    done

    cat >> "$report_file" << EOF

## Next Steps

1. **Review container logs** - Check logs-*.log files for error messages
2. **Verify certificate setup** - Check certs-*.log files for certificate issues
3. **Test network connectivity** - Review ping-*.log and netcat-*.log files
4. **Check configurations** - Review *-configs.log files for configuration problems

## Quick Commands for Further Investigation

\`\`\`bash
# View container logs
docker logs sigul-server
docker logs sigul-bridge

# Check container networking
docker network inspect \$(docker network ls --filter name=sigul --format "{{.Name}}" | head -1)

# Test manual sigul commands
docker exec sigul-client-debug sigul -c /var/sigul/config/client.conf list-users --password \$(cat pki/admin_password)
\`\`\`

EOF

    success "Summary report generated: $report_file"
    log "Review the report for key findings and next steps"
}

# Main execution
main() {
    section "Sigul Communication Issue Debugging"

    log "Starting comprehensive Sigul debugging session"
    log "Platform: $PLATFORM"
    log "Log directory: $LOG_DIR"

    # Cleanup if requested
    if [[ "$CLEAN_START" == "true" ]]; then
        cleanup
    fi

    # Build containers
    build_containers

    # Deploy infrastructure
    deploy_infrastructure

    # Wait for services to stabilize
    log "Waiting for services to stabilize..."
    sleep 10

    # Run debugging based on selected options
    if [[ "$DEBUG_CERTS" == "true" ]] || [[ "$FULL_TEST" == "true" ]]; then
        debug_certificates
    fi

    if [[ "$DEBUG_NETWORK" == "true" ]] || [[ "$FULL_TEST" == "true" ]]; then
        debug_network
    fi

    if [[ "$QUICK_TEST" == "true" ]] || [[ "$FULL_TEST" == "true" ]]; then
        test_client_communication
    fi

    # Always collect diagnostics
    collect_diagnostics

    # Generate final report
    generate_report

    section "Debug Session Complete"
    success "All debugging information collected in: $LOG_DIR"
    success "Review the SUMMARY_REPORT.md file for key findings"

    log "To reproduce the exact GitHub Actions environment:"
    log "1. Review the collected logs for communication errors"
    log "2. Check certificate validity and NSS database setup"
    log "3. Verify network connectivity between containers"
    log "4. Test sigul client commands manually"

    warn "Remember to run 'cleanup' when finished with debugging"
}

# Set up signal handlers
trap cleanup EXIT

# Run main function
main "$@"
