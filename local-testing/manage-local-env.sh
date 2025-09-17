#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Local Sigul Environment Management Script
#
# This script provides easy management of the local Sigul testing environment
# including quick start/stop, log viewing, debugging, and cleanup operations.
#
# Usage:
#   ./local-testing/manage-local-env.sh <command> [options]
#
# Commands:
#   start       Start the Sigul stack
#   stop        Stop the Sigul stack
#   restart     Restart the Sigul stack
#   status      Show status of all services
#   logs        Show logs for all or specific service
#   shell       Open shell in a container
#   test        Run connectivity and health tests
#   clean       Clean up containers, volumes, and images
#   reset       Full reset (clean + rebuild + start)
#   monitor     Real-time monitoring of services
#   debug       Start debug session with comprehensive diagnostics

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.sigul.yml"
ENV_FILE="${SCRIPT_DIR}/.env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')] ${NC}$*"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN:${NC} $*"
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
    fi
}

# Show usage information
show_usage() {
    cat << EOF
Local Sigul Environment Management Script

USAGE:
    $0 <command> [options]

COMMANDS:
    start               Start the Sigul stack
    stop                Stop the Sigul stack
    restart             Restart the Sigul stack
    status              Show status of all services
    logs [service]      Show logs for all or specific service
    shell <service>     Open shell in a container
    test                Run connectivity and health tests
    clean               Clean up containers, volumes, and images
    reset               Full reset (clean + rebuild + start)
    monitor             Real-time monitoring of services
    debug               Start debug session with comprehensive diagnostics

SERVICE NAMES:
    server              Sigul server
    bridge              Sigul bridge
    client              Sigul client (for testing)
    network-tester      Network testing container
    health-monitor      Health monitoring container

OPTIONS:
    -f, --follow        Follow logs in real-time
    -v, --verbose       Verbose output
    -h, --help          Show this help

EXAMPLES:
    $0 start                    # Start the stack
    $0 logs server              # Show server logs
    $0 logs -f                  # Follow all logs
    $0 shell bridge             # Open shell in bridge container
    $0 test                     # Run health tests
    $0 debug                    # Start debug session
    $0 reset                    # Complete reset

EOF
}

# Start the Sigul stack
cmd_start() {
    log "Starting Sigul stack..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Check if environment file exists
    if [[ ! -f "$ENV_FILE" ]]; then
        warn "Environment file not found: $ENV_FILE"
        warn "Running initial deployment to create environment..."
        "${SCRIPT_DIR}/deploy-local-sigul-stack.sh" --build-local
        return $?
    fi

    load_environment

    # Start core services
    if $compose_cmd -f "$COMPOSE_FILE" up -d sigul-server sigul-bridge; then
        success "Sigul stack started"

        # Wait for services to initialize
        log "Waiting for services to initialize..."
        sleep 10

        # Show status
        cmd_status
    else
        error "Failed to start Sigul stack"
        return 1
    fi
}

# Stop the Sigul stack
cmd_stop() {
    log "Stopping Sigul stack..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    if $compose_cmd -f "$COMPOSE_FILE" down; then
        success "Sigul stack stopped"
    else
        error "Failed to stop Sigul stack"
        return 1
    fi
}

# Restart the Sigul stack
cmd_restart() {
    log "Restarting Sigul stack..."
    cmd_stop
    sleep 2
    cmd_start
}

# Show status of services
cmd_status() {
    log "Sigul stack status:"

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    echo ""
    echo "=== Container Status ==="
    $compose_cmd -f "$COMPOSE_FILE" ps --format table

    echo ""
    echo "=== Service Health ==="

    # Check if containers are running
    local containers=("sigul-server" "sigul-bridge")
    for container in "${containers[@]}"; do
        if $compose_cmd -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -q "$container"; then
            success "$container: Running"
        else
            error "$container: Not running"
        fi
    done

    echo ""
    echo "=== Network Connectivity ==="

    # Test bridge connectivity
    if $compose_cmd -f "$COMPOSE_FILE" exec -T sigul-bridge nc -z localhost 44334 2>/dev/null; then
        success "Bridge port 44334: Accessible"
    else
        warn "Bridge port 44334: Not accessible"
    fi

    echo ""
}

# Show logs
cmd_logs() {
    local service="${1:-}"
    local follow="${2:-false}"
    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    if [[ -n "$service" ]]; then
        log "Showing logs for $service..."
        if [[ "$follow" == "true" ]]; then
            $compose_cmd -f "$COMPOSE_FILE" logs -f "$service"
        else
            $compose_cmd -f "$COMPOSE_FILE" logs --tail=50 "$service"
        fi
    else
        log "Showing logs for all services..."
        if [[ "$follow" == "true" ]]; then
            $compose_cmd -f "$COMPOSE_FILE" logs -f
        else
            $compose_cmd -f "$COMPOSE_FILE" logs --tail=20
        fi
    fi
}

# Open shell in container
cmd_shell() {
    local service="${1:-}"
    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    if [[ -z "$service" ]]; then
        error "Service name required for shell command"
        error "Available services: server, bridge, client, network-tester"
        return 1
    fi

    # Map service names to container names
    case "$service" in
        server)
            service="sigul-server"
            ;;
        bridge)
            service="sigul-bridge"
            ;;
        client)
            service="sigul-client-test"
            ;;
        network-tester)
            service="network-tester"
            ;;
    esac

    log "Opening shell in $service..."

    # Check if container is running
    if ! $compose_cmd -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -q "$service"; then
        warn "Container $service is not running, starting it first..."
        $compose_cmd -f "$COMPOSE_FILE" up -d "$service"
        sleep 5
    fi

    # Determine shell type
    local shell_cmd="bash"
    if [[ "$service" == "network-tester" ]]; then
        shell_cmd="sh"
    fi

    $compose_cmd -f "$COMPOSE_FILE" exec "$service" "$shell_cmd"
}

# Run connectivity and health tests
cmd_test() {
    log "Running connectivity and health tests..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Start network tester if not running
    $compose_cmd -f "$COMPOSE_FILE" --profile testing up -d network-tester
    sleep 5

    echo ""
    echo "=== Network Connectivity Tests ==="

    # Test bridge connectivity from network tester
    if $compose_cmd -f "$COMPOSE_FILE" exec -T network-tester nc -z sigul-bridge 44334; then
        success "Bridge connectivity: OK"
    else
        error "Bridge connectivity: FAILED"
    fi

    # Test DNS resolution
    if $compose_cmd -f "$COMPOSE_FILE" exec -T network-tester nslookup sigul-bridge; then
        success "DNS resolution: OK"
    else
        error "DNS resolution: FAILED"
    fi

    echo ""
    echo "=== Process Health Tests ==="

    # Check server process
    if $compose_cmd -f "$COMPOSE_FILE" exec -T sigul-server pgrep -f "sigul_server"; then
        success "Server process: Running"
    else
        error "Server process: Not running"
    fi

    # Check bridge process
    if $compose_cmd -f "$COMPOSE_FILE" exec -T sigul-bridge pgrep -f "sigul_bridge"; then
        success "Bridge process: Running"
    else
        error "Bridge process: Not running"
    fi

    echo ""
    echo "=== Certificate Tests ==="

    # Check server certificates
    if $compose_cmd -f "$COMPOSE_FILE" exec -T sigul-server test -d /var/sigul/secrets/certificates; then
        success "Server certificates: Directory exists"
        local server_certs
        server_certs=$($compose_cmd -f "$COMPOSE_FILE" exec -T sigul-server ls /var/sigul/secrets/certificates/ 2>/dev/null | wc -l)
        info "Server certificates count: $server_certs"
    else
        error "Server certificates: Directory missing"
    fi

    # Check bridge certificates
    if $compose_cmd -f "$COMPOSE_FILE" exec -T sigul-bridge test -d /var/sigul/secrets/certificates; then
        success "Bridge certificates: Directory exists"
        local bridge_certs
        bridge_certs=$($compose_cmd -f "$COMPOSE_FILE" exec -T sigul-bridge ls /var/sigul/secrets/certificates/ 2>/dev/null | wc -l)
        info "Bridge certificates count: $bridge_certs"
    else
        error "Bridge certificates: Directory missing"
    fi

    echo ""
    success "Health tests completed"
}

# Clean up environment
cmd_clean() {
    log "Cleaning up Sigul environment..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Stop and remove containers
    log "Stopping containers..."
    $compose_cmd -f "$COMPOSE_FILE" down --remove-orphans --volumes

    # Remove images
    log "Removing Sigul images..."
    docker images --format "table {{.Repository}}:{{.Tag}}" | grep -E "(client|server|bridge).*-image:test" | while IFS= read -r line; do
        if [[ "$line" != "REPOSITORY:TAG" ]]; then
            local image
            image=$(echo "$line" | awk '{print $1":"$2}')
            docker rmi "$image" 2>/dev/null || true
        fi
    done

    # Clean up build cache
    log "Cleaning Docker build cache..."
    docker builder prune -f

    # Remove environment file
    if [[ -f "$ENV_FILE" ]]; then
        log "Removing environment file..."
        rm "$ENV_FILE"
    fi

    success "Environment cleaned"
}

# Full reset
cmd_reset() {
    log "Performing full reset..."

    cmd_clean

    log "Rebuilding and starting environment..."
    "${SCRIPT_DIR}/deploy-local-sigul-stack.sh" --build-local --clean
}

# Real-time monitoring
cmd_monitor() {
    log "Starting real-time monitoring (Press Ctrl+C to stop)..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Start monitoring containers
    $compose_cmd -f "$COMPOSE_FILE" --profile monitoring up -d health-monitor

    echo ""
    echo "=== Real-time Monitoring ==="
    echo "Following logs from health monitor..."
    echo ""

    # Follow health monitor logs
    $compose_cmd -f "$COMPOSE_FILE" logs -f health-monitor
}

# Debug session
cmd_debug() {
    log "Starting debug session..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Start all debug containers
    $compose_cmd -f "$COMPOSE_FILE" --profile debug --profile testing up -d

    echo ""
    echo "=== Debug Environment Started ==="
    echo ""
    echo "Available debug containers:"
    echo "  - debug-helper: General debugging tools"
    echo "  - network-tester: Network connectivity testing"
    echo ""
    echo "Debug commands:"
    echo "  View all logs:     $0 logs -f"
    echo "  Open debug shell:  $0 shell debug-helper"
    echo "  Network tests:     $0 test"
    echo "  Container status:  $0 status"
    echo ""

    # Show immediate status
    cmd_status

    echo ""
    echo "=== Recent Logs ==="
    cmd_logs "" false

    echo ""
    success "Debug session ready. Use the commands above to investigate issues."
}

# Main function
main() {
    local command="${1:-}"
    local follow=false
    local verbose=false

    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--follow)
                follow=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -*)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [[ -z "$command" ]]; then
                    command="$1"
                fi
                shift
                ;;
        esac
    done

    # Check prerequisites
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running"
        exit 1
    fi

    if [[ ! -f "$COMPOSE_FILE" ]]; then
        error "Docker Compose file not found: $COMPOSE_FILE"
        exit 1
    fi

    # Execute command
    case "$command" in
        start)
            cmd_start
            ;;
        stop)
            cmd_stop
            ;;
        restart)
            cmd_restart
            ;;
        status)
            cmd_status
            ;;
        logs)
            cmd_logs "${2:-}" "$follow"
            ;;
        shell)
            cmd_shell "${2:-}"
            ;;
        test)
            cmd_test
            ;;
        clean)
            cmd_clean
            ;;
        reset)
            cmd_reset
            ;;
        monitor)
            cmd_monitor
            ;;
        debug)
            cmd_debug
            ;;
        ""|help)
            show_usage
            ;;
        *)
            error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
