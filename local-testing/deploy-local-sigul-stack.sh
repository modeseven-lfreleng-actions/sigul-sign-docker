#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Local Sigul Stack Deployment Script for macOS ARM64
#
# This script deploys a complete Sigul infrastructure locally using Docker
# to test the certificate setup, deployment scripts, and integration tests
# before deploying to GitHub CI environment.
#
# Usage:
#   ./local-testing/deploy-local-sigul-stack.sh [OPTIONS]
#
# Options:
#   --build-local       Build containers locally instead of downloading artifacts
#   --download-artifacts Download pre-built containers from GitHub workflow
#   --run-id ID         Specific GitHub workflow run ID to download from
#   --verbose           Enable verbose output
#   --debug             Enable debug mode with detailed diagnostics
#   --clean             Clean up existing containers and volumes before deployment
#   --skip-tests        Skip integration tests after deployment
#   --help              Show this help message

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.sigul.yml"
TEST_WORKSPACE="${SCRIPT_DIR}/test-workspace"

# Default options
BUILD_LOCAL=false
DOWNLOAD_ARTIFACTS=false
WORKFLOW_RUN_ID="${WORKFLOW_RUN_ID:-17629893204}"
VERBOSE_MODE=false
DEBUG_MODE=false
CLEAN_DEPLOYMENT=false
SKIP_TESTS=false
SHOW_HELP=false

# Container configuration for ARM64
PLATFORM="linux/arm64"
PLATFORM_ID="linux-arm64"
DOCKER_PLATFORM="linux/arm64"

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
        echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')] VERBOSE:${NC} $*"
    fi
}

debug() {
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        echo -e "${PURPLE}[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG:${NC} $*"
    fi
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

# Help function
show_help() {
    cat << EOF
Local Sigul Stack Deployment Script for macOS ARM64

This script deploys a complete Sigul infrastructure locally using Docker
to test certificate setup, deployment scripts, and integration tests.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --build-local           Build containers locally instead of downloading
    --download-artifacts    Download pre-built containers from GitHub workflow
    --run-id ID            Specific GitHub workflow run ID (default: $WORKFLOW_RUN_ID)
    --verbose              Enable verbose output
    --debug                Enable debug mode with detailed diagnostics
    --clean                Clean up existing containers and volumes before deployment
    --skip-tests           Skip integration tests after deployment
    --help                 Show this help message

EXAMPLES:
    # Build and deploy locally
    $0 --build-local --verbose

    # Download artifacts and deploy
    $0 --download-artifacts --run-id 17629893204

    # Clean deployment with debug output
    $0 --clean --debug --build-local

    # Quick deployment without tests
    $0 --build-local --skip-tests

ENVIRONMENT VARIABLES:
    WORKFLOW_RUN_ID        GitHub workflow run ID for artifact download
    DEBUG                  Enable debug mode (true/false)
    DOCKER_BUILDKIT        Enable Docker BuildKit (default: 1)

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build-local)
                BUILD_LOCAL=true
                shift
                ;;
            --download-artifacts)
                DOWNLOAD_ARTIFACTS=true
                shift
                ;;
            --run-id)
                if [[ -z "${2:-}" ]]; then
                    error "Workflow run ID required"
                    exit 1
                fi
                WORKFLOW_RUN_ID="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE_MODE=true
                shift
                ;;
            --debug)
                DEBUG_MODE=true
                VERBOSE_MODE=true
                shift
                ;;
            --clean)
                CLEAN_DEPLOYMENT=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --help)
                SHOW_HELP=true
                shift
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ "$SHOW_HELP" == "true" ]]; then
        show_help
        exit 0
    fi

    # Validate options
    if [[ "$BUILD_LOCAL" == "true" && "$DOWNLOAD_ARTIFACTS" == "true" ]]; then
        error "Cannot specify both --build-local and --download-artifacts"
        exit 1
    fi

    if [[ "$BUILD_LOCAL" == "false" && "$DOWNLOAD_ARTIFACTS" == "false" ]]; then
        log "No build option specified, defaulting to --build-local"
        BUILD_LOCAL=true
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites for macOS ARM64 deployment..."

    # Check macOS architecture
    local arch
    arch=$(uname -m)
    if [[ "$arch" != "arm64" ]]; then
        warn "Expected ARM64 architecture, found: $arch"
        warn "This script is optimized for macOS ARM64, continuing anyway..."
    fi

    # Check Docker
    if ! command -v docker >/dev/null 2>&1; then
        error "Docker is required but not installed"
        exit 1
    fi

    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running"
        exit 1
    fi

    # Check Docker Compose
    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)
    if ! $compose_cmd version >/dev/null 2>&1; then
        error "Docker Compose is required but not available"
        exit 1
    fi

    # Check if we're in the right directory
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        error "Docker Compose file not found: $COMPOSE_FILE"
        error "Please run this script from the project root or ensure the compose file exists"
        exit 1
    fi

    success "Prerequisites check passed"
}

# Clean up existing deployment
cleanup_deployment() {
    if [[ "$CLEAN_DEPLOYMENT" == "true" ]]; then
        log "Cleaning up existing Sigul deployment..."

        local compose_cmd
        compose_cmd=$(get_docker_compose_cmd)

        # Stop and remove containers
        verbose "Stopping containers..."
        $compose_cmd -f "$COMPOSE_FILE" down --remove-orphans --volumes || true

        # Remove images
        verbose "Removing existing Sigul images..."
        docker images --format "table {{.Repository}}:{{.Tag}}" | grep -E "(sigul|client|server|bridge)" | while read -r image; do
            if [[ "$image" != "REPOSITORY:TAG" ]]; then
                docker rmi "$image" 2>/dev/null || true
            fi
        done

        # Clean up build cache
        verbose "Cleaning Docker build cache..."
        docker builder prune -f || true

        success "Cleanup completed"
    fi
}

# Download artifacts from GitHub workflow
download_artifacts() {
    if [[ "$DOWNLOAD_ARTIFACTS" == "true" ]]; then
        log "Downloading pre-built containers from GitHub workflow run: $WORKFLOW_RUN_ID"

        local artifacts_dir="${SCRIPT_DIR}/artifacts"
        mkdir -p "$artifacts_dir"

        warn "Artifact download not yet implemented"
        warn "GitHub CLI or API integration needed for artifact download"
        warn "For now, please use --build-local option"

        # TODO: Implement GitHub artifact download
        # This would require:
        # 1. GitHub CLI (gh) authentication
        # 2. Download specific artifacts from the workflow run
        # 3. Extract and load Docker images

        error "Artifact download not implemented, please use --build-local"
        exit 1
    fi
}

# Build containers locally
build_containers() {
    if [[ "$BUILD_LOCAL" == "true" ]]; then
        log "Building Sigul containers locally for ARM64..."

        cd "$PROJECT_ROOT"

        # Enable BuildKit for better caching and multi-platform builds
        export DOCKER_BUILDKIT=1
        export BUILDKIT_PROGRESS=plain

        local components=("client" "server" "bridge")

        for component in "${components[@]}"; do
            log "Building ${component} container for ARM64..."

            local dockerfile="Dockerfile.${component}"
            local image_tag="${component}-${PLATFORM_ID}-image:test"

            verbose "Building: docker build --platform ${PLATFORM} -f ${dockerfile} -t ${image_tag} ."

            if docker build \
                --platform "$PLATFORM" \
                -f "$dockerfile" \
                -t "$image_tag" \
                .; then
                success "Built ${component} container: ${image_tag}"
            else
                error "Failed to build ${component} container"
                exit 1
            fi
        done

        success "All containers built successfully"
    fi
}

# Setup test workspace
setup_test_workspace() {
    log "Setting up test workspace..."

    mkdir -p "$TEST_WORKSPACE"

    # Create test files for signing
    cat > "$TEST_WORKSPACE/test-file.txt" << EOF
This is a test file for Sigul signing verification.
Created: $(date)
Platform: macOS ARM64
Deployment: Local Testing
EOF

    # Set proper permissions
    chmod 644 "$TEST_WORKSPACE/test-file.txt"

    verbose "Test workspace created at: $TEST_WORKSPACE"
    success "Test workspace setup completed"
}

# Generate environment file for Docker Compose
generate_env_file() {
    log "Generating environment configuration..."

    local env_file="${SCRIPT_DIR}/.env"
    # Generate proper random passwords like CI does
    local ephemeral_nss_password
    local ephemeral_admin_password
    ephemeral_nss_password=$(head -c 18 /dev/urandom | base64)
    ephemeral_admin_password=$(head -c 12 /dev/urandom | base64)

    verbose "Generated ephemeral credentials for local deployment"

    # Store passwords in test-artifacts for consistency with CI
    mkdir -p "${SCRIPT_DIR}/test-workspace/test-artifacts"
    echo "$ephemeral_admin_password" > "${SCRIPT_DIR}/test-workspace/test-artifacts/admin-password"
    echo "$ephemeral_nss_password" > "${SCRIPT_DIR}/test-workspace/test-artifacts/nss-password"
    chmod 600 "${SCRIPT_DIR}/test-workspace/test-artifacts/admin-password"
    chmod 600 "${SCRIPT_DIR}/test-workspace/test-artifacts/nss-password"

    verbose "Stored generated passwords in test-artifacts/"
    verbose "  Admin password: ${#ephemeral_admin_password} characters"
    verbose "  NSS password: ${#ephemeral_nss_password} characters"

    cat > "$env_file" << EOF
# Sigul Stack Environment Configuration
# Generated: $(date)

# Container Images
SIGUL_CLIENT_IMAGE=client-${PLATFORM_ID}-image:test
SIGUL_SERVER_IMAGE=server-${PLATFORM_ID}-image:test
SIGUL_BRIDGE_IMAGE=bridge-${PLATFORM_ID}-image:test

# Security Configuration (Generated randomly, stored in test-artifacts/)
NSS_PASSWORD=${ephemeral_nss_password}
SIGUL_ADMIN_PASSWORD=${ephemeral_admin_password}
SIGUL_ADMIN_USER=admin

# Debug Configuration
DEBUG=${DEBUG_MODE}

# Network Configuration
SIGUL_BRIDGE_CLIENT_PORT=44334
SIGUL_BRIDGE_SERVER_PORT=44333
SIGUL_BRIDGE_HOSTNAME=sigul-bridge

# Platform Configuration
SIGUL_PLATFORM_ID=${PLATFORM_ID}
EOF

    verbose "Environment file created: $env_file"
    success "Environment configuration generated"
}

# Deploy Sigul infrastructure
deploy_infrastructure() {
    log "Deploying Sigul infrastructure..."

    cd "$PROJECT_ROOT"

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Set environment file
    export COMPOSE_FILE="$COMPOSE_FILE"

    # Load environment
    if [[ -f "${SCRIPT_DIR}/.env" ]]; then
        set -a
        # shellcheck disable=SC1091
        source "${SCRIPT_DIR}/.env"
        set +a
    fi

    verbose "Using compose file: $COMPOSE_FILE"
    verbose "Container images:"
    verbose "  Client: ${SIGUL_CLIENT_IMAGE:-not-set}"
    verbose "  Server: ${SIGUL_SERVER_IMAGE:-not-set}"
    verbose "  Bridge: ${SIGUL_BRIDGE_IMAGE:-not-set}"

    # Deploy the stack
    log "Starting Sigul services..."
    if $compose_cmd -f "$COMPOSE_FILE" up -d sigul-server sigul-bridge; then
        success "Sigul infrastructure deployed"
    else
        error "Failed to deploy Sigul infrastructure"
        exit 1
    fi

    # Wait for services to be ready
    log "Waiting for services to initialize..."
    sleep 30

    # Check service status
    log "Checking service status..."
    $compose_cmd -f "$COMPOSE_FILE" ps

    success "Infrastructure deployment completed"
}

# Run health checks
run_health_checks() {
    log "Running health checks..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Check container status
    log "Container status:"
    $compose_cmd -f "$COMPOSE_FILE" ps --format table

    # Check logs for errors
    log "Checking recent logs for errors..."

    local containers=("sigul-server" "sigul-bridge")
    for container in "${containers[@]}"; do
        verbose "Checking logs for $container..."

        if $compose_cmd -f "$COMPOSE_FILE" logs --tail=20 "$container" | grep -i error; then
            warn "Errors found in $container logs"
        else
            verbose "No errors found in $container logs"
        fi
    done

    # Test network connectivity
    log "Testing network connectivity..."

    # Test bridge port
    if $compose_cmd -f "$COMPOSE_FILE" exec sigul-bridge nc -z localhost 44334; then
        success "Bridge port 44334 is accessible"
    else
        warn "Bridge port 44334 is not accessible"
    fi

    success "Health checks completed"
}

# Run integration tests
run_integration_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        log "Skipping integration tests (--skip-tests specified)"
        return 0
    fi

    log "Running integration tests..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)

    # Deploy network tester for diagnostics
    log "Starting network tester..."
    $compose_cmd -f "$COMPOSE_FILE" --profile testing up -d network-tester

    # Wait for network tester to initialize
    sleep 10

    # Run network connectivity tests
    log "Testing network connectivity..."
    $compose_cmd -f "$COMPOSE_FILE" exec network-tester nc -z sigul-bridge 44334 || warn "Bridge connectivity test failed"

    # Check certificate setup
    log "Checking certificate configuration..."
    $compose_cmd -f "$COMPOSE_FILE" exec sigul-server ls -la /var/sigul/secrets/certificates/ || warn "Server certificates not found"
    $compose_cmd -f "$COMPOSE_FILE" exec sigul-bridge ls -la /var/sigul/secrets/certificates/ || warn "Bridge certificates not found"

    # TODO: Add more comprehensive integration tests
    # - Certificate validation
    # - Signing operation tests
    # - End-to-end workflow tests

    success "Integration tests completed"
}

# Collect diagnostics
collect_diagnostics() {
    log "Collecting diagnostics..."

    local compose_cmd
    compose_cmd=$(get_docker_compose_cmd)
    local diagnostics_dir="${SCRIPT_DIR}/diagnostics-$(date +%Y%m%d-%H%M%S)"

    mkdir -p "$diagnostics_dir"

    # Container logs
    log "Collecting container logs..."
    local containers=("sigul-server" "sigul-bridge" "network-tester")
    for container in "${containers[@]}"; do
        if $compose_cmd -f "$COMPOSE_FILE" ps --services | grep -q "$container"; then
            $compose_cmd -f "$COMPOSE_FILE" logs "$container" > "$diagnostics_dir/${container}.log" 2>&1 || true
        fi
    done

    # Container status
    $compose_cmd -f "$COMPOSE_FILE" ps > "$diagnostics_dir/container-status.txt" 2>&1 || true

    # Docker info
    docker info > "$diagnostics_dir/docker-info.txt" 2>&1 || true
    docker version > "$diagnostics_dir/docker-version.txt" 2>&1 || true

    # Environment info
    uname -a > "$diagnostics_dir/system-info.txt" 2>&1 || true
    env | grep -E "(DOCKER|SIGUL|DEBUG)" > "$diagnostics_dir/environment.txt" 2>&1 || true

    # Network info
    $compose_cmd -f "$COMPOSE_FILE" exec sigul-bridge ip addr > "$diagnostics_dir/bridge-network.txt" 2>&1 || true
    $compose_cmd -f "$COMPOSE_FILE" exec sigul-server ip addr > "$diagnostics_dir/server-network.txt" 2>&1 || true

    success "Diagnostics collected in: $diagnostics_dir"
}

# Main deployment function
main() {
    log "Starting local Sigul stack deployment for macOS ARM64..."
    log "Project root: $PROJECT_ROOT"
    log "Script directory: $SCRIPT_DIR"

    # Parse arguments
    parse_arguments "$@"

    # Set debug mode from environment if not set by arguments
    if [[ "${DEBUG:-false}" == "true" && "$DEBUG_MODE" == "false" ]]; then
        DEBUG_MODE=true
        VERBOSE_MODE=true
        debug "Debug mode enabled via environment variable"
    fi

    verbose "Configuration:"
    verbose "  Build local: $BUILD_LOCAL"
    verbose "  Download artifacts: $DOWNLOAD_ARTIFACTS"
    verbose "  Workflow run ID: $WORKFLOW_RUN_ID"
    verbose "  Clean deployment: $CLEAN_DEPLOYMENT"
    verbose "  Skip tests: $SKIP_TESTS"
    verbose "  Platform: $PLATFORM"

    # Execute deployment steps
    check_prerequisites
    cleanup_deployment
    download_artifacts
    build_containers
    setup_test_workspace
    generate_env_file
    deploy_infrastructure
    run_health_checks
    run_integration_tests
    collect_diagnostics

    success "🎉 Local Sigul stack deployment completed successfully!"

    log ""
    log "Next steps:"
    log "1. Review logs: docker compose -f $COMPOSE_FILE logs"
    log "2. Access containers:"
    log "   - Server: docker compose -f $COMPOSE_FILE exec sigul-server bash"
    log "   - Bridge: docker compose -f $COMPOSE_FILE exec sigul-bridge bash"
    log "   - Network tester: docker compose -f $COMPOSE_FILE exec network-tester sh"
    log "3. Run manual tests in test workspace: $TEST_WORKSPACE"
    log "4. Stop stack: docker compose -f $COMPOSE_FILE down"
    log ""
    log "For debugging, check the diagnostics directory and container logs."
}

# Execute main function with all arguments
main "$@"
