#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Local Environment Validation Script
#
# This script validates that the local testing environment is properly set up
# and all prerequisites are met before attempting to deploy the Sigul stack.
#
# Usage:
#   ./local-testing/validate-setup.sh [--verbose] [--fix]

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.sigul.yml"

# Options
VERBOSE=false
FIX_ISSUES=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Validation results
CHECKS_TOTAL=0
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')] ${NC}$*"
}

success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] ✅ ${NC}$*"
    ((CHECKS_PASSED++))
}

fail() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ❌ ${NC}$*"
    ((CHECKS_FAILED++))
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠️  ${NC}$*"
    ((CHECKS_WARNING++))
}

verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}[$(date '+%H:%M:%S')] DEBUG: ${NC}$*"
    fi
}

check_start() {
    local check_name="$1"
    log "🔍 Checking: $check_name"
    ((CHECKS_TOTAL++))
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose)
                VERBOSE=true
                shift
                ;;
            --fix)
                FIX_ISSUES=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
Local Environment Validation Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --verbose       Enable verbose output
    --fix           Attempt to fix issues automatically
    --help          Show this help message

DESCRIPTION:
    This script validates that your local environment is properly set up
    for Sigul testing. It checks prerequisites, file permissions, and
    Docker configuration.

EXAMPLES:
    $0                  # Basic validation
    $0 --verbose        # Detailed validation output
    $0 --fix            # Attempt to fix issues

EOF
}

# Check operating system
check_os() {
    check_start "Operating System"

    local os
    os=$(uname)

    if [[ "$os" == "Darwin" ]]; then
        success "Running on macOS"

        local arch
        arch=$(uname -m)
        if [[ "$arch" == "arm64" ]]; then
            success "ARM64 architecture detected (Apple Silicon)"
        else
            warn "Expected ARM64, found: $arch (this setup is optimized for Apple Silicon)"
        fi
    else
        warn "Not running on macOS (found: $os) - this setup is optimized for macOS"
    fi
}

# Check Docker installation and status
check_docker() {
    check_start "Docker Installation"

    if command -v docker >/dev/null 2>&1; then
        success "Docker is installed"
        verbose "Docker version: $(docker --version)"
    else
        fail "Docker is not installed"
        if [[ "$FIX_ISSUES" == "true" ]]; then
            log "Please install Docker Desktop for Mac manually"
        fi
        return 1
    fi

    check_start "Docker Daemon"

    if docker info >/dev/null 2>&1; then
        success "Docker daemon is running"

        # Check Docker resources
        local memory_gb
        memory_gb=$(docker system info --format '{{.MemTotal}}' 2>/dev/null | awk '{print int($1/1024/1024/1024)}')
        if [[ "${memory_gb:-0}" -ge 4 ]]; then
            success "Docker has sufficient memory: ${memory_gb}GB"
        else
            warn "Docker memory limit may be low: ${memory_gb}GB (recommend 4GB+)"
        fi
    else
        fail "Docker daemon is not running"
        if [[ "$FIX_ISSUES" == "true" ]]; then
            log "Please start Docker Desktop and try again"
        fi
        return 1
    fi
}

# Check Docker Compose
check_docker_compose() {
    check_start "Docker Compose"

    if docker compose version >/dev/null 2>&1; then
        success "Docker Compose (integrated) is available"
        verbose "Version: $(docker compose version)"
    elif command -v docker-compose >/dev/null 2>&1; then
        success "Docker Compose (standalone) is available"
        verbose "Version: $(docker-compose --version)"
    else
        fail "Docker Compose is not available"
        return 1
    fi
}

# Check disk space
check_disk_space() {
    check_start "Disk Space"

    local available_space_gb
    if command -v df >/dev/null 2>&1; then
        available_space_gb=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')

        if [[ "${available_space_gb:-0}" -ge 10 ]]; then
            success "Sufficient disk space: ${available_space_gb}GB available"
        elif [[ "${available_space_gb:-0}" -ge 5 ]]; then
            warn "Limited disk space: ${available_space_gb}GB available (recommend 10GB+)"
        else
            fail "Insufficient disk space: ${available_space_gb}GB available (need at least 5GB)"
        fi
    else
        warn "Cannot check disk space (df command not available)"
    fi
}

# Check project structure
check_project_structure() {
    check_start "Project Structure"

    local required_files=(
        "docker-compose.sigul.yml"
        "Dockerfile.server"
        "Dockerfile.bridge"
        "Dockerfile.client"
        "scripts/sigul-init.sh"
        "scripts/deploy-sigul-infrastructure.sh"
        "pki/setup-ca.sh"
    )

    local missing_files=()

    for file in "${required_files[@]}"; do
        if [[ -f "$PROJECT_ROOT/$file" ]]; then
            verbose "Found: $file"
        else
            missing_files+=("$file")
        fi
    done

    if [[ ${#missing_files[@]} -eq 0 ]]; then
        success "All required project files found"
    else
        fail "Missing required files: ${missing_files[*]}"
        return 1
    fi
}

# Check script permissions
check_script_permissions() {
    check_start "Script Permissions"

    local scripts=(
        "local-testing/deploy-local-sigul-stack.sh"
        "local-testing/manage-local-env.sh"
        "local-testing/test-components.sh"
        "local-testing/getting-started.sh"
        "scripts/sigul-init.sh"
        "scripts/deploy-sigul-infrastructure.sh"
    )

    local non_executable=()

    for script in "${scripts[@]}"; do
        if [[ -f "$PROJECT_ROOT/$script" ]]; then
            if [[ -x "$PROJECT_ROOT/$script" ]]; then
                verbose "Executable: $script"
            else
                non_executable+=("$script")
            fi
        else
            verbose "Not found: $script"
        fi
    done

    if [[ ${#non_executable[@]} -eq 0 ]]; then
        success "All scripts are executable"
    else
        warn "Non-executable scripts: ${non_executable[*]}"

        if [[ "$FIX_ISSUES" == "true" ]]; then
            log "Fixing script permissions..."
            for script in "${non_executable[@]}"; do
                chmod +x "$PROJECT_ROOT/$script"
                verbose "Made executable: $script"
            done
            success "Fixed script permissions"
        fi
    fi
}

# Check Docker Compose file syntax
check_compose_syntax() {
    check_start "Docker Compose Syntax"

    if docker compose -f "$COMPOSE_FILE" config >/dev/null 2>&1; then
        success "Docker Compose file syntax is valid"
    else
        fail "Docker Compose file has syntax errors"
        verbose "Run: docker compose -f $COMPOSE_FILE config"
        return 1
    fi
}

# Check for running containers
check_existing_containers() {
    check_start "Existing Containers"

    local sigul_containers
    sigul_containers=$(docker ps -a --filter "name=sigul" --format "{{.Names}}" 2>/dev/null || true)

    if [[ -n "$sigul_containers" ]]; then
        warn "Found existing Sigul containers:"
        echo "$sigul_containers" | while read -r container; do
            verbose "  - $container"
        done
        log "Use './local-testing/manage-local-env.sh clean' to remove them"
    else
        success "No existing Sigul containers found"
    fi
}

# Check network ports
check_network_ports() {
    check_start "Network Ports"

    local ports=("44334" "44333")
    local ports_in_use=()

    for port in "${ports[@]}"; do
        if command -v lsof >/dev/null 2>&1; then
            if lsof -i ":$port" >/dev/null 2>&1; then
                ports_in_use+=("$port")
            else
                verbose "Port $port is available"
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -an | grep -q ":$port "; then
                ports_in_use+=("$port")
            else
                verbose "Port $port is available"
            fi
        else
            verbose "Cannot check port $port (no lsof or netstat)"
        fi
    done

    if [[ ${#ports_in_use[@]} -eq 0 ]]; then
        success "All required ports are available"
    else
        warn "Ports in use: ${ports_in_use[*]}"
        log "This may cause conflicts during deployment"
    fi
}

# Check Docker BuildKit support
check_buildkit() {
    check_start "Docker BuildKit Support"

    if docker buildx version >/dev/null 2>&1; then
        success "Docker BuildKit is available"
        verbose "Buildx version: $(docker buildx version)"
    else
        warn "Docker BuildKit is not available (may impact build performance)"
    fi
}

# Check available Docker images
check_docker_images() {
    check_start "Existing Docker Images"

    local sigul_images
    sigul_images=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(sigul|client|server|bridge).*test" || true)

    if [[ -n "$sigul_images" ]]; then
        success "Found existing Sigul images:"
        echo "$sigul_images" | while read -r image; do
            verbose "  - $image"
        done
        log "These can be used for faster deployment"
    else
        log "No existing Sigul images found (will need to build from scratch)"
    fi
}

# Generate validation report
generate_report() {
    echo ""
    echo "=================================="
    log "Validation Summary"
    echo "=================================="
    echo ""
    echo "Total checks: $CHECKS_TOTAL"
    echo "✅ Passed: $CHECKS_PASSED"
    echo "❌ Failed: $CHECKS_FAILED"
    echo "⚠️  Warnings: $CHECKS_WARNING"
    echo ""

    local success_rate
    if [[ $CHECKS_TOTAL -gt 0 ]]; then
        success_rate=$(( CHECKS_PASSED * 100 / CHECKS_TOTAL ))
    else
        success_rate=0
    fi

    echo "Success rate: ${success_rate}%"
    echo ""

    if [[ $CHECKS_FAILED -eq 0 ]]; then
        success "🎉 Environment validation passed!"
        echo ""
        echo "You can now run:"
        echo "  ./local-testing/getting-started.sh     # Interactive setup"
        echo "  ./local-testing/deploy-local-sigul-stack.sh --build-local --verbose"
        echo ""
    elif [[ $CHECKS_FAILED -le 2 && $CHECKS_PASSED -ge $((CHECKS_TOTAL - 2)) ]]; then
        warn "⚠️  Environment validation mostly passed with minor issues"
        echo ""
        echo "You can try to proceed, but may encounter issues:"
        echo "  ./local-testing/deploy-local-sigul-stack.sh --build-local --debug"
        echo ""
    else
        fail "❌ Environment validation failed"
        echo ""
        echo "Please resolve the issues above before proceeding."
        echo "Try running with --fix to automatically fix some issues:"
        echo "  ./local-testing/validate-setup.sh --fix"
        echo ""
        return 1
    fi
}

# Main function
main() {
    parse_args "$@"

    echo "🔍 Validating Local Sigul Testing Environment"
    echo "============================================="
    echo ""

    # Change to project root
    cd "$PROJECT_ROOT"

    # Run all validation checks
    check_os
    check_docker
    check_docker_compose
    check_disk_space
    check_project_structure
    check_script_permissions
    check_compose_syntax
    check_existing_containers
    check_network_ports
    check_buildkit
    check_docker_images

    # Generate final report
    generate_report
}

# Execute main function
main "$@"
