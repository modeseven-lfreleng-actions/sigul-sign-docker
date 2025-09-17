#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# GitHub Artifacts Download Script for Sigul Containers
#
# This script downloads pre-built ARM64 container images from GitHub workflow artifacts
# and loads them into the local Docker daemon for immediate use.
#
# Usage:
#   ./local-testing/download-github-artifacts.sh [OPTIONS]
#
# Options:
#   --run-id ID         GitHub workflow run ID (default: 17629893204)
#   --platform PLATFORM Platform to download (linux/arm64, linux/amd64, or both)
#   --token TOKEN       GitHub token for authentication (optional for public repos)
#   --verbose           Enable verbose output
#   --debug             Enable debug mode
#   --clean             Clean existing images before loading
#   --help              Show this help message

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACTS_DIR="${SCRIPT_DIR}/artifacts"
TEMP_DIR="${SCRIPT_DIR}/temp-downloads"

# Default options
WORKFLOW_RUN_ID="${WORKFLOW_RUN_ID:-17629893204}"
PLATFORM="${PLATFORM:-linux/arm64}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
VERBOSE_MODE=false
DEBUG_MODE=false
CLEAN_IMAGES=false
SHOW_HELP=false

# Repository information
REPO_OWNER="modeseven-lfreleng-actions"
REPO_NAME="sigul-sign-docker"
REPO_FULL="${REPO_OWNER}/${REPO_NAME}"

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

# Help function
show_help() {
    cat << EOF
GitHub Artifacts Download Script for Sigul Containers

This script downloads pre-built container images from GitHub workflow artifacts
and loads them into your local Docker daemon.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --run-id ID         GitHub workflow run ID (default: $WORKFLOW_RUN_ID)
    --platform PLATFORM Platform to download:
                          linux/arm64  - ARM64 containers (default)
                          linux/amd64  - AMD64 containers
                          both         - Both platforms
    --token TOKEN       GitHub token for authentication (optional for public repos)
    --verbose           Enable verbose output
    --debug             Enable debug mode with detailed diagnostics
    --clean             Clean existing images before loading new ones
    --help              Show this help message

ENVIRONMENT VARIABLES:
    GITHUB_TOKEN        GitHub personal access token
    WORKFLOW_RUN_ID     Default workflow run ID to use

EXAMPLES:
    # Download ARM64 containers (default)
    $0 --run-id 17629893204

    # Download with authentication
    $0 --token ghp_xxxxxxxxxxxx --verbose

    # Download both platforms
    $0 --platform both --clean

    # Debug mode
    $0 --debug --verbose

PREREQUISITES:
    - curl command available
    - unzip command available
    - Docker daemon running
    - Internet connection

NOTES:
    - Artifacts expire after a certain time (usually 7-90 days)
    - Large downloads may take several minutes
    - Existing images will be overwritten unless --clean is used

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --run-id)
                if [[ -z "${2:-}" ]]; then
                    error "Workflow run ID required"
                    exit 1
                fi
                WORKFLOW_RUN_ID="$2"
                shift 2
                ;;
            --platform)
                if [[ -z "${2:-}" ]]; then
                    error "Platform required"
                    exit 1
                fi
                PLATFORM="$2"
                shift 2
                ;;
            --token)
                if [[ -z "${2:-}" ]]; then
                    error "GitHub token required"
                    exit 1
                fi
                GITHUB_TOKEN="$2"
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
                CLEAN_IMAGES=true
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

    # Validate platform
    case "$PLATFORM" in
        linux/arm64|linux/amd64|both)
            ;;
        *)
            error "Invalid platform: $PLATFORM"
            error "Valid platforms: linux/arm64, linux/amd64, both"
            exit 1
            ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check required commands
    local required_commands=("curl" "unzip" "docker")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
            exit 1
        fi
        verbose "Found command: $cmd"
    done

    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running"
        exit 1
    fi
    verbose "Docker daemon is running"

    success "Prerequisites check passed"
}

# Setup directories
setup_directories() {
    log "Setting up directories..."

    mkdir -p "$ARTIFACTS_DIR"
    mkdir -p "$TEMP_DIR"

    verbose "Artifacts directory: $ARTIFACTS_DIR"
    verbose "Temp directory: $TEMP_DIR"

    success "Directories created"
}

# Prepare curl command with authentication
prepare_curl() {
    if [[ -n "$GITHUB_TOKEN" ]]; then
        verbose "Using GitHub token for authentication"
        echo "with_auth"
    else
        verbose "No GitHub token provided, using anonymous access"
        echo "no_auth"
    fi
}

# Get artifacts list from GitHub API
get_artifacts_list() {
    log "Fetching artifacts list from GitHub..."

    local auth_mode
    auth_mode=$(prepare_curl)

    local api_url="https://api.github.com/repos/$REPO_FULL/actions/runs/$WORKFLOW_RUN_ID/artifacts"

    verbose "API URL: $api_url"

    local artifacts_json="$TEMP_DIR/artifacts.json"

    if [[ "$auth_mode" == "with_auth" ]]; then
        curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "$api_url" > "$artifacts_json"
    else
        curl -s "$api_url" > "$artifacts_json"
    fi

    if [[ $? -ne 0 ]]; then
        error "Failed to fetch artifacts list"
        exit 1
    fi

    # Check if we got an error response
    if grep -q '"message"' "$artifacts_json"; then
        local error_msg
        error_msg=$(grep -o '"message":"[^"]*"' "$artifacts_json" | cut -d'"' -f4)
        error "GitHub API error: $error_msg"
        exit 1
    fi

    verbose "Artifacts list saved to: $artifacts_json"
    echo "$artifacts_json"
}

# Parse platform suffix from platform string
get_platform_suffix() {
    local platform="$1"
    case "$platform" in
        linux/arm64) echo "arm64" ;;
        linux/amd64) echo "amd64" ;;
        *) echo "unknown" ;;
    esac
}

# Extract artifact information
extract_artifact_info() {
    local artifacts_json="$1"
    local platform="$2"
    local platform_suffix
    platform_suffix=$(get_platform_suffix "$platform")

    debug "Extracting artifacts for platform: $platform (suffix: $platform_suffix)"

    # Use a simple approach to parse JSON without requiring jq
    local components=("client" "server" "bridge")

    for component in "${components[@]}"; do
        local artifact_name="${component}-linux-${platform_suffix}-image"
        verbose "Looking for artifact: $artifact_name"

        # Extract download URL for this artifact
        local download_url
        download_url=$(grep -A 10 "\"name\":\"$artifact_name\"" "$artifacts_json" | grep '"archive_download_url"' | sed 's/.*"archive_download_url": *"\([^"]*\)".*/\1/')

        if [[ -n "$download_url" ]]; then
            success "Found artifact: $artifact_name"
            verbose "Download URL: $download_url"
            echo "$component:$download_url"
        else
            warn "Artifact not found: $artifact_name"
        fi
    done
}

# Download and extract artifact
download_artifact() {
    local component="$1"
    local download_url="$2"
    local platform="$3"
    local platform_suffix
    platform_suffix=$(get_platform_suffix "$platform")

    log "Downloading $component artifact for $platform..."

    local auth_mode
    auth_mode=$(prepare_curl)

    local zip_file="$TEMP_DIR/${component}-${platform_suffix}.zip"
    local extract_dir="$TEMP_DIR/${component}-${platform_suffix}"

    verbose "Downloading to: $zip_file"

    # Download the zip file
    if [[ "$auth_mode" == "with_auth" ]]; then
        curl -L -H "Authorization: Bearer $GITHUB_TOKEN" "$download_url" -o "$zip_file"
    else
        curl -L "$download_url" -o "$zip_file"
    fi

    if [[ $? -ne 0 ]]; then
        error "Failed to download $component artifact"
        return 1
    fi

    # Extract the zip file
    log "Extracting $component artifact..."

    mkdir -p "$extract_dir"
    unzip -q "$zip_file" -d "$extract_dir"

    if [[ $? -ne 0 ]]; then
        error "Failed to extract $component artifact"
        return 1
    fi

    # Find the tar file (should be the only .tar file in the directory)
    local tar_file
    tar_file=$(find "$extract_dir" -name "*.tar" | head -1)

    if [[ -z "$tar_file" ]]; then
        error "No tar file found in $component artifact"
        return 1
    fi

    verbose "Found tar file: $tar_file"

    # Move tar file to final location
    local final_tar="$ARTIFACTS_DIR/${component}-linux-${platform_suffix}-image.tar"
    mv "$tar_file" "$final_tar"

    success "Downloaded and extracted: $final_tar"

    # Clean up temporary files
    rm -f "$zip_file"
    rm -rf "$extract_dir"

    echo "$final_tar"
}

# Load Docker image from tar file
load_docker_image() {
    local tar_file="$1"
    local component="$2"
    local platform="$3"
    local platform_suffix
    platform_suffix=$(get_platform_suffix "$platform")

    log "Loading $component Docker image..."

    verbose "Loading from: $tar_file"

    if docker load -i "$tar_file"; then
        success "Loaded $component image successfully"

        # Tag the image with our expected name
        local expected_tag="${component}-linux-${platform_suffix}-image:test"

        # Get the actual image name from docker load output
        local loaded_image
        loaded_image=$(docker load -i "$tar_file" 2>&1 | grep "Loaded image:" | sed 's/Loaded image: //')

        if [[ -n "$loaded_image" ]]; then
            verbose "Loaded image: $loaded_image"

            # Tag with expected name if different
            if [[ "$loaded_image" != "$expected_tag" ]]; then
                docker tag "$loaded_image" "$expected_tag"
                verbose "Tagged as: $expected_tag"
            fi
        fi

        return 0
    else
        error "Failed to load $component image"
        return 1
    fi
}

# Clean existing images
clean_existing_images() {
    if [[ "$CLEAN_IMAGES" == "true" ]]; then
        log "Cleaning existing Sigul images..."

        local images_to_remove
        images_to_remove=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(client|server|bridge).*linux.*image:test" || true)

        if [[ -n "$images_to_remove" ]]; then
            echo "$images_to_remove" | while IFS= read -r image; do
                verbose "Removing image: $image"
                docker rmi "$image" 2>/dev/null || true
            done
            success "Cleaned existing images"
        else
            verbose "No existing images to clean"
        fi
    fi
}

# Process single platform
process_platform() {
    local platform="$1"
    local artifacts_json="$2"

    log "Processing platform: $platform"

    # Extract artifact information
    local artifacts_info
    artifacts_info=$(extract_artifact_info "$artifacts_json" "$platform")

    if [[ -z "$artifacts_info" ]]; then
        warn "No artifacts found for platform: $platform"
        return 1
    fi

    # Download and load each component
    local success_count=0
    local total_count=0

    while IFS=':' read -r component download_url; do
        if [[ -n "$component" && -n "$download_url" ]]; then
            ((total_count++))

            # Download artifact
            local tar_file
            if tar_file=$(download_artifact "$component" "$download_url" "$platform"); then
                # Load into Docker
                if load_docker_image "$tar_file" "$component" "$platform"; then
                    ((success_count++))
                fi
            fi
        fi
    done <<< "$artifacts_info"

    log "Platform $platform: $success_count/$total_count components loaded successfully"

    if [[ $success_count -eq $total_count && $total_count -gt 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Generate environment file
generate_environment_file() {
    local platforms=("$@")

    log "Generating environment file..."

    local env_file="${SCRIPT_DIR}/.env"
    local platform_suffix

    # Use the first platform for environment setup
    platform_suffix=$(get_platform_suffix "${platforms[0]}")

    cat > "$env_file" << EOF
# Sigul Stack Environment Configuration
# Generated: $(date)
# Downloaded from GitHub workflow run: $WORKFLOW_RUN_ID

# Container Images
SIGUL_CLIENT_IMAGE=client-linux-${platform_suffix}-image:test
SIGUL_SERVER_IMAGE=server-linux-${platform_suffix}-image:test
SIGUL_BRIDGE_IMAGE=bridge-linux-${platform_suffix}-image:test

# Security Configuration
NSS_PASSWORD=downloaded_test_password_$(date +%s | tail -c 8)
SIGUL_ADMIN_PASSWORD=admin_password_$(date +%s | tail -c 8)
SIGUL_ADMIN_USER=admin

# Debug Configuration
DEBUG=${DEBUG_MODE}

# Network Configuration
SIGUL_BRIDGE_CLIENT_PORT=44334
SIGUL_BRIDGE_SERVER_PORT=44333
SIGUL_BRIDGE_HOSTNAME=sigul-bridge

# Platform Configuration
SIGUL_PLATFORM_ID=linux-${platform_suffix}
DOCKER_PLATFORM=${platforms[0]}

# Source Information
GITHUB_WORKFLOW_RUN_ID=$WORKFLOW_RUN_ID
ARTIFACT_SOURCE=github
EOF

    success "Environment file created: $env_file"
}

# Show downloaded images
show_downloaded_images() {
    log "Downloaded Sigul images:"

    local sigul_images
    sigul_images=$(docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" | grep -E "(REPOSITORY|client|server|bridge).*linux.*image")

    if [[ -n "$sigul_images" ]]; then
        echo "$sigul_images"
    else
        warn "No Sigul images found"
    fi
}

# Cleanup temporary files
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        verbose "Cleaning up temporary files..."
        rm -rf "$TEMP_DIR"
    fi
}

# Main function
main() {
    log "Starting GitHub artifacts download for Sigul containers..."
    log "Workflow run ID: $WORKFLOW_RUN_ID"
    log "Repository: $REPO_FULL"

    # Parse arguments
    parse_arguments "$@"

    verbose "Configuration:"
    verbose "  Platform: $PLATFORM"
    verbose "  Clean images: $CLEAN_IMAGES"
    verbose "  Verbose mode: $VERBOSE_MODE"
    verbose "  Debug mode: $DEBUG_MODE"

    # Setup
    check_prerequisites
    setup_directories
    clean_existing_images

    # Get artifacts list
    local artifacts_json
    artifacts_json=$(get_artifacts_list)

    # Process platforms
    local platforms_to_process=()
    case "$PLATFORM" in
        both)
            platforms_to_process=("linux/arm64" "linux/amd64")
            ;;
        *)
            platforms_to_process=("$PLATFORM")
            ;;
    esac

    local overall_success=true

    for platform in "${platforms_to_process[@]}"; do
        if ! process_platform "$platform" "$artifacts_json"; then
            overall_success=false
        fi
    done

    # Generate environment file
    generate_environment_file "${platforms_to_process[@]}"

    # Show results
    show_downloaded_images

    # Cleanup
    cleanup

    if [[ "$overall_success" == "true" ]]; then
        success "🎉 GitHub artifacts download completed successfully!"
        echo ""
        log "Next steps:"
        log "1. Start the stack: ./local-testing/manage-local-env.sh start"
        log "2. Check status: ./local-testing/manage-local-env.sh status"
        log "3. View logs: ./local-testing/manage-local-env.sh logs"
    else
        error "❌ Some artifacts failed to download or load"
        exit 1
    fi
}

# Trap cleanup on exit
trap cleanup EXIT

# Execute main function with all arguments
main "$@"
