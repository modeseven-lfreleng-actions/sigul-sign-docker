#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Simplified ARM64 Container Download Script
#
# This script downloads the specific ARM64 containers we need from GitHub artifacts
# using direct URLs and loads them into Docker.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')] INFO:${NC} $*"
}

success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] SUCCESS:${NC} $*"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN:${NC} $*"
}

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="${SCRIPT_DIR}/temp-downloads"
WORKFLOW_RUN_ID="17629893204"

# ARM64 artifact information (component:artifact_id)
CLIENT_ARTIFACT_ID="3980964529"
SERVER_ARTIFACT_ID="3980964551"
BRIDGE_ARTIFACT_ID="3980963524"

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    for cmd in curl unzip docker; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done

    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running"
        exit 1
    fi

    success "Prerequisites check passed"
}

# Setup directories
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$TEMP_DIR"
    success "Directories created"
}

# Download and load single component
download_and_load_component() {
    local component="$1"
    local artifact_id="$2"

    log "Processing $component component..."

    local download_url="https://api.github.com/repos/modeseven-lfreleng-actions/sigul-sign-docker/actions/artifacts/${artifact_id}/zip"
    local zip_file="$TEMP_DIR/${component}-arm64.zip"
    local extract_dir="$TEMP_DIR/${component}-arm64"

    # Download
    log "Downloading $component artifact (ID: $artifact_id)..."
    if ! curl -L -o "$zip_file" "$download_url"; then
        error "Failed to download $component artifact"
        return 1
    fi

    # Verify download
    if [[ ! -f "$zip_file" ]]; then
        error "Downloaded file not found: $zip_file"
        return 1
    fi

    local file_size
    file_size=$(wc -c < "$zip_file")
    if [[ $file_size -lt 1000 ]]; then
        error "Download appears to be incomplete (size: $file_size bytes)"
        return 1
    fi

    log "Downloaded $component artifact ($file_size bytes)"

    # Extract
    log "Extracting $component artifact..."
    mkdir -p "$extract_dir"
    if ! unzip -q "$zip_file" -d "$extract_dir"; then
        error "Failed to extract $component artifact"
        return 1
    fi

    # Find tar file
    local tar_file
    tar_file=$(find "$extract_dir" -name "*.tar" | head -1)

    if [[ -z "$tar_file" ]]; then
        error "No tar file found in $component artifact"
        log "Contents of extract directory:"
        ls -la "$extract_dir"
        return 1
    fi

    log "Found tar file: $tar_file"

    # Load into Docker
    log "Loading $component image into Docker..."
    local load_output
    load_output=$(docker load -i "$tar_file" 2>&1)

    if [[ $? -eq 0 ]]; then
        success "Loaded $component image successfully"

        # Extract image name from load output
        local loaded_image
        loaded_image=$(echo "$load_output" | grep "Loaded image:" | sed 's/Loaded image: //' || true)

        if [[ -n "$loaded_image" ]]; then
            log "Loaded image: $loaded_image"

            # Tag with expected name
            local expected_tag="${component}-linux-arm64-image:test"
            if docker tag "$loaded_image" "$expected_tag"; then
                success "Tagged as: $expected_tag"
            else
                warn "Failed to tag $loaded_image as $expected_tag"
            fi
        else
            warn "Could not determine loaded image name"
        fi
    else
        error "Failed to load $component image"
        error "Docker load output: $load_output"
        return 1
    fi

    # Cleanup
    rm -f "$zip_file"
    rm -rf "$extract_dir"

    return 0
}

# Generate environment file
generate_environment_file() {
    log "Generating environment file..."

    local env_file="${SCRIPT_DIR}/.env"

    cat > "$env_file" << EOF
SIGUL_CLIENT_IMAGE=client-linux-arm64-image:test
SIGUL_SERVER_IMAGE=server-linux-arm64-image:test
SIGUL_BRIDGE_IMAGE=bridge-linux-arm64-image:test
NSS_PASSWORD=github_test_password_$(date +%s | tail -c 8)
SIGUL_ADMIN_PASSWORD=admin_password_$(date +%s | tail -c 8)
SIGUL_ADMIN_USER=admin
DEBUG=false
SIGUL_BRIDGE_CLIENT_PORT=44334
SIGUL_BRIDGE_SERVER_PORT=44333
SIGUL_BRIDGE_HOSTNAME=sigul-bridge
SIGUL_PLATFORM_ID=linux-arm64
DOCKER_PLATFORM=linux/arm64
GITHUB_WORKFLOW_RUN_ID=$WORKFLOW_RUN_ID
ARTIFACT_SOURCE=github
DOCKER_BUILDKIT=1
BUILDKIT_PROGRESS=plain
EOF

    success "Environment file created: $env_file"
}

# Show downloaded images
show_downloaded_images() {
    log "Downloaded Sigul images:"
    echo ""

    # Check if any ARM64 images exist
    local arm64_images
    arm64_images=$(docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}" | grep -E "(REPOSITORY|.*linux-arm64-image)" || true)

    if [[ -n "$arm64_images" ]]; then
        echo "$arm64_images"
    else
        warn "No ARM64 Sigul images found"
    fi
    echo ""
}

# Cleanup
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        log "Cleaning up temporary files..."
        rm -rf "$TEMP_DIR"
    fi
}

# Main function
main() {
    echo "🚀 Downloading ARM64 Sigul Containers from GitHub"
    echo "================================================="
    echo ""

    log "Starting download of ARM64 containers from workflow run: $WORKFLOW_RUN_ID"

    # Setup
    check_prerequisites
    setup_directories

    # Download each component
    local success_count=0
    local total_count=3

    # Download client
    if download_and_load_component "client" "$CLIENT_ARTIFACT_ID"; then
        ((success_count++))
    fi

    # Download server
    if download_and_load_component "server" "$SERVER_ARTIFACT_ID"; then
        ((success_count++))
    fi

    # Download bridge
    if download_and_load_component "bridge" "$BRIDGE_ARTIFACT_ID"; then
        ((success_count++))
    fi

    # Generate environment
    generate_environment_file

    # Show results
    show_downloaded_images

    # Summary
    echo ""
    if [[ $success_count -eq $total_count ]]; then
        success "🎉 All $total_count ARM64 containers downloaded and loaded successfully!"
        echo ""
        log "Next steps:"
        log "1. Start the stack: ./local-testing/manage-local-env.sh start"
        log "2. Check status: ./local-testing/manage-local-env.sh status"
        log "3. View logs: ./local-testing/manage-local-env.sh logs"
        echo ""
    else
        error "❌ Only $success_count/$total_count containers loaded successfully"
        exit 1
    fi
}

# Trap cleanup on exit
trap cleanup EXIT

# Execute main function
main "$@"
