#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Getting Started with Local Sigul Testing
#
# This script provides a quick setup and introduction to the local Sigul testing environment.
# It will guide you through the initial setup and show you the most common operations.

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')] ${NC}$*"
}

success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] ✅ ${NC}$*"
}

warn() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠️  ${NC}$*"
}

error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ❌ ${NC}$*" >&2
}

info() {
    echo -e "${CYAN}[$(date '+%H:%M:%S')] ℹ️  ${NC}$*"
}

title() {
    echo ""
    echo -e "${BOLD}${PURPLE}================================${NC}"
    echo -e "${BOLD}${PURPLE} $*${NC}"
    echo -e "${BOLD}${PURPLE}================================${NC}"
    echo ""
}

# Show welcome message
show_welcome() {
    clear
    cat << EOF
${BOLD}${BLUE}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║                 🚀 Sigul Local Testing Setup                   ║
║                                                                ║
║              Welcome to the Local Testing Environment!         ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
${NC}

This script will help you get started with testing the Sigul infrastructure
locally on your macOS ARM64 system.

${BOLD}What this will do:${NC}
✅ Check your system prerequisites
✅ Build Sigul containers for ARM64
✅ Deploy the complete Sigul stack (Server, Bridge, Client)
✅ Run health checks and basic tests
✅ Show you how to use the management tools

${BOLD}What you'll get:${NC}
🔐 Complete PKI certificate infrastructure
🐳 All Sigul components running in Docker
🔍 Health monitoring and debugging tools
📋 Comprehensive logging and diagnostics
🧪 Integration testing capabilities

EOF

    read -p "Ready to get started? (y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled. Run this script again when you're ready!"
        exit 0
    fi
}

# Check prerequisites
check_prerequisites() {
    title "Checking Prerequisites"

    local all_good=true

    # Check macOS
    if [[ "$(uname)" == "Darwin" ]]; then
        success "Running on macOS"
    else
        error "This setup is optimized for macOS"
        all_good=false
    fi

    # Check architecture
    local arch
    arch=$(uname -m)
    if [[ "$arch" == "arm64" ]]; then
        success "ARM64 architecture detected (Apple Silicon)"
    else
        warn "Expected ARM64, found: $arch"
        info "This setup is optimized for Apple Silicon Macs"
    fi

    # Check Docker
    if command -v docker >/dev/null 2>&1; then
        success "Docker is installed"

        if docker info >/dev/null 2>&1; then
            success "Docker daemon is running"
        else
            error "Docker daemon is not running"
            error "Please start Docker Desktop and try again"
            all_good=false
        fi
    else
        error "Docker is not installed"
        error "Please install Docker Desktop for Mac and try again"
        all_good=false
    fi

    # Check Docker Compose
    if docker compose version >/dev/null 2>&1; then
        success "Docker Compose is available"
    elif command -v docker-compose >/dev/null 2>&1; then
        success "Docker Compose (standalone) is available"
    else
        error "Docker Compose is not available"
        all_good=false
    fi

    # Check available disk space
    local available_space
    available_space=$(df -H . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ "${available_space%.*}" -gt 5 ]]; then
        success "Sufficient disk space available"
    else
        warn "Low disk space detected. At least 5GB recommended for container builds"
    fi

    if [[ "$all_good" == "false" ]]; then
        error "Prerequisites check failed. Please resolve the issues above and try again."
        exit 1
    fi

    success "All prerequisites check passed!"
}

# Deploy the Sigul stack
deploy_stack() {
    title "Deploying Sigul Stack"

    log "This will build and deploy all Sigul components..."
    log "Expected time: 5-10 minutes (first run may take longer)"

    echo ""
    read -p "Continue with deployment? (Y/n): " -r
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        warn "Deployment skipped"
        return 0
    fi

    log "Starting deployment..."

    if "${SCRIPT_DIR}/deploy-local-sigul-stack.sh" --build-local --verbose; then
        success "Sigul stack deployed successfully!"
    else
        error "Deployment failed. Check the logs above for details."
        error "You can retry with: ./local-testing/deploy-local-sigul-stack.sh --build-local --debug"
        exit 1
    fi
}

# Show stack status
show_status() {
    title "Stack Status"

    log "Checking the status of your Sigul stack..."

    if "${SCRIPT_DIR}/manage-local-env.sh" status; then
        success "Status check completed"
    else
        warn "Status check had some issues. This is normal for a new deployment."
    fi
}

# Run basic tests
run_tests() {
    title "Running Basic Tests"

    log "Running connectivity and health tests..."

    if "${SCRIPT_DIR}/test-components.sh" network; then
        success "Network tests passed"
    else
        warn "Network tests had issues. Check the detailed output above."
    fi

    log "Testing certificate setup..."

    if "${SCRIPT_DIR}/test-components.sh" certs; then
        success "Certificate tests passed"
    else
        warn "Certificate tests had issues. This may be expected on first run."
    fi
}

# Show next steps
show_next_steps() {
    title "🎉 Setup Complete!"

    cat << EOF
${BOLD}${GREEN}Congratulations! Your local Sigul testing environment is ready!${NC}

${BOLD}Here's what you can do now:${NC}

${BOLD}📊 Check Status:${NC}
  ./local-testing/manage-local-env.sh status

${BOLD}📋 View Logs:${NC}
  ./local-testing/manage-local-env.sh logs           # All services
  ./local-testing/manage-local-env.sh logs server    # Just server
  ./local-testing/manage-local-env.sh logs -f        # Follow logs

${BOLD}🐚 Access Containers:${NC}
  ./local-testing/manage-local-env.sh shell server   # Server shell
  ./local-testing/manage-local-env.sh shell bridge   # Bridge shell

${BOLD}🧪 Run Tests:${NC}
  ./local-testing/test-components.sh server health   # Test server
  ./local-testing/test-components.sh all             # Test everything

${BOLD}🔄 Manage Environment:${NC}
  ./local-testing/manage-local-env.sh stop           # Stop all services
  ./local-testing/manage-local-env.sh start          # Start all services
  ./local-testing/manage-local-env.sh restart        # Restart all services

${BOLD}🐛 Debug Issues:${NC}
  ./local-testing/manage-local-env.sh debug          # Start debug session
  ./local-testing/test-components.sh server logs     # Analyze logs

${BOLD}🧹 Clean Up:${NC}
  ./local-testing/manage-local-env.sh clean          # Remove containers
  ./local-testing/manage-local-env.sh reset          # Complete reset

${BOLD}📚 Documentation:${NC}
  See ./local-testing/README.md for detailed usage information

${BOLD}💡 Pro Tips:${NC}
• Use ${YELLOW}--verbose${NC} flag for detailed output
• Use ${YELLOW}--debug${NC} flag for troubleshooting
• Check ${YELLOW}local-testing/diagnostics-*/${NC} for diagnostic files
• Monitor resources with ${YELLOW}docker stats${NC}

EOF

    info "For help with any issues, check the troubleshooting section in README.md"
    success "Happy testing! 🚀"
}

# Offer quick demo
offer_demo() {
    echo ""
    read -p "Would you like a quick demonstration of the management tools? (y/N): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        run_demo
    fi
}

# Run a quick demo
run_demo() {
    title "Quick Demo"

    log "Let me show you some basic operations..."

    echo ""
    info "1. Checking stack status..."
    sleep 2
    "${SCRIPT_DIR}/manage-local-env.sh" status

    echo ""
    info "2. Showing recent logs (last 5 lines per service)..."
    sleep 2
    docker compose -f "${PROJECT_ROOT}/docker-compose.sigul.yml" logs --tail=5

    echo ""
    info "3. Testing network connectivity..."
    sleep 2
    if docker compose -f "${PROJECT_ROOT}/docker-compose.sigul.yml" exec -T sigul-bridge nc -z localhost 44334; then
        success "Bridge port 44334 is accessible!"
    else
        warn "Bridge port test failed (this might be normal)"
    fi

    echo ""
    success "Demo complete! You can now explore the environment on your own."
}

# Main function
main() {
    # Change to project root
    cd "$PROJECT_ROOT"

    # Check if we're in the right place
    if [[ ! -f "docker-compose.sigul.yml" ]]; then
        error "This script must be run from the sigul-sign-docker project root"
        error "Current directory: $(pwd)"
        exit 1
    fi

    # Run the setup process
    show_welcome
    check_prerequisites
    deploy_stack
    show_status
    run_tests
    show_next_steps
    offer_demo

    echo ""
    success "Setup complete! Enjoy working with your local Sigul environment! 🎯"
}

# Execute main function
main "$@"
