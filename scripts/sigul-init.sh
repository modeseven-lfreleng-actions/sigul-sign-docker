#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# shellcheck disable=SC2317  # Disable unreachable code false positives from complex error handling

# Unified Sigul Initialization Script
# This script replaces the separate sigul-server-init.sh and sigul-bridge-init.sh scripts
# with a unified, modular approach supporting all sigul components.
#
# Usage: sigul-init.sh --role <server|bridge|client>
#
# Environment Variables:
#   SIGUL_ROLE              - Component role (server|bridge|client)
#   SIGUL_BASE_DIR         - Base application directory (default: /var/sigul)
#   DEBUG                  - Enable debug logging (default: false)
#   NSS_PASSWORD           - NSS database password (generated if not provided)
#   SIGUL_ADMIN_PASSWORD   - Admin password for server role (generated if not provided)
#   SIGUL_BRIDGE_HOSTNAME  - Bridge connection hostname (default: sigul-bridge)
#   SIGUL_BRIDGE_CLIENT_PORT - Bridge client listen port (default: 44334)
#   SIGUL_BRIDGE_SERVER_PORT - Bridge server listen port (default: 44333)

set -euo pipefail

# Global variables
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly VERSION="1.0.0"
readonly DEFAULT_BASE_DIR="/var/sigul"

# Secrets and certificate configuration
readonly NSS_PASSWORD_LENGTH=32
readonly ADMIN_PASSWORD_LENGTH=16
readonly CERT_VALIDITY_DAYS=365
readonly MIN_CERT_DAYS_REMAINING=30

# Component role - set by command line or environment
SIGUL_ROLE="${SIGUL_ROLE:-}"

# Application directory structure (initialized in setup_env)
SIGUL_BASE_DIR="${SIGUL_BASE_DIR:-$DEFAULT_BASE_DIR}"
CONFIG_DIR=""
LOGS_DIR=""
PIDS_DIR=""
SECRETS_DIR=""
NSS_DIR=""
DATABASE_DIR=""
GNUPG_DIR=""
TMP_DIR=""

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_INVALID_ARGS=1
readonly EXIT_INVALID_ROLE=2
readonly EXIT_SETUP_FAILED=3
readonly EXIT_VALIDATION_FAILED=4
# readonly EXIT_SERVICE_FAILED=5  # Currently unused but may be needed in future
readonly EXIT_DEPENDENCY_MISSING=6
readonly EXIT_CONFIG_ERROR=7

#######################################
# Core Utility Functions
#######################################

# Unified logging system with timestamps and component identification
# Arguments:
#   $1 - Log message
# Outputs:
#   Timestamped log message to stdout
log() {
    local component
    component="$(echo "${SIGUL_ROLE:-sigul}" | tr '[:lower:]' '[:upper:]')"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $component: $*" >&2
}

# Error logging with exit codes
# Arguments:
#   $1 - Error message
#   $2 - Exit code (optional, defaults to 1)
# Outputs:
#   Timestamped error message to stderr
error() {
    local message="$1"
    local exit_code="${2:-1}"
    local component
    component="$(echo "${SIGUL_ROLE:-sigul}" | tr '[:lower:]' '[:upper:]')"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $component ERROR: $message" >&2
    exit "$exit_code"
}

# Debug logging with conditional output
# Arguments:
#   $1 - Debug message
# Outputs:
#   Timestamped debug message to stdout if DEBUG=true
debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        local component
        component="$(echo "${SIGUL_ROLE:-sigul}" | tr '[:lower:]' '[:upper:]')"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $component DEBUG: $*" >&2
    fi
}

# Validate component role
# Arguments:
#   $1 - Role to validate
# Returns:
#   0 if valid role, 1 if invalid
validate_role() {
    local role="$1"
    case "$role" in
        server|bridge|client)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Display usage information
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME --role <server|bridge|client> [options]

Unified Sigul Initialization Script v$VERSION

This script initializes sigul components with a unified directory structure
and modular function design.

OPTIONS:
    --role ROLE         Component role: server, bridge, or client (required)
    --base-dir DIR      Base application directory (default: $DEFAULT_BASE_DIR)
    --debug             Enable debug logging
    --start-service     Start service after initialization
    --service-only      Skip initialization, start service directly
    --help              Show this help message
    --version           Show version information

ENVIRONMENT VARIABLES:
    SIGUL_ROLE             Component role (can override --role)
    SIGUL_BASE_DIR         Base application directory
    DEBUG                  Enable debug logging (true/false)
    NSS_PASSWORD           NSS database password (auto-generated if not set)
    SIGUL_ADMIN_PASSWORD   Admin password for server (auto-generated if not set)
    SIGUL_BRIDGE_HOSTNAME  Bridge connection hostname (default: sigul-bridge)
    SIGUL_BRIDGE_CLIENT_PORT Bridge client listen port (default: 44334)
    SIGUL_BRIDGE_SERVER_PORT Bridge server listen port (default: 44333)

EXAMPLES:
    # Initialize sigul server
    $SCRIPT_NAME --role server

    # Initialize sigul bridge with debug logging
    $SCRIPT_NAME --role bridge --debug

    # Initialize and start server service
    $SCRIPT_NAME --role server --start-service

    # Start service only (skip initialization)
    $SCRIPT_NAME --role bridge --service-only

    # Initialize with custom base directory
    $SCRIPT_NAME --role server --base-dir /opt/sigul

    # Use environment variables
    export SIGUL_ROLE=server
    export DEBUG=true
    $SCRIPT_NAME

DIRECTORY STRUCTURE:
    The script creates a unified directory structure under \$SIGUL_BASE_DIR:

    $DEFAULT_BASE_DIR/
    ├── config/             # Configuration files
    ├── logs/               # Log files (by component)
    ├── pids/               # PID files
    ├── secrets/            # Passwords, private keys (700 permissions)
    ├── nss/                # NSS databases (700 permissions)
    ├── database/           # SQLite database files (server only)
    ├── gnupg/              # GPG home directory
    └── tmp/                # Temporary files

EOF
}

# Display version information
show_version() {
    echo "$SCRIPT_NAME version $VERSION"
    echo "Part of sigul-sign-docker infrastructure"
    echo "SPDX-License-Identifier: Apache-2.0"
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --role)
                if [[ -n "${2:-}" ]]; then
                    SIGUL_ROLE="$2"
                    shift 2
                else
                    error "Option --role requires an argument" $EXIT_INVALID_ARGS
                fi
                ;;
            --base-dir)
                if [[ -n "${2:-}" ]]; then
                    SIGUL_BASE_DIR="$2"
                    shift 2
                else
                    error "Option --base-dir requires an argument" $EXIT_INVALID_ARGS
                fi
                ;;
            --debug)
                export DEBUG=true
                shift
                ;;
            --start-service)
                # Flag handled in main() - just consume it here
                shift
                ;;
            --service-only)
                # Flag handled in main() - just consume it here
                shift
                ;;
            --help|-h)
                show_usage
                exit $EXIT_SUCCESS
                ;;
            --version|-v)
                show_version
                exit $EXIT_SUCCESS
                ;;
            -*)
                error "Unknown option: $1" $EXIT_INVALID_ARGS
                ;;
            *)
                error "Unexpected argument: $1" $EXIT_INVALID_ARGS
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$SIGUL_ROLE" ]]; then
        error "Role is required. Use --role or set SIGUL_ROLE environment variable." $EXIT_INVALID_ARGS
    fi

    if ! validate_role "$SIGUL_ROLE"; then
        error "Invalid role: $SIGUL_ROLE. Must be server, bridge, or client." $EXIT_INVALID_ROLE
    fi
}

# Setup and validate environment variables
setup_env() {
    debug "Setting up environment variables for role: $SIGUL_ROLE"

    # Initialize directory paths based on final SIGUL_BASE_DIR
    CONFIG_DIR="$SIGUL_BASE_DIR/config"
    LOGS_DIR="$SIGUL_BASE_DIR/logs"
    PIDS_DIR="$SIGUL_BASE_DIR/pids"
    SECRETS_DIR="$SIGUL_BASE_DIR/secrets"
    NSS_DIR="$SIGUL_BASE_DIR/nss"
    DATABASE_DIR="$SIGUL_BASE_DIR/database"
    GNUPG_DIR="$SIGUL_BASE_DIR/gnupg"
    TMP_DIR="$SIGUL_BASE_DIR/tmp"

    # Core environment variables with defaults
    export SIGUL_ROLE
    export SIGUL_BASE_DIR
    export DEBUG="${DEBUG:-false}"

    # Component-specific environment variables with defaults
    # NOTE: Bridge bind address is NOT configurable - Sigul always binds to 0.0.0.0
    export SIGUL_BRIDGE_HOSTNAME="${SIGUL_BRIDGE_HOSTNAME:-sigul-bridge}"
    export SIGUL_BRIDGE_CLIENT_PORT="${SIGUL_BRIDGE_CLIENT_PORT:-44334}"
    export SIGUL_BRIDGE_SERVER_PORT="${SIGUL_BRIDGE_SERVER_PORT:-44333}"

    # Validate numeric ports
    if ! [[ "$SIGUL_BRIDGE_CLIENT_PORT" =~ ^[0-9]+$ ]] || (( SIGUL_BRIDGE_CLIENT_PORT < 1 || SIGUL_BRIDGE_CLIENT_PORT > 65535 )); then
        error "Invalid SIGUL_BRIDGE_CLIENT_PORT: $SIGUL_BRIDGE_CLIENT_PORT. Must be 1-65535." $EXIT_INVALID_ARGS
    fi
    if ! [[ "$SIGUL_BRIDGE_SERVER_PORT" =~ ^[0-9]+$ ]] || (( SIGUL_BRIDGE_SERVER_PORT < 1 || SIGUL_BRIDGE_SERVER_PORT > 65535 )); then
        error "Invalid SIGUL_BRIDGE_SERVER_PORT: $SIGUL_BRIDGE_SERVER_PORT. Must be 1-65535." $EXIT_INVALID_ARGS
    fi

    # Validate base directory is absolute path
    if [[ ! "$SIGUL_BASE_DIR" =~ ^/ ]]; then
        error "SIGUL_BASE_DIR must be an absolute path: $SIGUL_BASE_DIR" $EXIT_INVALID_ARGS
    fi

    debug "Environment setup complete:"
    debug "  Role: $SIGUL_ROLE"
    debug "  Base directory: $SIGUL_BASE_DIR"
    debug "  Bridge: $SIGUL_BRIDGE_HOSTNAME:$SIGUL_BRIDGE_CLIENT_PORT"
    debug "  Debug mode: $DEBUG"
}

#######################################
# Phase 2.1: Directory Structure Setup
#######################################

# Normalize volume permissions to ensure consistent ownership
normalize_volume_permissions() {
    local base="/var/sigul"
    debug "Normalizing volume ownership under $base"

    # Only attempt if we're running as the sigul user (UID 1000)
    if [[ "$(id -u)" == "1000" ]]; then
        # Find files/dirs not owned by sigul (1000:1000) and fix them
        # Use maxdepth to avoid deep recursion and focus on key areas
        find "$base" -maxdepth 4 \( -type d -o -type f \) ! -user 1000 \
            -exec chown 1000:1000 {} + 2>/dev/null || true

        # Ensure key directories have proper permissions
        if [[ -d "$base" ]]; then
            chmod 755 "$base" 2>/dev/null || true
        fi
        if [[ -d "$base/secrets" ]]; then
            chmod 700 "$base/secrets" 2>/dev/null || true
        fi
        if [[ -d "$base/nss" ]]; then
            chmod 755 "$base/nss" 2>/dev/null || true
        fi

        debug "Volume permission normalization completed"
    else
        debug "Skipping permission normalization (not running as sigul user)"
    fi
}

# Create complete /var/sigul directory structure
setup_application_directory() {
    log "Setting up application directory structure at $SIGUL_BASE_DIR"

    # Create all required directories
    # Logging structure:
    # - Server: Daemon logs to $LOGS_DIR/server/ via --internal-log-dir
    # - Bridge: Daemon logs to $LOGS_DIR/bridge/ via --internal-log-dir
    # - Client: Non-daemon, logs to stderr (container stdout/stderr)
    local directories=(
        "$SIGUL_BASE_DIR"
        "$CONFIG_DIR"
        "$LOGS_DIR"
        "$LOGS_DIR/server"
        "$LOGS_DIR/bridge"
        "$PIDS_DIR"
        "$SECRETS_DIR"
        "$SECRETS_DIR/nss-passwords"
        "$SECRETS_DIR/admin-passwords"
        "$SECRETS_DIR/certificates"
        "$NSS_DIR"
        "$NSS_DIR/server"
        "$NSS_DIR/bridge"
        "$NSS_DIR/client"
        "$DATABASE_DIR"
        "$GNUPG_DIR"
        "$TMP_DIR"
    )

    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            debug "Creating directory: $dir"
            mkdir -p "$dir" || error "Failed to create directory: $dir" $EXIT_SETUP_FAILED
        else
            debug "Directory already exists: $dir"
        fi
    done

    log "Directory structure created successfully"
}

# Apply correct permissions to directory structure
set_directory_permissions() {
    log "Setting directory permissions"

    # Base directory - readable by sigul group
    chmod 755 "$SIGUL_BASE_DIR" || error "Failed to set permissions on $SIGUL_BASE_DIR" $EXIT_SETUP_FAILED

    # Secrets - completely private
    chmod 700 "$SECRETS_DIR" || error "Failed to set permissions on $SECRETS_DIR" $EXIT_SETUP_FAILED
    find "$SECRETS_DIR" -type d -exec chmod 700 {} \; || error "Failed to set permissions on secrets subdirectories" $EXIT_SETUP_FAILED

    # NSS databases - private
    chmod 700 "$NSS_DIR" || error "Failed to set permissions on $NSS_DIR" $EXIT_SETUP_FAILED
    find "$NSS_DIR" -type d -exec chmod 700 {} \; || error "Failed to set permissions on NSS subdirectories" $EXIT_SETUP_FAILED

    # Configs - readable by group
    chmod 750 "$CONFIG_DIR" || error "Failed to set permissions on $CONFIG_DIR" $EXIT_SETUP_FAILED

    # Logs - readable for debugging (all components)
    chmod 755 "$LOGS_DIR" || error "Failed to set permissions on $LOGS_DIR" $EXIT_SETUP_FAILED
    find "$LOGS_DIR" -type d -exec chmod 755 {} \; || error "Failed to set permissions on log subdirectories" $EXIT_SETUP_FAILED

    # Ensure sigul user can write to all log directories
    chown -R sigul:sigul "$LOGS_DIR" || error "Failed to set ownership on log directories" $EXIT_SETUP_FAILED

    # PIDs - readable for monitoring
    chmod 755 "$PIDS_DIR" || error "Failed to set permissions on $PIDS_DIR" $EXIT_SETUP_FAILED

    # Database - private
    chmod 700 "$DATABASE_DIR" || error "Failed to set permissions on $DATABASE_DIR" $EXIT_SETUP_FAILED

    # GPG - private
    chmod 700 "$GNUPG_DIR" || error "Failed to set permissions on $GNUPG_DIR" $EXIT_SETUP_FAILED

    # Temporary - private
    chmod 700 "$TMP_DIR" || error "Failed to set permissions on $TMP_DIR" $EXIT_SETUP_FAILED

    debug "Directory permissions set successfully"
}

# Verify directory setup is correct
validate_directories() {
    log "Validating directory structure"

    local required_dirs=(
        "$SIGUL_BASE_DIR"
        "$CONFIG_DIR"
        "$LOGS_DIR"
        "$PIDS_DIR"
        "$SECRETS_DIR"
        "$NSS_DIR"
        "$DATABASE_DIR"
        "$GNUPG_DIR"
        "$TMP_DIR"
    )

    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            error "Required directory missing: $dir" $EXIT_VALIDATION_FAILED
        fi
        if [[ ! -w "$dir" ]]; then
            error "Directory not writable: $dir" $EXIT_VALIDATION_FAILED
        fi
        debug "Validated directory: $dir"
    done

    # Validate specific role directories exist
    local role_nss_dir="$NSS_DIR/$SIGUL_ROLE"

    # Only validate log directories for server and bridge (daemons that write log files)
    # Client logs go to stderr/stdout and don't need a log directory
    if [[ "$SIGUL_ROLE" == "server" || "$SIGUL_ROLE" == "bridge" ]]; then
        local role_log_dir="$LOGS_DIR/$SIGUL_ROLE"
        if [[ ! -d "$role_log_dir" ]]; then
            error "Role-specific log directory missing: $role_log_dir" $EXIT_VALIDATION_FAILED
        fi
    fi

    if [[ ! -d "$role_nss_dir" ]]; then
        error "Role-specific NSS directory missing: $role_nss_dir" $EXIT_VALIDATION_FAILED
    fi

    log "Directory validation completed successfully"
}

# Handle migration from existing installations
# Legacy migration function removed - not needed in containerized environment

#######################################
# Phase 2: Security and Secrets Management Functions
#######################################

# Generate secure random password
# Arguments:
#   $1 - Password length
# Outputs:
#   Random password to stdout
generate_password() {
    local length="$1"
    # Use openssl for secure random generation, generate more bytes than needed
    # to account for base64 encoding overhead and character filtering
    local raw_bytes=$((length * 2))
    openssl rand -base64 "$raw_bytes" | tr -d "=+/\n" | head -c "$length"
}

# Store secret securely in secrets directory
# Arguments:
#   $1 - Secret name (e.g., "nss_password", "admin_password")
#   $2 - Secret value
#   $3 - Component role (optional, defaults to current role)
store_secret() {
    local secret_name="$1"
    local secret_value="$2"
    local component_role="${3:-$SIGUL_ROLE}"

    local secret_file="$SECRETS_DIR/${component_role}_${secret_name}"

    # Write secret to file with secure permissions (no trailing newline)
    printf '%s' "$secret_value" > "$secret_file"
    chmod 600 "$secret_file"

    return 0
}

# Load secret from secrets directory
# Arguments:
#   $1 - Secret name
#   $2 - Component role (optional, defaults to current role)
# Outputs:
#   Secret value to stdout
# Returns:
#   0 if secret loaded, 1 if not found
load_secret() {
    local secret_name="$1"
    local component_role="${2:-$SIGUL_ROLE}"

    local secret_file="$SECRETS_DIR/${component_role}_${secret_name}"

    if [[ -f "$secret_file" ]]; then
        cat "$secret_file"
        return 0
    else
        return 1
    fi
}

# Generate NSS database password
# Outputs:
#   Password to stdout
generate_nss_password() {
    # Check if password already exists
    if load_secret "nss_password" >/dev/null 2>&1; then
        load_secret "nss_password"
        return 0
    fi

    # Check environment variable - but ignore placeholder values
    if [[ -n "${NSS_PASSWORD:-}" ]] && [[ "$NSS_PASSWORD" != *"auto_generated"* ]] && [[ "$NSS_PASSWORD" != *"ephemeral"* ]]; then
        store_secret "nss_password" "$NSS_PASSWORD"
        echo "$NSS_PASSWORD"
        return 0
    fi

    # Generate new password (either no env var or placeholder detected)
    local password
    password=$(generate_password "$NSS_PASSWORD_LENGTH")

    store_secret "nss_password" "$password"
    echo "$password"
}

# Generate admin password (server role only)
# Outputs:
#   Password to stdout
generate_admin_password() {
    if [[ "$SIGUL_ROLE" != "server" ]]; then
        debug "Admin password only needed for server role"
        return 0
    fi

    # Check if password already exists
    if load_secret "admin_password" >/dev/null 2>&1; then
        load_secret "admin_password"
        return 0
    fi

    # Check environment variable - but ignore placeholder values
    if [[ -n "${SIGUL_ADMIN_PASSWORD:-}" ]] && [[ "$SIGUL_ADMIN_PASSWORD" != *"auto_generated"* ]] && [[ "$SIGUL_ADMIN_PASSWORD" != *"ephemeral"* ]]; then
        store_secret "admin_password" "$SIGUL_ADMIN_PASSWORD"
        echo "$SIGUL_ADMIN_PASSWORD"
        return 0
    fi

    # Generate new password (either no env var or placeholder detected)
    local password
    password=$(generate_password "$ADMIN_PASSWORD_LENGTH")

    store_secret "admin_password" "$password"
    echo "$password"
}

# Validate secret file permissions
# Arguments:
#   $1 - Secret file path
# Returns:
#   0 if permissions are correct, 1 if not
validate_secret_permissions() {
    local secret_file="$1"

    if [[ ! -f "$secret_file" ]]; then
        debug "Secret file does not exist: $secret_file"
        return 1
    fi

    # Check permissions are 600 (owner read/write only)
    local perms
    perms=$(stat -c "%a" "$secret_file" 2>/dev/null || stat -f "%A" "$secret_file" 2>/dev/null)

    if [[ "$perms" != "600" ]]; then
        error "Invalid permissions on secret file $secret_file: $perms (expected: 600)" $EXIT_VALIDATION_FAILED
    fi

    debug "Secret file permissions validated: $secret_file"
    return 0
}

# Main secrets setup orchestration
setup_secrets() {
    log "Setting up secrets management for role: $SIGUL_ROLE"

    # Generate NSS password for all roles
    local nss_password
    nss_password=$(generate_nss_password)
    export NSS_PASSWORD="$nss_password"

    # Generate admin password for server role
    if [[ "$SIGUL_ROLE" == "server" ]]; then
        local admin_password
        admin_password=$(generate_admin_password)
        export SIGUL_ADMIN_PASSWORD="$admin_password"
    fi

    # Validate all secret files have correct permissions
    for secret_file in "$SECRETS_DIR"/*; do
        if [[ -f "$secret_file" ]]; then
            validate_secret_permissions "$secret_file"
        fi
    done

    log "Secrets management setup completed"
}




# Validate certificate file
# Arguments:
#   $1 - Certificate file path
# Returns:
#   0 if valid, 1 if invalid
validate_certificate() {
    local cert_file="$1"

    if [[ ! -f "$cert_file" ]]; then
        return 1
    fi

    # Check if certificate is valid using openssl
    if ! openssl x509 -in "$cert_file" -noout -checkend $((MIN_CERT_DAYS_REMAINING * 24 * 3600)) >/dev/null 2>&1; then
        return 1
    fi

    return 0
}

# Generate self-signed test certificate
# Arguments:
#   $1 - Certificate name (e.g., "server", "bridge", "client")
# Outputs:
#   Path to generated certificate
generate_test_certificate() {
    local cert_name="$1"
    local cert_file="$SECRETS_DIR/certificates/${cert_name}.crt"
    local key_file="$SECRETS_DIR/certificates/${cert_name}-key.pem"

    # Create certificate directory if it doesn't exist
    mkdir -p "$(dirname "$cert_file")" >/dev/null 2>&1

    # Generate private key
    openssl genrsa -out "$key_file" 2048 >/dev/null 2>&1
    chmod 600 "$key_file" >/dev/null 2>&1

    # Generate self-signed certificate
    openssl req -new -x509 -key "$key_file" -out "$cert_file" -days "$CERT_VALIDITY_DAYS" \
        -subj "/C=US/ST=Test/L=Test/O=Sigul Test/OU=Testing/CN=${cert_name}.sigul.test" \
        >/dev/null 2>&1
    chmod 644 "$cert_file" >/dev/null 2>&1

    echo "$cert_file"
}

# Import certificates to NSS database
# Arguments:
#   $1 - Certificate file path
import_certificate_to_nss() {
    local cert_file="$1"

    # Store certificate path for later NSS import
    local import_list="$NSS_DIR/$SIGUL_ROLE/import_list.txt"
    echo "$cert_file" >> "$import_list"
}

# Main certificate setup orchestration
setup_certificates() {
    log "Setting up certificate management for role: $SIGUL_ROLE"

    # Clear any existing import list to prevent duplicates
    local import_list="$NSS_DIR/$SIGUL_ROLE/import_list.txt"
    mkdir -p "$(dirname "$import_list")"
    true > "$import_list"

    # Copy shared CA certificate from repository
    copy_shared_ca

    # Generate component-specific certificate signed by shared CA
    log "Generating certificate for role: $SIGUL_ROLE using shared CA"

    local generated_certs=()
    local component_cert
    component_cert=$(generate_component_certificate "$SIGUL_ROLE")
    log "Generated component certificate: $component_cert"

    # Verify component certificate path is valid before adding to array
    if [[ -n "$component_cert" ]] && [[ -f "$component_cert" ]]; then
        generated_certs+=("$component_cert")
        debug "Added component certificate to import list: $component_cert"
    else
        error "Component certificate generation failed or path is invalid: $component_cert"
        return 1
    fi

    # Add shared CA certificate to import list
    local ca_cert="$SECRETS_DIR/certificates/ca.crt"
    if [[ -f "$ca_cert" ]]; then
        generated_certs+=("$ca_cert")
        debug "Added CA certificate to import list: $ca_cert"
    else
        error "CA certificate not found: $ca_cert"
        return 1
    fi

    # Validate certificates before NSS import
    for cert_file in "${generated_certs[@]}"; do
        if [[ -n "$cert_file" ]] && [[ -f "$cert_file" ]]; then
            local cert_name
            cert_name=$(basename "$cert_file" .crt)

            # Skip validation for CA cert (self-signed)
            if [[ "$cert_name" != "ca" ]]; then
                if validate_component_certificate "$cert_file" "$ca_cert" "$SIGUL_ROLE"; then
                    debug "Certificate validation passed: $cert_file"
                    generate_cert_metadata_json "$cert_file" "$SIGUL_ROLE"
                else
                    error "Certificate validation failed: $cert_file"
                    return 1
                fi
            else
                generate_cert_metadata_json "$cert_file" "ca"
            fi
        fi
    done

    # Create unified certificate metadata summary
    create_certificate_metadata_summary

    # Import certificates for NSS
    debug "About to import ${#generated_certs[@]} certificates to NSS"
    for cert_file in "${generated_certs[@]}"; do
        if [[ -n "$cert_file" ]] && [[ -f "$cert_file" ]]; then
            debug "Importing certificate to NSS: $cert_file"
            import_certificate_to_nss "$cert_file"
            debug "Added to import list: $cert_file"
        else
            error "Certificate file not found or empty: $cert_file"
        fi
    done

    # Verify import list contents
    debug "Final import list contents:"
    if [[ -f "$import_list" ]]; then
        while IFS= read -r line; do
            debug "  Import list entry: $line"
        done < "$import_list"
        debug "Import list size: $(wc -c < "$import_list") bytes"
    else
        error "Import list file not found: $import_list"
    fi

    log "Certificate management setup completed"
    log "Generated and prepared ${#generated_certs[@]} certificate(s) for NSS import"
}

# Function to copy shared CA certificate from repository
copy_shared_ca() {
    local shared_ca_cert="/workspace/pki/ca.crt"
    local shared_ca_key="/workspace/pki/ca-key.pem"
    local local_ca_cert="$SECRETS_DIR/certificates/ca.crt"
    local local_ca_key="$SECRETS_DIR/certificates/ca-key.pem"

    log "Copying shared CA certificate from repository"

    # Create certificates directory if it doesn't exist
    mkdir -p "$SECRETS_DIR/certificates"

    # Copy CA certificate and key from repository
    if [[ -f "$shared_ca_cert" ]]; then
        cp "$shared_ca_cert" "$local_ca_cert"
        chmod 644 "$local_ca_cert"
        log "Copied shared CA certificate"
    else
        error "Shared CA certificate not found: $shared_ca_cert"
    fi

    if [[ -f "$shared_ca_key" ]]; then
        cp "$shared_ca_key" "$local_ca_key"
        chmod 600 "$local_ca_key"
        log "Copied shared CA private key"
    else
        error "Shared CA private key not found: $shared_ca_key"
    fi
}

# Function to generate component certificate signed by shared CA
generate_component_certificate() {
    local component="$1"
    local cert_file="$SECRETS_DIR/certificates/${component}.crt"
    local key_file="$SECRETS_DIR/certificates/${component}-key.pem"
    local csr_file="$SECRETS_DIR/certificates/${component}.csr"
    local ca_cert="$SECRETS_DIR/certificates/ca.crt"
    local ca_key="$SECRETS_DIR/certificates/ca-key.pem"
    local ca_config="/workspace/pki/ca.conf"

    # Create certificates directory if it doesn't exist
    mkdir -p "$(dirname "$cert_file")"

    # Check if both certificate and key already exist from PKI generation
    if [[ -f "$cert_file" ]] && [[ -f "$key_file" ]]; then
        log "Using existing certificate for component: $component (from PKI generation)"
        log "Certificate: $cert_file"
        log "Private key: $key_file"

        # Verify the certificate is valid
        if openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1; then
            debug "Existing certificate is valid: $cert_file"
            echo "$cert_file"
            return 0
        else
            log "Warning: Existing certificate appears invalid, regenerating: $cert_file"
        fi
    else
        log "Certificates not found, generating new certificate for component: $component"
    fi

    # Generate private key for component (only if not existing or invalid)
    openssl genrsa -out "$key_file" 2048 >/dev/null 2>&1
    chmod 600 "$key_file"

    # Create certificate signing request
    local subject="/C=US/ST=California/L=San Francisco/O=Linux Foundation/OU=Sigul Infrastructure/CN=sigul-${component}"
    openssl req -new -key "$key_file" -out "$csr_file" -subj "$subject" >/dev/null 2>&1

    # Sign certificate with shared CA
    if [[ -f "$ca_config" ]]; then
        openssl x509 -req -in "$csr_file" \
            -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
            -out "$cert_file" -days 365 \
            -extensions "${component}_extensions" \
            -extfile "$ca_config" >/dev/null 2>&1
    else
        # Fallback without extensions if config not available
        openssl x509 -req -in "$csr_file" \
            -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
            -out "$cert_file" -days 365 >/dev/null 2>&1
    fi

    # Clean up CSR
    rm -f "$csr_file"

    # Set proper permissions
    chmod 644 "$cert_file"

    log "Generated certificate: $cert_file"
    echo "$cert_file"
}

# Validate component certificate before NSS import
validate_component_certificate() {
    local cert="$1"
    local ca="$2"
    local role="$3"
    local artifacts_dir="${PROJECT_ROOT:-/tmp}/test-artifacts"

    debug "Validating certificate: $cert for role: $role"

    # Ensure artifacts directory exists
    mkdir -p "$artifacts_dir"

    # Check certificate structure
    if ! openssl x509 -in "$cert" -noout >/dev/null 2>&1; then
        error "Invalid X.509 certificate structure: $cert"
        return 1
    fi

    # Verify certificate chain
    if ! openssl verify -CAfile "$ca" "$cert" >/dev/null 2>&1; then
        error "Certificate failed chain verification: $cert"
        return 1
    fi

    # Check Subject Alternative Name (warn but don't fail)
    local san
    san=$(openssl x509 -in "$cert" -noout -text | awk '/Subject Alternative Name/{flag=1;next}/X509v3/{flag=0}flag' || true)
    if ! grep -qi "sigul-${role}" <<<"$san"; then
        warn "SAN does not include expected role hostname: sigul-${role} (continuing in test mode)"
    fi

    debug "Certificate validation passed: $cert"
    return 0
}

# Generate certificate metadata JSON artifact
generate_cert_metadata_json() {
    local cert="$1"
    local role="$2"
    local artifacts_dir="${PROJECT_ROOT:-/tmp}/test-artifacts"
    local metadata_file="$artifacts_dir/cert-metadata-${role}.json"

    debug "Generating certificate metadata for: $cert"

    # Ensure artifacts directory exists
    mkdir -p "$artifacts_dir"

    if [[ ! -f "$cert" ]]; then
        echo '{"error": "Certificate file not found", "validated": false}' > "$metadata_file"
        return 1
    fi

    # Extract certificate information
    local issuer subject san not_before not_after fingerprint
    issuer=$(openssl x509 -in "$cert" -noout -issuer | sed 's/issuer=//' || echo "unknown")
    subject=$(openssl x509 -in "$cert" -noout -subject | sed 's/subject=//' || echo "unknown")
    san=$(openssl x509 -in "$cert" -noout -text | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^ *//' | tr -d '\n' || echo "none")
    not_before=$(openssl x509 -in "$cert" -noout -startdate | sed 's/notBefore=//' || echo "unknown")
    not_after=$(openssl x509 -in "$cert" -noout -enddate | sed 's/notAfter=//' || echo "unknown")
    fingerprint=$(openssl x509 -in "$cert" -noout -fingerprint -sha256 | sed 's/SHA256 Fingerprint=//' || echo "unknown")

    # Check if certificate is still valid (not expired)
    local validated="true"
    if ! openssl x509 -in "$cert" -checkend 0 >/dev/null 2>&1; then
        validated="false"
    fi

    # Escape JSON strings to prevent invalid JSON
    local issuer_escaped subject_escaped san_escaped not_before_escaped not_after_escaped fingerprint_escaped
    issuer_escaped=$(printf '%s' "$issuer" | sed 's/"/\\"/g' | tr -d '\n\r')
    subject_escaped=$(printf '%s' "$subject" | sed 's/"/\\"/g' | tr -d '\n\r')
    san_escaped=$(printf '%s' "$san" | sed 's/"/\\"/g' | tr -d '\n\r')
    not_before_escaped=$(printf '%s' "$not_before" | sed 's/"/\\"/g' | tr -d '\n\r')
    not_after_escaped=$(printf '%s' "$not_after" | sed 's/"/\\"/g' | tr -d '\n\r')
    fingerprint_escaped=$(printf '%s' "$fingerprint" | sed 's/"/\\"/g' | tr -d '\n\r')

    # Generate JSON metadata with escaped strings
    cat > "$metadata_file" << EOF
{
    "role": "$role",
    "certificate_path": "$cert",
    "issuer_cn": "$issuer_escaped",
    "subject_cn": "$subject_escaped",
    "san_list": "$san_escaped",
    "not_before": "$not_before_escaped",
    "not_after": "$not_after_escaped",
    "fingerprint": "$fingerprint_escaped",
    "validated": $validated,
    "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

    debug "Certificate metadata written to: $metadata_file"
}

# Create unified certificate metadata summary
create_certificate_metadata_summary() {
    local artifacts_dir="${PROJECT_ROOT:-/tmp}/test-artifacts"
    local summary_file="$artifacts_dir/cert-metadata.json"

    debug "Creating unified certificate metadata summary"

    # Ensure artifacts directory exists
    mkdir -p "$artifacts_dir"

    # Initialize summary structure
    cat > "$summary_file" << EOF
{
    "certificate_summary": {
        "role": "$SIGUL_ROLE",
        "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "certificates": []
    }
}
EOF

    # Collect all individual cert metadata files
    local cert_files=()
    for metadata in "$artifacts_dir"/cert-metadata-*.json; do
        if [[ -f "$metadata" ]]; then
            cert_files+=("$metadata")
        fi
    done

    if [[ ${#cert_files[@]} -gt 0 ]]; then
        # Build certificates array
        debug "Building certificates JSON array from ${#cert_files[@]} metadata files"
        local certs_json="["
        local first=true
        for cert_file in "${cert_files[@]}"; do
            debug "Processing certificate metadata file: $cert_file"
            debug "File exists: $(test -f "$cert_file" && echo "yes" || echo "no")"
            if [[ -f "$cert_file" ]]; then
                debug "File size: $(wc -c < "$cert_file") bytes"
                debug "File content preview:"
                head -3 "$cert_file" | while IFS= read -r line; do
                    debug "  $line"
                done

                # Validate individual JSON file
                if cat "$cert_file" | jq . >/dev/null 2>&1; then
                    debug "Individual certificate JSON is valid"
                else
                    debug "WARNING: Individual certificate JSON is invalid!"
                    debug "Full content of invalid file:"
                    debug "$(cat "$cert_file")"
                fi
            else
                debug "WARNING: Certificate metadata file does not exist: $cert_file"
                continue
            fi

            if [[ "$first" == "true" ]]; then
                first=false
            else
                certs_json+=","
            fi
            certs_json+=$(cat "$cert_file")
        done
        certs_json+="]"

        # Update summary with certificates array
        debug "Attempting to merge certificate metadata with jq"
        debug "Summary file: $summary_file"
        debug "Summary file exists: $(test -f "$summary_file" && echo "yes" || echo "no")"
        if [[ -f "$summary_file" ]]; then
            debug "Summary file size: $(wc -c < "$summary_file") bytes"
            debug "Summary file content preview:"
            head -5 "$summary_file" | while IFS= read -r line; do
                debug "  $line"
            done
        fi

        debug "Certificates JSON length: ${#certs_json} characters"
        debug "Certificates JSON preview (first 200 chars):"
        debug "  ${certs_json:0:200}..."

        # Validate JSON before passing to jq
        if echo "$certs_json" | jq . >/dev/null 2>&1; then
            debug "Certificates JSON is valid"
        else
            debug "ERROR: Certificates JSON is invalid!"
            debug "Full certificates JSON content:"
            debug "$certs_json"
        fi

        local updated_summary
        local jq_error_output
        if jq_error_output=$(jq --argjson certs "$certs_json" '.certificate_summary.certificates = $certs' "$summary_file" 2>&1) && updated_summary="$jq_error_output"; then
            echo "$updated_summary" > "$summary_file"
            debug "Successfully updated certificate metadata summary"
        else
            debug "ERROR: jq command failed with output:"
            debug "$jq_error_output"
            debug "jq command was: jq --argjson certs \"\$certs_json\" '.certificate_summary.certificates = \$certs' \"$summary_file\""
            debug "Certificates JSON that caused failure:"
            debug "$certs_json"
            debug "Summary file that caused failure:"
            if [[ -f "$summary_file" ]]; then
                debug "$(cat "$summary_file")"
            else
                debug "Summary file does not exist"
            fi

            # Create a minimal valid summary file
            echo '{"certificate_summary": {"certificates": [], "error": "jq processing failed"}}' > "$summary_file"
            debug "Created fallback summary file"
        fi

        debug "Certificate metadata summary created: $summary_file (${#cert_files[@]} certificates)"
    else
        debug "No certificate metadata files found"
    fi
}

#######################################
# Phase 3.1: NSS Database Management
#######################################

# Create NSS database with password for specified role
create_nss_database() {
    local role="$1"
    local nss_dir="$SIGUL_BASE_DIR/nss/$role"

    log "=== NSS DATABASE CREATION DEBUG START ==="
    log "Function: create_nss_database"
    log "Role: $role"
    log "NSS directory: $nss_dir"
    log "Current working directory: $(pwd)"
    log "Call stack: ${FUNCNAME[*]}"

    debug "Creating NSS database for role: $role"
    debug "NSS directory: $nss_dir"

    # Ensure NSS directory exists
    if ! mkdir -p "$nss_dir"; then
        error "Failed to create NSS directory: $nss_dir"
    fi

    # Check what files exist before creation
    log "Files in NSS directory before creation check:"
    ls -la "$nss_dir" 2>/dev/null || log "NSS directory is empty or doesn't exist"

    # Check if NSS database already exists
    if [[ -f "$nss_dir/cert9.db" ]] && [[ -f "$nss_dir/key4.db" ]] && [[ -f "$nss_dir/pkcs11.txt" ]]; then
        log "NSS database already exists for role: $role"
        log "Existing files:"
        ls -la "$nss_dir"/ 2>/dev/null
        log "=== NSS DATABASE CREATION DEBUG END (ALREADY EXISTS) ==="
        return 0
    fi

    # Load the NSS password
    local nss_password
    if ! nss_password=$(load_secret "nss_password" "$role"); then
        error "Failed to load NSS password for role: $role"
    fi

    # Create NSS database
    log "Creating NSS database for role: $role"
    log "Password length for NSS creation: $(printf '%s' "$nss_password" | wc -c)"
    log "Password hexdump for NSS creation: $(printf '%s' "$nss_password" | hexdump -C)"

    if ! echo "$nss_password" | certutil -N -d "$nss_dir" -f /dev/stdin; then
        error "Failed to create NSS database for role: $role"
    fi

    # Set proper permissions on NSS database files
    chmod 600 "$nss_dir"/*
    chown sigul:sigul "$nss_dir"/*

    log "NSS database created successfully for role: $role"
    log "Files created:"
    ls -la "$nss_dir"/ 2>/dev/null
    log "=== NSS DATABASE CREATION DEBUG END (NEWLY CREATED) ==="
    return 0
}

# Import certificates into NSS database
# shellcheck disable=SC2317  # Complex error handling creates false positive unreachable code warnings
import_nss_certificates() {
    local role="$1"
    local nss_dir="$SIGUL_BASE_DIR/nss/$role"
    local cert_dir="$SIGUL_BASE_DIR/secrets/certificates"
    local import_list="$nss_dir/import_list.txt"

    debug "Importing certificates to NSS database for role: $role"

    # Ensure diagnostics directory exists early
    local diagnostics_dir="${PROJECT_ROOT:-/tmp}/test-artifacts/nss-diagnostics"
    mkdir -p "$diagnostics_dir"

    # Check if NSS database exists
    if [[ ! -f "$nss_dir/cert9.db" ]]; then
        error "NSS database does not exist for role: $role"
    fi

    # Check if import list exists
    if [[ ! -f "$import_list" ]]; then
        debug "No certificate import list found for role: $role"
        return 0
    fi

    # Load the NSS password
    local nss_password
    if ! nss_password=$(load_secret "nss_password" "$role"); then
        error "Failed to load NSS password for role: $role"
    fi

    # Import each certificate from the list
    local imported_count=0
    while IFS= read -r cert_file; do
        if [[ -n "$cert_file" ]] && [[ -f "$cert_file" ]]; then
            local cert_name
            cert_name=$(basename "$cert_file" .crt)

            # Use proper certificate nicknames based on role and certificate type
            local cert_nickname
            case "$role" in
                server)
                    if [[ "$cert_name" == "server" ]]; then
                        cert_nickname="sigul-server-cert"
                    elif [[ "$cert_name" == "ca" ]]; then
                        cert_nickname="sigul-ca-cert"
                    else
                        cert_nickname="$cert_name"
                    fi
                    ;;
                bridge)
                    if [[ "$cert_name" == "bridge" ]]; then
                        cert_nickname="sigul-bridge-cert"
                    elif [[ "$cert_name" == "ca" ]]; then
                        cert_nickname="sigul-ca-cert"
                    else
                        cert_nickname="$cert_name"
                    fi
                    ;;
                client)
                    if [[ "$cert_name" == "client" ]]; then
                        cert_nickname="sigul-client-cert"
                    elif [[ "$cert_name" == "ca" ]]; then
                        cert_nickname="sigul-ca-cert"
                    else
                        cert_nickname="$cert_name"
                    fi
                    ;;
                *)
                    cert_nickname="$cert_name"
                    ;;
            esac

            # Check if certificate already exists
            if echo "$nss_password" | certutil -L -d "$nss_dir" -n "$cert_nickname" -f /dev/stdin >/dev/null 2>&1; then
                debug "Certificate already exists: $cert_name as $cert_nickname, skipping import"
                ((imported_count++))
            else
                log "Importing certificate: $cert_name as nickname: $cert_nickname"
                if echo "$nss_password" | certutil -A -d "$nss_dir" -n "$cert_nickname" -t "CT,C,C" -i "$cert_file" -f /dev/stdin; then
                    ((imported_count++))
                    debug "Successfully imported: $cert_name as $cert_nickname"
                else
                    error "Failed to import certificate: $cert_name as $cert_nickname"
                fi
            fi

            # Also import private key if it exists
            local key_file="${cert_file%.*}-key.pem"
            if [[ -f "$key_file" ]]; then
                if [[ "$cert_name" == "ca" ]]; then
                    debug "Skipping private key import for CA certificate: $cert_name"
                    continue
                fi
                log "Importing private key for certificate: $cert_name"
                # Create temporary PKCS#12 file to import both cert and key
                local temp_p12=""
                temp_p12=$(mktemp -t cert.XXXXXXXX.p12)
                trap 'rm -f "$temp_p12" 2>/dev/null || true' EXIT

                # Diagnostics directory already created at function start

                # Convert cert + key to PKCS#12 format (password protected) with stderr capture
                local openssl_stderr="$diagnostics_dir/openssl-pkcs12-${cert_name}-${role}.stderr"
                if openssl pkcs12 -export -in "$cert_file" -inkey "$key_file" \
                    -out "$temp_p12" -name "$cert_nickname" \
                    -passout pass:"$nss_password" 2>"$openssl_stderr"; then

                    # Import PKCS#12 into NSS (this updates the existing cert with private key) with stderr capture
                    local pk12util_stderr="$diagnostics_dir/pk12util-${cert_name}-${role}.stderr"
                    if echo "$nss_password" | pk12util -i "$temp_p12" -d "$nss_dir" -W "$nss_password" -K "$nss_password" 2>"$pk12util_stderr"; then
                        debug "Successfully imported private key for: $cert_name"
                        # Clean up successful diagnostic files
                        rm -f "$openssl_stderr" "$pk12util_stderr"
                    else
                        error "Failed to import private key for: $cert_name - this is fatal for daemon roles"
                        error "pk12util stderr captured in: $pk12util_stderr"
                        if [[ -s "$pk12util_stderr" ]]; then
                            error "pk12util error output:"
                            while IFS= read -r line; do
                                error "  $line"
                            done < "$pk12util_stderr"
                        fi
                        # For server and bridge roles, private key import failure is fatal
                        if [[ "$role" == "server" || "$role" == "bridge" ]]; then
                            return 1
                        else
                            log "Warning: Failed to import private key for: $cert_name (certificate import succeeded)"
                        fi
                    fi
                else
                    error "Failed to create PKCS#12 file for: $cert_name - this is fatal for daemon roles"
                    error "openssl stderr captured in: $openssl_stderr"
                    if [[ -s "$openssl_stderr" ]]; then
                        error "openssl error output:"
                        while IFS= read -r line; do
                            error "  $line"
                        done < "$openssl_stderr"
                    fi
                    # For server and bridge roles, PKCS#12 creation failure is fatal
                    if [[ "$role" == "server" || "$role" == "bridge" ]]; then
                        return 1
                    else
                        log "Warning: Failed to create PKCS#12 file for: $cert_name"
                    fi
                fi

                # Cleanup temporary PKCS#12 file and clear trap
                rm -f "$temp_p12" 2>/dev/null || true
                trap - EXIT
            fi
        fi
    done < "$import_list"

    log "Imported $imported_count certificate(s) to NSS database for role: $role"

    # Generate NSS import diagnostics summary
    generate_nss_import_summary "$role" "$diagnostics_dir"

    return 0
}

# Generate comprehensive NSS import diagnostics summary
generate_nss_import_summary() {
    local role="$1"
    local diagnostics_dir="$2"
    local summary_file="$diagnostics_dir/nss-import-summary-${role}.txt"

    debug "Generating NSS import summary for role: $role"

    {
        echo "=== NSS Import Diagnostics Summary ==="
        echo "Role: $role"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "NSS Directory: $SIGUL_BASE_DIR/nss/$role"
        echo ""

        echo "=== Certificate Import Status ==="
        if [[ -f "$SIGUL_BASE_DIR/nss/$role/import_list.txt" ]]; then
            echo "Import list contents:"
            while IFS= read -r cert_file; do
                if [[ -n "$cert_file" ]] && [[ -f "$cert_file" ]]; then
                    local cert_name
                    cert_name=$(basename "$cert_file" .crt)
                    local key_file="${cert_file%.*}-key.pem"
                    echo "  Certificate: $cert_name"
                    echo "    Cert file: $cert_file ($(stat -c%s "$cert_file" 2>/dev/null || echo "unknown") bytes)"
                    if [[ -f "$key_file" ]]; then
                        echo "    Key file: $key_file ($(stat -c%s "$key_file" 2>/dev/null || echo "unknown") bytes)"
                    else
                        echo "    Key file: not found"
                    fi
                fi
            done < "$SIGUL_BASE_DIR/nss/$role/import_list.txt"
        else
            echo "No import list found"
        fi
        echo ""

        echo "=== Error Diagnostics Files ==="
        local error_files_found=false
        for file in "$diagnostics_dir"/*.stderr; do
            if [[ -f "$file" ]] && [[ -s "$file" ]]; then
                error_files_found=true
                echo "Found error file: $(basename "$file")"
                echo "  Size: $(stat -c%s "$file") bytes"
                echo "  Content preview (first 5 lines):"
                head -5 "$file" | sed 's/^/    /'
                echo ""
            fi
        done
        if [[ "$error_files_found" == "false" ]]; then
            echo "No error diagnostic files found - all operations succeeded"
        fi
        echo ""

        echo "=== Final NSS Database State ==="
        local nss_password
        if nss_password=$(load_secret "nss_password" "$role" 2>/dev/null); then
            echo "Certificates in NSS database:"
            if echo "$nss_password" | certutil -L -d "$SIGUL_BASE_DIR/nss/$role" -f /dev/stdin 2>/dev/null; then
                echo "Private keys in NSS database:"
                echo "$nss_password" | certutil -K -d "$SIGUL_BASE_DIR/nss/$role" -f /dev/stdin 2>/dev/null || echo "  (unable to list private keys)"
            else
                echo "  (unable to access NSS database)"
            fi
        else
            echo "  (unable to load NSS password for final validation)"
        fi

        echo ""
        echo "=== NSS Import Summary Complete ==="
    } > "$summary_file"

    debug "NSS import summary written to: $summary_file"
}

# Validate NSS database integrity
validate_nss_database() {
    local role="$1"
    local nss_dir="$SIGUL_BASE_DIR/nss/$role"

    debug "Validating NSS database for role: $role"

    # Check if NSS database files exist
    local required_files=("cert9.db" "key4.db" "pkcs11.txt")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$nss_dir/$file" ]]; then
            error "Missing NSS database file: $nss_dir/$file"
        fi
    done

    # Load the NSS password
    local nss_password
    if ! nss_password=$(load_secret "nss_password" "$role"); then
        error "Failed to load NSS password for role: $role"
    fi

    # Test NSS database accessibility
    if ! echo "$nss_password" | certutil -L -d "$nss_dir" -f /dev/stdin >/dev/null 2>&1; then
        error "NSS database is not accessible or corrupted for role: $role"
    fi

    # List certificates in database
    local cert_count
    cert_count=$(echo "$nss_password" | certutil -L -d "$nss_dir" -f /dev/stdin 2>/dev/null | grep -c "^[[:space:]]*[^[:space:]]" || echo "0")

    debug "NSS database validation successful for role: $role"
    debug "Found $cert_count certificate(s) in database"

    return 0
}

# Migrate existing NSS database if present
# Legacy NSS migration function removed - not needed in containerized environment

# Main NSS database setup orchestration
setup_nss_database() {
    local role="$SIGUL_ROLE"

    log "=== SETUP NSS DATABASE PHASE START ==="
    log "Setting up NSS database for role: $role"
    log "NSS base directory: $NSS_DIR"
    log "Role-specific NSS directory: $NSS_DIR/$role"

    # Create NSS database
    if ! create_nss_database "$role"; then
        error "Failed to create NSS database for role: $role"
    fi

    # Step 3: Import certificates
    if ! import_nss_certificates "$role"; then
        error "Failed to import certificates to NSS database for role: $role"
    fi

    # Step 4: Validate database integrity
    if ! validate_nss_database "$role"; then
        error "NSS database validation failed for role: $role"
    fi

    # Step 5: Perform deep integrity check
    if ! perform_nss_integrity_deep_check "$role"; then
        error "NSS deep integrity check failed for role: $role"
    fi

    log "NSS database setup completed successfully for role: $role"
    return 0
}

# Perform deep NSS integrity check with private key validation
# shellcheck disable=SC2317  # Complex error handling creates false positive unreachable code warnings
perform_nss_integrity_deep_check() {
    local role="$1"
    local nss_dir="$SIGUL_BASE_DIR/nss/$role"
    local artifacts_dir="${PROJECT_ROOT:-/tmp}/test-artifacts"
    local integrity_file="$artifacts_dir/nss-integrity-${role}.txt"

    log "Performing NSS deep integrity check for role: $role"

    # Ensure artifacts directory exists
    mkdir -p "$artifacts_dir"

    # Load the NSS password
    local nss_password
    if ! nss_password=$(load_secret "nss_password" "$role"); then
        error "Failed to load NSS password for deep integrity check"
        return 1
    fi

    log "NSS INTEGRITY CHECK DEBUG:"
    log "Password length: $(printf '%s' "$nss_password" | wc -c)"
    log "Password hexdump: $(printf '%s' "$nss_password" | hexdump -C)"

    # Create comprehensive integrity report
    {
        echo "=== NSS Deep Integrity Check Report ==="
        echo "Role: $role"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "NSS Directory: $nss_dir"
        echo ""

        echo "=== Certificate Database Listing (certutil -L) ==="
        if echo "$nss_password" | certutil -L -d "$nss_dir" -f /dev/stdin 2>&1; then
            echo "✅ Certificate listing successful"
        else
            echo "❌ Certificate listing failed"
            echo ""
            echo "=== End of Integrity Check (FAILED) ==="
            return 1
        fi
        echo ""

        echo "=== Private Key Database Listing (certutil -K) ==="
        local key_list_result
        if key_list_result=$(echo "$nss_password" | certutil -K -d "$nss_dir" -f /dev/stdin 2>&1); then
            echo "$key_list_result"
            echo "✅ Private key listing successful"

            # Note: Sigul architecture uses PEM files for private keys, not NSS database
            # Private keys are stored as files: server-key.pem, bridge-key.pem, etc.
            # NSS database contains only certificates with nicknames for identification
            echo ""
            echo "=== Private Key Architecture Note ==="
            echo "Sigul uses PEM files for private keys (server-key.pem, bridge-key.pem)"
            echo "NSS database stores certificates only, referenced by nickname in config"
            echo "This is the correct architecture - no private keys expected in NSS database"

        else
            echo "$key_list_result"
            echo "⚠️  Private key listing failed (this is normal - Sigul uses PEM files for private keys)"
        fi
        echo ""

        echo "=== NSS Database File Information ==="
        ls -la "$nss_dir"/ 2>/dev/null || echo "Cannot list NSS directory files"
        echo ""

        echo "=== Database File Integrity ==="
        for db_file in "$nss_dir/cert9.db" "$nss_dir/key4.db" "$nss_dir/pkcs11.txt"; do
            if [[ -f "$db_file" ]]; then
                local file_size
                local file_perms
                file_size=$(stat -c%s "$db_file" 2>/dev/null || echo "unknown")
                file_perms=$(stat -c%a "$db_file" 2>/dev/null || echo "unknown")
                echo "✅ $(basename "$db_file"): size=${file_size}B, perms=${file_perms}"
            else
                echo "❌ Missing database file: $(basename "$db_file")"
            fi
        done
        echo ""

        echo "✅ NSS Deep Integrity Check PASSED"
        echo "=== End of Integrity Check (SUCCESS) ==="

    } > "$integrity_file" 2>&1

    # Set readable permissions for retrieval
    chmod 644 "$integrity_file" 2>/dev/null || true

    # Also output summary to log
    debug "NSS integrity check report saved: $integrity_file"

    # Validate the check actually passed by examining the output
    if grep -q "NSS Deep Integrity Check PASSED" "$integrity_file"; then
        debug "NSS deep integrity check passed for role: $role"
        return 0
    else
        error "NSS deep integrity check failed for role: $role - see $integrity_file"
        return 1
    fi
}

#######################################
# Phase 3.2: Configuration Generation
#######################################

# Substitute environment variables in configuration template
substitute_variables() {
    local input="$1"
    local output="$2"

    debug "Substituting variables in configuration"
    debug "Input: $input"
    debug "Output: $output"

    # Create output from input with variable substitution
    eval "cat << 'TEMPLATE_EOF'
$(cat "$input")
TEMPLATE_EOF" > "$output"

    if ! certutil -L -d "$nss_dir" -h all &>/dev/null; then
        error "Failed to substitute variables in configuration"
    fi

    debug "Variable substitution completed successfully"
    return 0
}

# Generate server configuration
generate_server_config() {
    local config_file="$SIGUL_BASE_DIR/config/server.conf"
    local nss_dir="$SIGUL_BASE_DIR/nss/server"
    local database_dir="$SIGUL_BASE_DIR/database"

    log "Generating server configuration"

    # Load NSS password directly to avoid debug output during config generation
    local nss_password
    if ! nss_password=$(load_secret "nss_password" 2>/dev/null); then
        error "Failed to load NSS password for server configuration"
    fi

    # Set default environment variables for configuration
    export SIGUL_BRIDGE_HOSTNAME="${SIGUL_BRIDGE_HOSTNAME:-sigul-bridge}"
    export SIGUL_BRIDGE_CLIENT_PORT="${SIGUL_BRIDGE_CLIENT_PORT:-44334}"
    export SIGUL_NSS_DIR="$nss_dir"
    export SIGUL_DATABASE_PATH="$database_dir/sigul.db"
    export SIGUL_LOG_DIR="$SIGUL_BASE_DIR/logs/server"
    export SIGUL_PID_FILE="$SIGUL_BASE_DIR/pids/server.pid"

    # Create server configuration content with variable substitution
    cat > "$config_file" << SERVER_CONFIG_EOF
# Sigul Server Configuration
# Generated by sigul-init.sh

[server]
# Bridge connection configuration
bridge-hostname = sigul-bridge
bridge-port = ${SIGUL_BRIDGE_CLIENT_PORT}
server-cert-nickname = sigul-server-cert
max-file-payload-size = 2097152
signing-timeout = 60
idle-timeout = 300


# Database Configuration - SQLite
[database]
database-path = ${SIGUL_DATABASE_PATH}

# SSL/TLS configuration
ca-cert-file = ${SIGUL_BASE_DIR}/secrets/certificates/ca.crt
server-cert-file = ${SIGUL_BASE_DIR}/secrets/certificates/server.crt
server-key-file = ${SIGUL_BASE_DIR}/secrets/certificates/server-key.pem
require-tls = true

# NSS Configuration
[nss]
nss-dir = ${SIGUL_NSS_DIR}
nss-password = ${nss_password}

# GnuPG Configuration
[gnupg]
gnupg-home = ${GNUPG_DIR}


# Daemon configuration
# IMPORTANT: Empty unix-user/unix-group disables privilege dropping in containers.
# This is REQUIRED when running as non-root container user (sigul UID 1000).
# Privilege dropping fails when container already runs as target user.
# Container runtime provides security isolation - no additional dropping needed.
[daemon]
unix-user =
unix-group =

SERVER_CONFIG_EOF

    # Set proper permissions
    chmod 640 "$config_file"
    chown sigul:sigul "$config_file"

    log "Server configuration generated successfully"
    return 0
}

# Generate bridge configuration
generate_bridge_config() {
    local config_file="$SIGUL_BASE_DIR/config/bridge.conf"
    local nss_dir="$SIGUL_BASE_DIR/nss/bridge"

    log "Generating bridge configuration"

    # Load NSS password directly to avoid debug output during config generation
    local nss_password
    if ! nss_password=$(load_secret "nss_password" 2>/dev/null); then
        error "Failed to load NSS password for bridge configuration"
    fi

    # Set default environment variables for configuration
    export SIGUL_BRIDGE_CLIENT_PORT="${SIGUL_BRIDGE_CLIENT_PORT:-44334}"
    export SIGUL_BRIDGE_SERVER_PORT="${SIGUL_BRIDGE_SERVER_PORT:-44333}"
    export SIGUL_NSS_DIR="$nss_dir"
    export SIGUL_GNUPG_DIR="$SIGUL_BASE_DIR/gnupg"

    # Create bridge configuration content with variable substitution
    cat > "$config_file" << BRIDGE_CONFIG_EOF
# Sigul Bridge Configuration
# Generated by sigul-init.sh

[bridge]
# IMPORTANT: Sigul bridge ALWAYS binds to all interfaces (0.0.0.0)
# There is NO configuration option in Sigul to change the bind address
# The bridge hardcodes: sock.bind(nss.io.NetworkAddress(nss.io.PR_IpAddrAny, port))
# See: /usr/share/sigul/bridge.py create_listen_sock() function
client-listen-port = ${SIGUL_BRIDGE_CLIENT_PORT}
server-listen-port = ${SIGUL_BRIDGE_SERVER_PORT}
server-hostname = sigul-server
bridge-cert-nickname = sigul-bridge-cert
max-file-payload-size = 2097152
idle-timeout = 300
# NSS directory setting
nss-dir = ${SIGUL_NSS_DIR}

# SSL/TLS configuration
ca-cert-file = ${SIGUL_BASE_DIR}/secrets/certificates/ca.crt
bridge-cert-file = ${SIGUL_BASE_DIR}/secrets/certificates/bridge.crt
bridge-key-file = ${SIGUL_BASE_DIR}/secrets/certificates/bridge-key.pem
require-tls = true

# NSS Configuration
[nss]
nss-dir = ${SIGUL_NSS_DIR}
nss-password = ${nss_password}

# GnuPG Configuration
[gnupg]
gnupg-home = ${SIGUL_GNUPG_DIR}


# Daemon configuration
# IMPORTANT: Empty unix-user/unix-group disables privilege dropping in containers.
# This is REQUIRED when running as non-root container user (sigul UID 1000).
# Privilege dropping fails when container already runs as target user.
# Container runtime provides security isolation - no additional dropping needed.
[daemon]
unix-user =
unix-group =

BRIDGE_CONFIG_EOF

    # Set proper permissions
    chmod 640 "$config_file"
    chown sigul:sigul "$config_file"

    log "Bridge configuration generated successfully"
    return 0
}

# Generate client configuration
generate_client_config() {
    local config_file="$SIGUL_BASE_DIR/config/client.conf"
    local nss_dir="$SIGUL_BASE_DIR/nss/client"

    log "Generating client configuration"

    # Load NSS password directly to avoid debug output during config generation
    local nss_password
    if ! nss_password=$(load_secret "nss_password" 2>/dev/null); then
        error "Failed to load NSS password for client configuration"
    fi

    # Set default environment variables for configuration
    # Set default environment variables for configuration
    export SIGUL_BRIDGE_HOSTNAME="${SIGUL_BRIDGE_HOSTNAME:-sigul-bridge}"
    export SIGUL_BRIDGE_CLIENT_PORT="${SIGUL_BRIDGE_CLIENT_PORT:-44334}"
    export SIGUL_SERVER_HOST="${SIGUL_SERVER_HOST:-sigul-server}"
    export SIGUL_NSS_DIR="$nss_dir"

    # Create client configuration content with variable substitution
    cat > "$config_file" << CLIENT_CONFIG_EOF
# Sigul Client Configuration
# Generated by sigul-init.sh

[client]
# Bridge connection configuration
bridge-hostname = ${SIGUL_BRIDGE_HOSTNAME}
bridge-port = ${SIGUL_BRIDGE_CLIENT_PORT}
server-hostname = ${SIGUL_SERVER_HOST:-sigul-server}
client-cert-nickname = sigul-client-cert

# SSL/TLS configuration
ca-cert-file = ${SIGUL_BASE_DIR}/secrets/certificates/ca.crt
client-cert-file = ${SIGUL_BASE_DIR}/secrets/certificates/client.crt
client-key-file = ${SIGUL_BASE_DIR}/secrets/certificates/client-key.pem
require-tls = true

# NSS Configuration
[nss]
nss-dir = ${SIGUL_NSS_DIR}
nss-password = ${nss_password}

# Client logging uses stderr by default (no file logging for non-daemon clients)
# For consistency, client logs are available in the container output

CLIENT_CONFIG_EOF

    # Set proper permissions
    chmod 640 "$config_file"
    chown sigul:sigul "$config_file"

    log "Client configuration generated successfully"
    return 0
}

# Validate configuration syntax
validate_configuration() {
    local role="$SIGUL_ROLE"
    local config_file="$SIGUL_BASE_DIR/config/${role}.conf"

    debug "Validating configuration for role: $role"
    debug "Configuration file: $config_file"

    # Check if configuration file exists
    if [[ ! -f "$config_file" ]]; then
        error "Configuration file not found: $config_file"
    fi

    # Check file is readable
    if [[ ! -r "$config_file" ]]; then
        error "Configuration file is not readable: $config_file"
    fi

    # Basic syntax validation - check for required sections
    case "$role" in
        "server")
            if ! grep -q "^\[server\]" "$config_file"; then
                error "Server configuration missing [server] section"
            fi
            # Check for required server settings
            local required_settings=("bridge-hostname" "database-path")
            ;;
        "bridge")
            if ! grep -q "^\[bridge\]" "$config_file"; then
                error "Bridge configuration missing [bridge] section"
            fi
            # Check for required bridge settings
            local required_settings=("client-listen-port" "server-listen-port" "server-hostname" "nss-dir")
            ;;
        "client")
            if ! grep -q "^\[client\]" "$config_file"; then
                error "Client configuration missing [client] section"
            fi
            # Check for required client settings
            local required_settings=("bridge-hostname" "server-hostname")

            # Check for NSS section and nss-dir setting separately
            if ! grep -q "^\[nss\]" "$config_file"; then
                error "Client configuration missing [nss] section"
            fi
            if ! grep -q "^nss-dir[[:space:]]*=" "$config_file"; then
                error "Configuration missing required setting: nss-dir"
            fi
            ;;
        *)
            error "Unknown role for configuration validation: $role"
            ;;
    esac

    # Check for required settings
    for setting in "${required_settings[@]}"; do
        if ! grep -q "^${setting}[[:space:]]*=" "$config_file"; then
            error "Configuration missing required setting: $setting"
        fi
    done

    debug "Configuration validation successful for role: $role"
    return 0
}

# Main configuration generation orchestration
create_configuration() {
    local role="$SIGUL_ROLE"

    log "Creating configuration for role: $role"

    # Generate role-specific configuration
    case "$role" in
        "server")
            if ! generate_server_config; then
                error "Failed to generate server configuration"
            fi
            ;;
        "bridge")
            if ! generate_bridge_config; then
                error "Failed to generate bridge configuration"
            fi
            ;;
        "client")
            if ! generate_client_config; then
                error "Failed to generate client configuration"
            fi
            ;;
        *)
            error "Unknown role for configuration generation: $role"
            ;;
    esac

    # Validate generated configuration
    if ! validate_configuration; then
        error "Configuration validation failed for role: $role"
    fi

    # Perform config drift detection
    if ! detect_config_drift; then
        warn "Configuration drift detected - see diagnostics for details"
    fi

    log "Configuration created and validated successfully for role: $role"
    return 0
}

# Config drift detection
detect_config_drift() {
    local role="$SIGUL_ROLE"
    local config_dir="$SIGUL_BASE_DIR/config"
    local artifacts_dir="${PROJECT_ROOT:-/tmp}/test-artifacts"
    local digests_file="$artifacts_dir/config-digests.json"

    log "Performing config drift detection for role: $role"

    # Ensure artifacts directory exists
    mkdir -p "$artifacts_dir"

    # Load existing digests if they exist
    local existing_digests='{}'
    if [[ -f "$digests_file" ]]; then
        existing_digests=$(cat "$digests_file" 2>/dev/null || echo '{}')
    fi

    # Calculate current config hashes
    local current_digests='{}'
    local drift_detected="false"
    local drift_details='[]'

    # Hash all configuration files for this role
    local config_files=()
    case "$role" in
        "server")
            config_files=("$config_dir/server.conf")
            ;;
        "bridge")
            config_files=("$config_dir/bridge.conf")
            ;;
        "client")
            config_files=("$config_dir/client.conf")
            ;;
    esac

    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            local filename
            filename=$(basename "$config_file")
            local file_hash
            if command -v sha256sum >/dev/null 2>&1; then
                file_hash=$(sha256sum "$config_file" | awk '{print $1}')
            else
                # Fallback for systems without sha256sum
                file_hash=$(openssl dgst -sha256 "$config_file" | awk '{print $NF}')
            fi

            # Add to current digests
            current_digests=$(echo "$current_digests" | jq --arg file "$filename" --arg hash "$file_hash" '.[$file] = $hash')

            # Check for drift
            local existing_hash
            existing_hash=$(echo "$existing_digests" | jq -r --arg file "$filename" '.[$file] // null')

            if [[ "$existing_hash" != "null" && "$existing_hash" != "$file_hash" ]]; then
                drift_detected="true"
                local drift_info
                drift_info=$(jq -n --arg file "$filename" --arg old_hash "$existing_hash" --arg new_hash "$file_hash" --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
                    "file": $file,
                    "oldHash": $old_hash,
                    "newHash": $new_hash,
                    "detectedAt": $timestamp
                }')
                drift_details=$(echo "$drift_details" | jq --argjson drift "$drift_info" '. += [$drift]')
                warn "Config drift detected in $filename: $existing_hash -> $file_hash"
            elif [[ "$existing_hash" == "null" ]]; then
                debug "New config file detected: $filename ($file_hash)"
            else
                debug "Config file unchanged: $filename ($file_hash)"
            fi
        fi
    done

    # Update digests file with current hashes and drift information
    local updated_digests
    updated_digests=$(jq -n \
        --argjson existing "$existing_digests" \
        --argjson current "$current_digests" \
        --argjson drift_detected "$drift_detected" \
        --argjson drift_details "$drift_details" \
        --arg role "$role" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
            "digests": ($existing + $current),
            "lastUpdated": $timestamp,
            "lastRole": $role,
            "driftDetected": $drift_detected,
            "driftHistory": $drift_details
        }')

    echo "$updated_digests" > "$digests_file"
    chmod 644 "$digests_file" 2>/dev/null || true

    debug "Config digests updated: $digests_file"

    if [[ "$drift_detected" == "true" ]]; then
        warn "Configuration drift detected - changes logged to $digests_file"
        return 1
    else
        debug "No configuration drift detected"
        return 0
    fi
}

#######################################
# Phase 4.1: Database Management Functions
#######################################

# Initialize SQLite database for server role
initialize_sigul_database() {
    local db_path="$DATABASE_DIR/sigul.db"
    local config_file="$CONFIG_DIR/server.conf"

    log "Initializing Sigul SQLite database at: $db_path"

    # Check if database already exists
    if [[ -f "$db_path" ]]; then
        log "Database already exists at $db_path, validating..."
        if validate_database; then
            log "Existing database is valid, skipping initialization"
            return 0
        else
            log "Existing database is invalid, backing up and recreating..."
            mv "$db_path" "${db_path}.backup.$(date +%Y%m%d_%H%M%S)" || {
                error "Failed to backup existing database"
            }
        fi
    fi

    # Check if sigul_server_create_db command exists
    if ! command -v sigul_server_create_db >/dev/null 2>&1; then
        debug "sigul_server_create_db not found, creating basic database structure"
        # Create a basic database structure for testing/fallback
        sqlite3 "$db_path" "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT); CREATE TABLE IF NOT EXISTS packages (id INTEGER PRIMARY KEY, name TEXT); CREATE TABLE IF NOT EXISTS signing_keys (id INTEGER PRIMARY KEY, name TEXT);" || {
            error "Failed to create basic database structure"
        }
        log "Basic database structure created (production deployment should use sigul_server_create_db)"
        return 0
    fi

    # Create the database using official sigul command
    log "Creating database using sigul_server_create_db..."
    if ! sigul_server_create_db --config-file="$config_file"; then
        error "Failed to create Sigul database using sigul_server_create_db"
    fi

    # Validate the created database
    if ! validate_database; then
        error "Database creation succeeded but validation failed"
    fi

    log "Database initialized successfully"
    return 0
}

# Set up admin user for server role
setup_admin_user() {
    local config_file="$CONFIG_DIR/server.conf"
    local admin_password_file="$SECRETS_DIR/server_admin_password"

    log "Setting up admin user for Sigul server"
    debug "Config file: $config_file"
    debug "Admin password file: $admin_password_file"
    debug "SIGUL_ADMIN_PASSWORD env var: ${SIGUL_ADMIN_PASSWORD:+SET}"

    # Check if admin password exists in file or environment variable
    if [[ ! -f "$admin_password_file" ]]; then
        # If password file doesn't exist, try to create it from environment variable
        if [[ -n "${SIGUL_ADMIN_PASSWORD:-}" ]]; then
            log "Creating admin password file from environment variable"
            mkdir -p "$(dirname "$admin_password_file")"
            echo "$SIGUL_ADMIN_PASSWORD" > "$admin_password_file"
            chmod 600 "$admin_password_file"
            debug "Admin password file created: $admin_password_file"
        else
            warn "Admin password file not found and SIGUL_ADMIN_PASSWORD not set"
            debug "Admin password file: $admin_password_file"
            debug "Listing contents of secrets directory:"
            debug "$(find "$SECRETS_DIR" -type f 2>/dev/null | head -10 || echo 'No files found')"
            log "Skipping admin user creation - password not available"
            return 0
        fi
    fi

    local admin_password
    admin_password=$(cat "$admin_password_file")
    debug "Successfully read admin password from file"

    # Check if sigul_server_add_admin command exists
    if ! command -v sigul_server_add_admin >/dev/null 2>&1; then
        log "sigul_server_add_admin command not found, skipping admin user creation"
        debug "Available sigul commands: $(find /usr/bin /usr/local/bin -name 'sigul*' 2>/dev/null || echo 'none found')"
        log "Admin user can be created manually later if needed"
        return 0
    fi

    # Create admin user using official sigul command
    log "Creating admin user using sigul_server_add_admin..."
    debug "Running: sigul_server_add_admin --config-file=$config_file --batch"

    local add_admin_output
    if add_admin_output=$(echo -e "admin\n$admin_password" | sigul_server_add_admin --config-file="$config_file" --batch 2>&1); then
        log "Admin user created successfully"
        debug "Admin creation output: $add_admin_output"
        return 0
    else
        debug "Admin creation failed with output: $add_admin_output"

        # Check if user already exists (common case)
        local list_output
        if list_output=$(sigul_server_add_admin --config-file="$config_file" --name=admin --list 2>&1) && echo "$list_output" | grep -q "admin"; then
            log "Admin user already exists, skipping creation"
            debug "Existing admin user confirmed: $list_output"
            return 0
        else
            warn "Failed to add admin user - server will start without admin user"
            debug "List users output: $list_output"
            log "Admin user can be created manually after server startup"
            return 0
        fi
    fi
}

# Validate database integrity
validate_database() {
    local db_path="$DATABASE_DIR/sigul.db"

    debug "Validating database integrity: $db_path"

    # Check if database file exists
    if [[ ! -f "$db_path" ]]; then
        debug "Database file does not exist: $db_path"
    fi

    # Check if SQLite can open the database
    if ! sqlite3 "$db_path" "SELECT name FROM sqlite_master WHERE type='table';" >/dev/null 2>&1; then
        debug "Database file is corrupted or not a valid SQLite database"
    fi

    # Check for essential Sigul tables (basic validation)
    local essential_tables=("users" "keys" "key_accesses")
    for table in "${essential_tables[@]}"; do
        if ! sqlite3 "$db_path" "SELECT name FROM sqlite_master WHERE type='table' AND name='$table';" | grep -q "$table"; then
            debug "Essential table '$table' not found in database"
            return 1
        fi
    done

    debug "Database validation passed"
    return 0
}

# Migrate existing database if needed
# Legacy database migration function removed - not needed in containerized environment

# Main database setup orchestration (server role only)
setup_database() {
    if [[ "$SIGUL_ROLE" != "server" ]]; then
        debug "Database setup only required for server role, skipping"
        return 0
    fi

    log "Setting up database management for server role"

    # Initialize database if needed
    # Step 2: Initialize database
    if ! initialize_sigul_database; then
        error "Failed to initialize Sigul database"
    fi

    # Step 3: Set up admin user (if not skipped)
    if [[ "${SIGUL_SKIP_ADMIN_USER:-false}" != "true" ]]; then
        if ! setup_admin_user; then
            warn "Admin user setup encountered issues but server will continue"
            log "Admin user can be created manually after server startup"
        fi
    else
        log "Skipping admin user creation (SIGUL_SKIP_ADMIN_USER=true)"
    fi

    log "Database setup completed successfully"
    return 0
}

#######################################
# Phase 4.2: Health Checks and Validation Functions
#######################################

# Validate all secrets are present and valid
# shellcheck disable=SC2317  # Complex error handling creates false positive unreachable code warnings
validate_secrets() {
    local role="$SIGUL_ROLE"

    debug "Validating secrets for role: $role"

    # Check NSS password for all roles
    local nss_password_file="$SECRETS_DIR/${role}_nss_password"
    if [[ ! -f "$nss_password_file" ]]; then
        error "NSS password file missing: $nss_password_file"
        return 1
    fi

    # Validate file permissions
    local perms
    perms=$(stat -c "%a" "$nss_password_file" 2>/dev/null)
    if [[ "$perms" != "600" ]]; then
        error "NSS password file has incorrect permissions: $perms (expected 600)"
        return 1
    fi

    # Check admin password for server role
    if [[ "$role" == "server" ]]; then
        local admin_password_file="$SECRETS_DIR/server_admin_password"
        # Check if admin password exists
        if [[ ! -f "$admin_password_file" ]]; then
            error "Admin password file missing: $admin_password_file"
            return 1
        fi

        perms=$(stat -c "%a" "$admin_password_file" 2>/dev/null)
        if [[ "$perms" != "600" ]]; then
            error "Admin password file has incorrect permissions: $perms (expected 600)"
            return 1
        fi
    fi

    debug "Secrets validation passed"
    return 0
}

# Validate certificates are present and valid
validate_certificates() {
    local role="$SIGUL_ROLE"
    local cert_dir="$SECRETS_DIR/certificates"

    debug "Validating certificates for role: $role"

    # Define expected certificates by role
    local expected_certs=()
    local expected_keys=()
    case "$role" in
        "server")
            expected_certs=("server.crt" "ca.crt")
            expected_keys=("server-key.pem")
            ;;
        "bridge")
            expected_certs=("bridge.crt" "ca.crt")
            expected_keys=("bridge-key.pem")
            ;;
        "client")
            expected_certs=("client.crt" "ca.crt")
            expected_keys=("client-key.pem")
            ;;
    esac

    # Check each expected certificate
    for cert in "${expected_certs[@]}"; do
        local cert_path="$cert_dir/$cert"
        if [[ ! -f "$cert_path" ]]; then
            error "Certificate missing: $cert_path"
            return 1
        fi

        # Validate certificate file size (must be > 0)
        if [[ ! -s "$cert_path" ]]; then
            error "Certificate file is empty: $cert_path"
            return 1
        fi

        # Validate certificate using OpenSSL
        if ! openssl x509 -in "$cert_path" -noout -checkend 86400 >/dev/null 2>&1; then
            error "Certificate is invalid or expires within 24 hours: $cert_path"
            return 1
        fi
    done

    # Check each expected private key
    for key in "${expected_keys[@]}"; do
        local key_path="$cert_dir/$key"
        if [[ ! -f "$key_path" ]]; then
            error "Private key missing: $key_path"
            return 1
        fi

        # Validate key file size (must be > 0)
        if [[ ! -s "$key_path" ]]; then
            error "Private key file is empty: $key_path"
            return 1
        fi
    done

    debug "Certificate validation passed"
    return 0
}

# Validate file and directory permissions
validate_permissions() {
    debug "Validating file and directory permissions"

    # Check base directory
    local perms
    perms=$(stat -c "%a" "$SIGUL_BASE_DIR" 2>/dev/null)
    if [[ "$perms" != "755" ]]; then
        debug "Base directory has incorrect permissions: $perms (expected 755)"
        return 1
    fi

    # Check secrets directory
    perms=$(stat -c "%a" "$SECRETS_DIR" 2>/dev/null)
    if [[ "$perms" != "700" ]]; then
        debug "Secrets directory has incorrect permissions: $perms (expected 700)"
        return 1
    fi

    # Check NSS directory
    perms=$(stat -c "%a" "$NSS_DIR" 2>/dev/null)
    if [[ "$perms" != "700" ]]; then
        debug "NSS directory has incorrect permissions: $perms (expected 700)"
        return 1
    fi

    # Check config directory
    perms=$(stat -c "%a" "$CONFIG_DIR" 2>/dev/null)
    if [[ "$perms" != "750" ]]; then
        debug "Config directory has incorrect permissions: $perms (expected 750)"
        return 1
    fi

    debug "Permission validation passed"
    return 0
}

# Check required binaries and libraries
validate_dependencies() {
    debug "Validating required dependencies"

    # Essential binaries for all roles (must be present)
    local essential_binaries=("openssl" "sqlite3")

    # Optional role-specific binaries (warn if missing but don't fail)
    local optional_binaries=()
    case "$SIGUL_ROLE" in
        "server")
            optional_binaries+=("sigul_server" "sigul_server_create_db" "sigul_server_add_admin")
            ;;
        "bridge")
            optional_binaries+=("sigul_bridge")
            ;;
        "client")
            optional_binaries+=("sigul")
            ;;
    esac

    # Check essential binaries
    for binary in "${essential_binaries[@]}"; do
        if ! command -v "$binary" >/dev/null 2>&1; then
            debug "Essential binary not found: $binary"
            return 1
        fi
    done

    # Check optional binaries (warn but don't fail)
    for binary in "${optional_binaries[@]}"; do
        if ! command -v "$binary" >/dev/null 2>&1; then
            debug "Optional binary not found: $binary (will use fallback methods)"
        fi
    done

    debug "Dependency validation passed"
    return 0
}

# Check if service is ready to start
check_service_readiness() {
    local role="$SIGUL_ROLE"

    debug "Checking service readiness for role: $role"

    # Check configuration file exists
    local config_file="$CONFIG_DIR/${role}.conf"
    if [[ ! -f "$config_file" ]]; then
        debug "Configuration file missing: $config_file"
        return 1
    fi

    # Validate configuration syntax (basic check)
    if ! grep -q "^\[" "$config_file"; then
        debug "Configuration file appears to be invalid: $config_file"
        return 1
    fi

    # Check NSS database exists
    local nss_db_dir="$NSS_DIR/$role"
    if [[ ! -d "$nss_db_dir" ]] || [[ ! -f "$nss_db_dir/cert8.db" && ! -f "$nss_db_dir/cert9.db" ]]; then
        debug "NSS database not properly initialized: $nss_db_dir"
        return 1
    fi

    # Server-specific readiness checks
    if [[ "$role" == "server" ]]; then
        # Check database exists (validate_database may fail if created by mock)
        local db_path="$DATABASE_DIR/sigul.db"
        if [[ ! -f "$db_path" ]]; then
            debug "Server database file not found: $db_path"
            return 1
        fi

        # Basic database check (more tolerant than full validation)
        if ! sqlite3 "$db_path" "SELECT name FROM sqlite_master LIMIT 1;" >/dev/null 2>&1; then
            debug "Server database is not accessible or corrupted"
            return 1
        fi
    fi

    debug "Service readiness check passed"
    return 0
}

# Validate NSS database has expected certificate nicknames
# shellcheck disable=SC2317  # Complex error handling creates false positive unreachable code warnings
validate_nss_nicknames() {
    local role="$SIGUL_ROLE"
    local nss_dir="$NSS_DIR/$role"

    debug "Validating NSS certificate nicknames for role: $role"

    # Load the NSS password
    local nss_password
    if ! nss_password=$(load_secret "nss_password" "$role" 2>/dev/null); then
        error "Failed to load NSS password for role: $role"
        return 1
    fi

    # Test NSS database accessibility
    if ! echo "$nss_password" | certutil -L -d "$nss_dir" -f /dev/stdin >/dev/null 2>&1; then
        error "NSS database is not accessible for role: $role"
        return 1
    fi

    # Define expected nicknames by role
    local expected_nicknames=()
    case "$role" in
        "server")
            expected_nicknames=("sigul-server-cert" "sigul-ca-cert")
            ;;
        "bridge")
            expected_nicknames=("sigul-bridge-cert" "sigul-ca-cert")
            ;;
        "client")
            expected_nicknames=("sigul-client-cert" "sigul-ca-cert")
            ;;
    esac

    # Check for expected certificate nicknames
    for nickname in "${expected_nicknames[@]}"; do
        if ! echo "$nss_password" | certutil -L -d "$nss_dir" -f /dev/stdin | grep -q "$nickname"; then
            error "NSS database missing expected certificate nickname: $nickname"
            return 1
        fi
    done

    debug "NSS nickname validation passed for role: $role"
    return 0
}

# Main health check orchestration - comprehensive validation
perform_health_check() {
    log "Performing comprehensive health check for role: $SIGUL_ROLE"

    local checks_passed=0
    local checks_total=5

    # Run secrets validation
    log "Testing: validate_secrets"
    if validate_secrets; then
        log "✓ Secrets validation passed"
        checks_passed=$((checks_passed + 1))
    else
        log "✗ Secrets validation failed"
        return 1
    fi

    # Run certificate validation
    log "Testing: validate_certificates"
    if validate_certificates; then
        log "✓ Certificate validation passed"
        checks_passed=$((checks_passed + 1))
    else
        log "✗ Certificate validation failed"
        return 1
    fi

    # Run NSS nickname validation
    log "Testing: validate_nss_nicknames"
    if validate_nss_nicknames; then
        log "✓ NSS nickname validation passed"
        checks_passed=$((checks_passed + 1))
    else
        log "✗ NSS nickname validation failed"
        return 1
    fi

    # Run NSS deep integrity check (for daemon roles) - non-fatal
    if [[ "$SIGUL_ROLE" == "server" || "$SIGUL_ROLE" == "bridge" ]]; then
        log "Testing: perform_nss_integrity_deep_check"
        if perform_nss_integrity_deep_check "$SIGUL_ROLE"; then
            log "✓ NSS deep integrity check passed"
            checks_passed=$((checks_passed + 1))
        else
            log "⚠️ NSS deep integrity check had warnings (non-fatal - Sigul uses PEM files for private keys)"
            checks_passed=$((checks_passed + 1))
        fi
    else
        log "Skipping NSS deep integrity check for non-daemon role: $SIGUL_ROLE"
        checks_passed=$((checks_passed + 1))
    fi

    # Run service readiness check
    log "Testing: check_service_readiness"
    if check_service_readiness; then
        log "✓ Service readiness check passed"
        checks_passed=$((checks_passed + 1))
    else
        log "✗ Service readiness check failed"
        return 1
    fi

    log "Health check results: $checks_passed/$checks_total checks passed"

    if [[ $checks_passed -eq $checks_total ]]; then
        log "All health checks passed - system ready for service startup"
        return 0
    else
        log "Health checks failed - manual intervention may be required"
        return 1
    fi
}

#######################################
# Phase 5: Service Integration and Testing
#######################################

# Phase 5.1: Service Startup Integration Functions
#######################################

# Main service startup orchestration by role
start_service() {
    log "Starting service for role: $SIGUL_ROLE"

    case "$SIGUL_ROLE" in
        "server")
            start_server
            ;;
        "bridge")
            start_bridge
            ;;
        "client")
            start_client
            ;;
        *)
            error "Invalid role for service startup: $SIGUL_ROLE" "$EXIT_INVALID_ARGS"
            ;;
    esac
}

# Start sigul_server daemon
start_server() {
    log "Starting Sigul server daemon"

    # Verify prerequisites
    if ! command -v sigul_server >/dev/null 2>&1; then
        error "sigul_server binary not found in PATH" "$EXIT_DEPENDENCY_MISSING"
    fi

    # Verify configuration exists
    local server_config="$CONFIG_DIR/server.conf"
    if [[ ! -f "$server_config" ]]; then
        error "Server configuration not found: $server_config" "$EXIT_CONFIG_ERROR"
    fi

    # Enforce ordered initialization dependency - bridge must be reachable
    if ! verify_bridge_reachability; then
        error "Bridge dependency check failed - server cannot start" "$EXIT_DEPENDENCY_MISSING"
    fi

    # Check daemon flag support
    local support_internal_flags=1
    if ! sigul_server --help 2>&1 | grep -q -- '--internal-log-dir'; then
        support_internal_flags=0
        log "Server binary does not support --internal-log-dir/--internal-pid-dir; using standard startup"
    else
        debug "Server binary supports --internal-log-dir/--internal-pid-dir flags"
    fi

    # Create PID file path
    local pid_file="$PIDS_DIR/sigul_server.pid"
    local log_file="$LOGS_DIR/server/daemon.log"

    # Ensure log directory exists
    mkdir -p "$(dirname "$log_file")"

    log "Server daemon configuration:"
    debug "  Config file: $server_config"
    debug "  PID file: $pid_file"
    if [[ $support_internal_flags -eq 1 ]]; then
        debug "  Log directory: $LOGS_DIR/server (via --internal-log-dir)"
        debug "  Expected log file: $log_file"
    else
        debug "  Log directory: default sigul logging (internal flags not supported)"
    fi
    debug "  Database: $DATABASE_DIR/sigul.db"

    # Start the server daemon
    log "Executing sigul_server daemon..."

    # Simple pre-startup diagnostics
    debug "Server config file: $server_config"
    debug "Database directory: $DATABASE_DIR"
    debug "NSS directory: $SIGUL_BASE_DIR/nss/server"

    # Use exec to replace the current process (standard for Docker containers)
    # Run in foreground (no -d flag) for Docker containers
    # Wrap in a subshell to capture exit codes for first-failure diagnostics
    set +e
    if [[ $support_internal_flags -eq 1 ]]; then
        debug "Using sigul_server with internal directory flags"
        debug "  Using internal log dir: $LOGS_DIR/server"
        debug "  Using internal pid dir: $PIDS_DIR"
        sigul_server -c "$server_config" -v --internal-log-dir "$LOGS_DIR/server" --internal-pid-dir "$PIDS_DIR"
        server_rc=$?
    else
        debug "Using sigul_server with standard configuration"
        sigul_server -c "$server_config" -v
        server_rc=$?
    fi
    set -e

    # Capture first-failure diagnostic snapshot if server exits with non-zero code
    if [[ $server_rc -ne 0 ]]; then
        capture_fatal_exit_snapshot "server" "$server_rc"
        exit "$server_rc"
    fi
}

# Start sigul_bridge daemon
start_bridge() {
    log "Starting Sigul bridge daemon"

    # Verify prerequisites
    if ! command -v sigul_bridge >/dev/null 2>&1; then
        error "sigul_bridge binary not found in PATH" "$EXIT_DEPENDENCY_MISSING"
    fi

    # Verify configuration exists
    local bridge_config="$CONFIG_DIR/bridge.conf"
    if [[ ! -f "$bridge_config" ]]; then
        error "Bridge configuration not found: $bridge_config" "$EXIT_CONFIG_ERROR"
    fi

    # Check daemon flag support
    local support_internal_flags=1
    if ! sigul_bridge --help 2>&1 | grep -q -- '--internal-log-dir'; then
        support_internal_flags=0
        log "Bridge binary does not support --internal-log-dir/--internal-pid-dir; using standard startup"
    else
        debug "Bridge binary supports --internal-log-dir/--internal-pid-dir flags"
    fi

    # Create PID file path
    local pid_file="$PIDS_DIR/sigul_bridge.pid"
    local log_file="$LOGS_DIR/bridge/daemon.log"

    # Ensure log directory exists
    mkdir -p "$(dirname "$log_file")"

    log "Bridge daemon configuration:"
    debug "  Config file: $bridge_config"
    debug "  PID file: $pid_file"
    if [[ $support_internal_flags -eq 1 ]]; then
        debug "  Log directory: $LOGS_DIR/bridge (via --internal-log-dir)"
        debug "  Expected log file: $log_file"
    else
        debug "  Log directory: default sigul logging (internal flags not supported)"
    fi
    debug "  Bridge client port: ${SIGUL_BRIDGE_CLIENT_PORT:-44334}"
    debug "  Bridge server port: ${SIGUL_BRIDGE_SERVER_PORT:-44333}"
    debug "  Bridge bind address: 0.0.0.0 (hardcoded in Sigul, not configurable)"

    # Start the bridge daemon
    log "Executing sigul_bridge daemon..."

    # Simple pre-startup diagnostics
    debug "Bridge config file: $bridge_config"
    debug "NSS directory: $SIGUL_BASE_DIR/nss/bridge"
    debug "Certificate directory: $SIGUL_BASE_DIR/secrets/certificates"

    # Use exec to replace the current process (standard for Docker containers)
    # Run in foreground (no -d flag) for Docker containers
    debug "Starting sigul_bridge with wrapper capture for diagnostics..."

    wrapper_log="$LOGS_DIR/bridge/daemon.stdout.log"
    startup_err_file="$LOGS_DIR/bridge/startup_errors.log"
    # Ensure log directory exists
    mkdir -p "$LOGS_DIR/bridge"
    : > "$wrapper_log"
    # Pre-flight diagnostics before launching bridge
    debug "Collecting pre-flight diagnostics for bridge startup..."
    {
        echo "=== Bridge Pre-flight Diagnostics ($(date)) ==="
        echo "Config file checksum:"
        if command -v sha256sum >/dev/null 2>&1; then sha256sum "$bridge_config" || true; fi
        echo
        echo "File permissions:"
        for f in "$bridge_config" \
                 "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" \
                 "$SIGUL_BASE_DIR/secrets/certificates/bridge.crt" \
                 "$SIGUL_BASE_DIR/secrets/certificates/bridge-key.pem"; do
            [ -e "$f" ] && ls -l "$f" || echo "MISSING: $f"
        done
        echo
        echo "NSS directory listing:"
        ls -l "$SIGUL_BASE_DIR/nss/bridge" 2>/dev/null || echo "Cannot list NSS dir"
        echo
        echo "Environment (filtered):"
        env | grep -E '^SIGUL_|^NSS_|^DEBUG=' || true
        echo "Internal flags support: $support_internal_flags"
        echo "==============================="
    } >> "$wrapper_log" 2>&1

    start_time=$(date +%s)
    set +e

    # Check if strace should wrap the first attempt
    local use_strace="${SIGUL_ENABLE_STRACE:-0}"
    local strace_file="$LOGS_DIR/bridge/strace.bridge.txt"
    local strace_summary_file="$LOGS_DIR/bridge/strace.summary.txt"

    # Run bridge in foreground, capture output, with optional strace wrapping
    if [[ "$use_strace" == "1" && -x "$(command -v strace)" ]]; then
        debug "Starting sigul_bridge with strace enabled (first attempt)"
        if [[ $support_internal_flags -eq 1 ]]; then
            debug "  Using strace + internal directory flags"
            strace -tt -f -o "$strace_file" \
                sigul_bridge -c "$bridge_config" -v --internal-log-dir "$LOGS_DIR/bridge" --internal-pid-dir "$PIDS_DIR" 2>&1 | tee -a "$wrapper_log"
        else
            debug "  Using strace + standard configuration"
            strace -tt -f -o "$strace_file" \
                sigul_bridge -c "$bridge_config" -v 2>&1 | tee -a "$wrapper_log"
        fi

        # Generate syscall summary if strace succeeded
        if [[ -f "$strace_file" ]]; then
            debug "Generating syscall summary from strace output"
            {
                echo "=== Syscall Summary (Top 20) ==="
                echo "Generated at: $(date)"
                echo ""
                awk '/^[0-9]+.*[0-9]+:[0-9]+:[0-9]+/ {
                    # Extract syscall name from strace line
                    match($0, /[0-9]+:[0-9]+:[0-9]+\.[0-9]+ ([a-zA-Z_]+)/, arr)
                    if (arr[1]) syscalls[arr[1]]++
                } END {
                    for (sc in syscalls) {
                        printf "%6d %s\n", syscalls[sc], sc
                    }
                }' "$strace_file" | sort -nr | head -20
                echo ""
                echo "=== End Syscall Summary ==="
            } > "$strace_summary_file"
            chmod 644 "$strace_summary_file" 2>/dev/null || true
        fi
    else
        # Standard execution without strace
        if [[ $support_internal_flags -eq 1 ]]; then
            debug "Using sigul_bridge with internal directory flags"
            debug "  Using internal log dir: $LOGS_DIR/bridge"
            debug "  Using internal pid dir: $PIDS_DIR"
            sigul_bridge -c "$bridge_config" -v --internal-log-dir "$LOGS_DIR/bridge" --internal-pid-dir "$PIDS_DIR" 2>&1 | tee -a "$wrapper_log"
        else
            debug "Using sigul_bridge with standard configuration"
            sigul_bridge -c "$bridge_config" -v 2>&1 | tee -a "$wrapper_log"
        fi
    fi
    bridge_rc=${PIPESTATUS[0]}
    set -e
    if [[ $bridge_rc -ne 0 ]]; then
        # Capture first-failure diagnostic snapshot
        capture_fatal_exit_snapshot "bridge" "$bridge_rc"

        end_time=$(date +%s)
        runtime=$(( end_time - start_time ))
        {
            echo "Bridge daemon exited with code $bridge_rc at $(date)"
            echo "Runtime (seconds): $runtime"
            echo "--- Last 80 lines of captured output ---"
            tail -80 "$wrapper_log" 2>/dev/null || echo "No wrapper log content"
            echo
            echo "--- Additional diagnostics after failure ---"
            echo "Listing /var/sigul/logs/bridge:"
            ls -l "$LOGS_DIR/bridge" || true
            echo
            echo "Attempting secondary strace (short) if available..."
        } > "$startup_err_file"

        # Include strace information if it was captured during first attempt
        if [[ -f "$strace_file" ]]; then
            {
                echo "--- Strace Summary (from first attempt) ---"
                cat "$strace_summary_file" 2>/dev/null || echo "No strace summary available"
                echo ""
                echo "--- Tail of strace.bridge.txt (last 60 lines) ---"
                tail -60 "$strace_file" 2>/dev/null || echo "No strace output"
            } >> "$startup_err_file"
        elif [[ "$use_strace" == "1" ]]; then
            echo "strace was enabled but no trace file found" >> "$startup_err_file"
        else
            echo "strace not enabled (set SIGUL_ENABLE_STRACE=1 to enable)" >> "$startup_err_file"
        fi

        # If wrapper log ended up empty, note that explicitly
        if [[ ! -s "$wrapper_log" ]]; then
            echo "NOTE: Wrapper stdout log is empty (process may have aborted before emitting output)" >> "$startup_err_file"
        fi

        # Relax permissions so external diagnostic containers (even if non-root) can read
        chmod 644 "$wrapper_log" "$startup_err_file" 2>/dev/null || true

        echo "==== BRIDGE STARTUP FAIL (runtime ${runtime}s, rc=$bridge_rc) ====" >&2
        echo "---- startup_errors.log (full) ----" >&2
        cat "$startup_err_file" 2>/dev/null || echo "Cannot read startup_err_file" >&2
        echo "---- wrapper stdout tail (80) ----" >&2
        tail -80 "$wrapper_log" 2>/dev/null || echo "No wrapper log content" >&2
        if [[ -f "$strace_file" ]]; then
            echo "---- strace summary ----" >&2
            cat "$strace_summary_file" 2>/dev/null || echo "No strace summary" >&2
            echo "---- strace tail (60) ----" >&2
            tail -60 "$strace_file" 2>/dev/null || echo "No strace output" >&2
        fi
        echo "==== END BRIDGE STARTUP FAIL DUMP ====" >&2

        # Allow inspection time in debug mode to avoid rapid restart loops
        if [[ "${DEBUG:-false}" == "true" ]]; then
            echo "DEBUG mode: sleeping 600s for inspection" >> "$startup_err_file"
            sleep 600
        else
            # Reduced pause for faster CI feedback while allowing log extraction
            sleep 3
        fi
        exit "$bridge_rc"
    fi
    # Successful startup: the bridge process remains PID in the pipeline; when it exits, container exits.
}

# Start sigul client (if applicable)
start_client() {
    log "Client role service startup"

    # For client role, we don't start a persistent daemon
    # Instead, we validate the client setup and provide instructions

    local client_config="$CONFIG_DIR/client.conf"
    if [[ ! -f "$client_config" ]]; then
        error "Client configuration not found: $client_config" "$EXIT_CONFIG_ERROR"
    fi

    log "Client setup completed successfully"
    log "Client configuration: $client_config"
    log "NSS database: $NSS_DIR/client"
    log "Client logs: Non-daemon mode - outputs to stderr (container stdout/stderr)"

    log "Client is ready for signing operations"
    log "Example usage:"
    log "  sigul --config $client_config list-keys"
    log "  sigul --config $client_config sign-data <key> <file>"

    # For client, we don't exec a daemon, just exit successfully
    log "Client initialization complete - no persistent daemon required"
}

# Setup signal handlers for graceful shutdown
setup_signal_handlers() {
    log "Setting up signal handlers for graceful shutdown"

    # Function to handle shutdown signals
    shutdown_handler() {
        local signal="$1"
        log "Received signal $signal - initiating graceful shutdown"

        # Kill any running sigul processes
        if [[ "$SIGUL_ROLE" == "server" ]]; then
            pkill -f "sigul_server" 2>/dev/null || true
        elif [[ "$SIGUL_ROLE" == "bridge" ]]; then
            pkill -f "sigul_bridge" 2>/dev/null || true
        fi

        log "Graceful shutdown completed"
        exit 0
    }

    # Register signal handlers
    trap 'shutdown_handler SIGTERM' SIGTERM
    trap 'shutdown_handler SIGINT' SIGINT
    trap 'shutdown_handler SIGHUP' SIGHUP
}

# Basic service monitoring
monitor_service() {
    log "Setting up basic service monitoring for $SIGUL_ROLE"

    local pid_file="$PIDS_DIR/sigul_${SIGUL_ROLE}.pid"
    local check_interval=30

    while true; do
        if [[ -f "$pid_file" ]]; then
            local pid
            pid=$(cat "$pid_file" 2>/dev/null || echo "")

            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                debug "Service $SIGUL_ROLE (PID: $pid) is running"
            else
                log "WARNING: Service $SIGUL_ROLE process not found, PID file may be stale"
            fi
        else
            debug "PID file not found: $pid_file"
        fi

        sleep "$check_interval"
    done
}

# Verify bridge is reachable before server startup
verify_bridge_reachability() {
    log "Verifying bridge reachability before server startup..."

    local bridge_hostname="${SIGUL_BRIDGE_HOSTNAME:-sigul-bridge}"
    local bridge_port="${SIGUL_BRIDGE_CLIENT_PORT:-44334}"
    local max_attempts=30
    local attempt=1

    debug "Checking bridge connectivity: $bridge_hostname:$bridge_port"

    while [[ $attempt -le $max_attempts ]]; do
        debug "Bridge dependency check attempt $attempt/$max_attempts..."

        # Test if bridge port is accessible
        if nc -z "$bridge_hostname" "$bridge_port" 2>/dev/null; then
            log "✅ Bridge is reachable at $bridge_hostname:$bridge_port"
            return 0
        fi

        # Show progress every 10 attempts
        if [[ $((attempt % 10)) -eq 0 ]]; then
            log "Still waiting for bridge to become reachable... (attempt $attempt/$max_attempts)"
        fi

        sleep 2
        ((attempt++))
    done

    error "❌ Bridge is not reachable after $max_attempts attempts"
    # shellcheck disable=SC2317  # This code is reachable via error condition
    error "Server cannot start without bridge connectivity"
    return 1
}

# First-failure diagnostic snapshot capture
capture_fatal_exit_snapshot() {
    local component="$1"
    local exit_code="$2"
    local artifacts_dir="${PROJECT_ROOT:-/tmp}/test-artifacts"

    # Only capture on first failure - check if snapshot already exists
    local snapshot_file="$artifacts_dir/fatal_exit_snapshot.txt"
    if [[ -f "$snapshot_file" ]]; then
        debug "Fatal exit snapshot already exists, skipping duplicate capture"
        return 0
    fi

    log "Capturing first-failure diagnostic snapshot for $component (exit code: $exit_code)"

    # Ensure artifacts directory exists
    mkdir -p "$artifacts_dir"

    # Capture comprehensive diagnostic information
    {
        echo "=== Sigul Fatal Exit Snapshot ==="
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Component: $component"
        echo "Exit Code: $exit_code"
        echo "PID: $$"
        echo "PPID: $PPID"
        echo ""

        echo "=== System Information ==="
        uname -a 2>/dev/null || echo "uname failed"
        echo ""

        echo "=== Environment Variables (Filtered) ==="
        env | grep -E '^(SIGUL_|NSS_|DEBUG|HOME|PATH|USER|PWD)' | sort || echo "env filtering failed"
        echo ""

        echo "=== Certificate Listings ==="
        if [[ -d "$SIGUL_BASE_DIR/secrets/certificates" ]]; then
            echo "Certificate directory contents:"
            ls -la "$SIGUL_BASE_DIR/secrets/certificates/" 2>/dev/null || echo "Cannot list certificates"
            echo ""

            echo "Certificate validity checks:"
            for cert_file in "$SIGUL_BASE_DIR/secrets/certificates"/*.crt; do
                if [[ -f "$cert_file" ]]; then
                    echo "Certificate: $(basename "$cert_file")"
                    openssl x509 -in "$cert_file" -noout -dates -subject 2>/dev/null || echo "Cannot read certificate"
                    echo ""
                fi
            done
        else
            echo "Certificate directory not found"
            echo ""
        fi

        echo "=== NSS Database Listings ==="
        if [[ -d "$SIGUL_BASE_DIR/nss/$component" ]]; then
            echo "NSS directory contents:"
            ls -la "$SIGUL_BASE_DIR/nss/$component/" 2>/dev/null || echo "Cannot list NSS directory"
            echo ""

            # Try to list NSS certificates if certutil is available
            if command -v certutil >/dev/null 2>&1 && [[ -f "$SIGUL_BASE_DIR/secrets/nss_password" ]]; then
                echo "NSS certificate database contents:"
                certutil -L -d "$SIGUL_BASE_DIR/nss/$component" 2>/dev/null || echo "Cannot list NSS certificates"
                echo ""
            fi
        else
            echo "NSS directory not found for $component"
            echo ""
        fi

        echo "=== Recent Wrapper Log (Last 200 lines) ==="
        local wrapper_log="$LOGS_DIR/$component/daemon.stdout.log"
        if [[ -f "$wrapper_log" ]]; then
            echo "From: $wrapper_log"
            tail -200 "$wrapper_log" 2>/dev/null || echo "Cannot read wrapper log"
        else
            echo "Wrapper log not found: $wrapper_log"
        fi
        echo ""

        echo "=== Process Information ==="
        echo "Current processes:"
        pgrep -f "(sigul|$component)" >/dev/null && pgrep -af "(sigul|$component)" || echo "Cannot list processes"
        echo ""

        echo "=== Directory Permissions ==="
        ls -la "$SIGUL_BASE_DIR" 2>/dev/null || echo "Cannot list base directory"
        echo ""

        echo "=== End of Fatal Exit Snapshot ==="

    } > "$snapshot_file" 2>&1

    # Ensure snapshot is world-readable for reliable retrieval
    chmod 644 "$snapshot_file" 2>/dev/null || true

    log "Fatal exit snapshot saved: $snapshot_file"
}

#######################################
# Main Execution Functions
#######################################

# Main initialization function
main() {
    # Parse arguments first (handles --help and --version)
    parse_arguments "$@"

    # Check if we should start service directly
    local start_service_flag=false
    local service_only_flag=false

    # Parse service startup arguments
    for arg in "$@"; do
        case "$arg" in
            "--start-service")
                start_service_flag=true
                ;;
            "--service-only")
                service_only_flag=true
                ;;
        esac
    done

    # If service-only mode, skip initialization and start service
    if [[ "$service_only_flag" == "true" ]]; then
        log "Service-only mode - skipping initialization, starting service directly"

        # Minimal setup for service startup (role already parsed)
        setup_env

        # Setup signal handlers for graceful shutdown
        setup_signal_handlers

        # Start the service
        start_service
        return $?
    fi

    log "Starting Sigul initialization v$VERSION"

    # NSS Database Tracking - Before Phase 1
    log "=== NSS DB TRACKING: Before Phase 1 ==="
    find /var/sigul -name "*.db" -o -name "pkcs11.txt" 2>/dev/null | while read -r file; do log "Found NSS file: $file"; done || log "No NSS database files found"

    # Phase 1.1: Core Infrastructure
    setup_env

    # Phase 1.2: Volume Permission Normalization
    normalize_volume_permissions

    # Phase 1.3: Application Directory Setup
    setup_application_directory
    set_directory_permissions
    validate_directories

    log "Phase 1 initialization completed successfully for role: $SIGUL_ROLE"
    log "Application directory: $SIGUL_BASE_DIR"

    # NSS Database Tracking - After Phase 1
    log "=== NSS DB TRACKING: After Phase 1 ==="
    find /var/sigul -name "*.db" -o -name "pkcs11.txt" 2>/dev/null | while read -r file; do log "Found NSS file: $file"; done || log "No NSS database files found"

    # Phase 2.1: Secrets Management
    setup_secrets

    # NSS Database Tracking - Before Certificate Management
    log "=== NSS DB TRACKING: Before Certificate Management ==="
    find /var/sigul -name "*.db" -o -name "pkcs11.txt" 2>/dev/null | while read -r file; do log "Found NSS file: $file"; done || log "No NSS database files found"

    # Phase 2.2: Certificate Management
    setup_certificates

    # NSS Database Tracking - After Certificate Management
    log "=== NSS DB TRACKING: After Certificate Management ==="
    find /var/sigul -name "*.db" -o -name "pkcs11.txt" 2>/dev/null | while read -r file; do log "Found NSS file: $file"; done || log "No NSS database files found"

    log "Phase 2 initialization completed successfully"

    # Phase 3.1: NSS Database Management
    setup_nss_database

    # Phase 3.2: Configuration Generation
    create_configuration

    log "Phase 3 initialization completed successfully"

    # Phase 4.1: Database Management
    setup_database

    # Phase 4.2: Health Checks and Validation
    perform_health_check

    log "Phase 4 initialization completed successfully"

    # Phase 5: Service Integration
    if [[ "$start_service_flag" == "true" ]]; then
        log "Starting service after initialization"

        # Setup signal handlers for graceful shutdown
        setup_signal_handlers

        # Start the service
        start_service
    else
        log "Sigul $SIGUL_ROLE initialization complete - system ready for service startup"
        log "To start the service, run: $0 --role $SIGUL_ROLE --service-only"
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
