#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Sigul Health Check Library
#
# This library provides reusable health check functions for Sigul infrastructure
# components. It reduces code duplication across deployment scripts, init scripts,
# and diagnostics collectors.
#
# Usage:
#   source scripts/lib/health.sh
#   check_container_status "sigul-bridge"
#   check_port "localhost" "44334"
#   collect_nss_metadata "bridge" "/var/sigul/nss/bridge"
#   emit_json_block "status" "healthy"
#
# Dependencies:
#   - jq (for JSON processing)
#   - nc (for port checking)
#   - docker (for container operations)

# Prevent multiple sourcing
if [[ "${SIGUL_HEALTH_LIB_LOADED:-}" == "true" ]]; then
    return 0
fi
readonly SIGUL_HEALTH_LIB_LOADED="true"

# Library version
readonly SIGUL_HEALTH_LIB_VERSION="1.0.0"

# Health status constants
readonly HEALTH_HEALTHY="healthy"
readonly HEALTH_DEGRADED="degraded"
readonly HEALTH_UNREACHABLE="unreachable"
readonly HEALTH_CRASHED="crashed"

# Colors for output
readonly HEALTH_RED='\033[0;31m'
readonly HEALTH_GREEN='\033[0;32m'
readonly HEALTH_YELLOW='\033[1;33m'
readonly HEALTH_BLUE='\033[0;34m'
readonly HEALTH_PURPLE='\033[0;35m'
readonly HEALTH_NC='\033[0m' # No Color

#######################################
# Logging functions for health library
#######################################

health_log() {
    echo -e "${HEALTH_BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] HEALTH:${HEALTH_NC} $*" >&2
}

health_warn() {
    echo -e "${HEALTH_YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] HEALTH-WARN:${HEALTH_NC} $*" >&2
}

health_error() {
    echo -e "${HEALTH_RED}[$(date '+%Y-%m-%d %H:%M:%S')] HEALTH-ERROR:${HEALTH_NC} $*" >&2
}

health_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${HEALTH_PURPLE}[$(date '+%Y-%m-%d %H:%M:%S')] HEALTH-DEBUG:${HEALTH_NC} $*" >&2
    fi
}

#######################################
# Core health check functions
#######################################

# Check Docker container status
# Arguments:
#   $1 - Container name
# Returns:
#   JSON object with container status information
check_container_status() {
    local container_name="$1"

    if [[ -z "$container_name" ]]; then
        health_error "Container name required for status check"
        echo '{"error": "container_name_required"}'
        return 1
    fi

    health_debug "Checking container status for: $container_name"

    local status restart_count exit_code created_at started_at
    local container_exists="false"

    # Check if container exists
    if docker container inspect "$container_name" >/dev/null 2>&1; then
        container_exists="true"

        # Collect container metadata
        status=$(docker container inspect "$container_name" --format '{{.State.Status}}' 2>/dev/null || echo "unknown")
        restart_count=$(docker container inspect "$container_name" --format '{{.RestartCount}}' 2>/dev/null || echo "0")
        exit_code=$(docker container inspect "$container_name" --format '{{.State.ExitCode}}' 2>/dev/null || echo "unknown")
        created_at=$(docker container inspect "$container_name" --format '{{.Created}}' 2>/dev/null || echo "unknown")
        started_at=$(docker container inspect "$container_name" --format '{{.State.StartedAt}}' 2>/dev/null || echo "unknown")
    else
        status="not_found"
        restart_count="0"
        exit_code="unknown"
        created_at="unknown"
        started_at="unknown"
    fi

    # Determine health classification
    local health_status
    case "$status" in
        "running")
            health_status="$HEALTH_HEALTHY"
            ;;
        "restarting")
            health_status="$HEALTH_DEGRADED"
            ;;
        "exited")
            if [[ "$exit_code" == "0" ]]; then
                health_status="$HEALTH_HEALTHY"
            else
                health_status="$HEALTH_CRASHED"
            fi
            ;;
        "paused"|"dead"|"not_found")
            health_status="$HEALTH_UNREACHABLE"
            ;;
        *)
            health_status="$HEALTH_UNREACHABLE"
            ;;
    esac

    # Generate JSON response
    jq -n \
        --arg container_name "$container_name" \
        --argjson container_exists "$container_exists" \
        --arg status "$status" \
        --argjson restart_count "$restart_count" \
        --arg exit_code "$exit_code" \
        --arg created_at "$created_at" \
        --arg started_at "$started_at" \
        --arg health_status "$health_status" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
            "containerName": $container_name,
            "exists": $container_exists,
            "status": $status,
            "restartCount": $restart_count,
            "exitCode": $exit_code,
            "createdAt": $created_at,
            "startedAt": $started_at,
            "healthStatus": $health_status,
            "checkedAt": $timestamp
        }'
}

# Check network port connectivity
# Arguments:
#   $1 - Hostname or IP address
#   $2 - Port number
#   $3 - Timeout in seconds (optional, default: 5)
# Returns:
#   JSON object with port connectivity information
check_port() {
    local hostname="$1"
    local port="$2"
    local timeout="${3:-5}"

    if [[ -z "$hostname" || -z "$port" ]]; then
        health_error "Hostname and port required for port check"
        echo '{"error": "hostname_port_required"}'
        return 1
    fi

    health_debug "Checking port connectivity: $hostname:$port (timeout: ${timeout}s)"

    local start_time end_time response_time_ms
    local reachable="false"
    local error_message=""

    start_time=$(date +%s%3N)

    # Test connectivity with timeout
    if timeout "$timeout" nc -z "$hostname" "$port" 2>/dev/null; then
        reachable="true"
        health_debug "Port $hostname:$port is reachable"
    else
        error_message="Port not reachable or connection timeout"
        health_debug "Port $hostname:$port is not reachable"
    fi

    end_time=$(date +%s%3N)
    response_time_ms=$((end_time - start_time))

    # Determine health status
    local health_status
    if [[ "$reachable" == "true" ]]; then
        if (( response_time_ms <= 1000 )); then
            health_status="$HEALTH_HEALTHY"
        else
            health_status="$HEALTH_DEGRADED"  # Slow response
        fi
    else
        health_status="$HEALTH_UNREACHABLE"
    fi

    # Generate JSON response
    jq -n \
        --arg hostname "$hostname" \
        --argjson port "$port" \
        --argjson timeout "$timeout" \
        --argjson reachable "$reachable" \
        --argjson response_time_ms "$response_time_ms" \
        --arg error_message "$error_message" \
        --arg health_status "$health_status" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
            "hostname": $hostname,
            "port": $port,
            "timeout": $timeout,
            "reachable": $reachable,
            "responseTimeMs": $response_time_ms,
            "errorMessage": $error_message,
            "healthStatus": $health_status,
            "checkedAt": $timestamp
        }'
}

# Collect NSS database metadata
# Arguments:
#   $1 - Role name (server|bridge|client)
#   $2 - NSS directory path
#   $3 - NSS password (optional, will attempt to load from secrets)
# Returns:
#   JSON object with NSS database information
collect_nss_metadata() {
    local role="$1"
    local nss_dir="$2"
    local nss_password="$3"

    if [[ -z "$role" || -z "$nss_dir" ]]; then
        health_error "Role and NSS directory required for NSS metadata collection"
        echo '{"error": "role_nss_dir_required"}'
        return 1
    fi

    # Handle missing NSS password gracefully
    if [[ -z "$nss_password" ]]; then
        health_debug "NSS password not provided for $role, skipping detailed NSS checks"
        echo '{
            "healthStatus": "unknown",
            "nicknames": [],
            "missingNicknames": [],
            "error": "nss_password_unavailable"
        }'
        return 0
    fi

    health_debug "Collecting NSS metadata for role: $role, directory: $nss_dir"

    local database_exists="false"
    local certificates='[]'
    local private_keys='[]'
    local missing_certificates='[]'
    local missing_private_keys='[]'
    local database_files='[]'
    local health_status="$HEALTH_UNREACHABLE"
    local error_message=""

    # Check if NSS directory exists
    if [[ ! -d "$nss_dir" ]]; then
        error_message="NSS directory does not exist: $nss_dir"
        echo "{\"error\": \"$error_message\"}"
        return 1
    fi

    # Check for NSS database files
    local required_files=("cert9.db" "key4.db" "pkcs11.txt")
    local found_files=()

    for file in "${required_files[@]}"; do
        local file_path="$nss_dir/$file"
        if [[ -f "$file_path" ]]; then
            found_files+=("$file")
            local file_size
            local file_perms
            file_size=$(stat -c%s "$file_path" 2>/dev/null || echo "0")
            file_perms=$(stat -c%a "$file_path" 2>/dev/null || echo "unknown")
            database_files=$(echo "$database_files" | jq --arg name "$file" --argjson size "$file_size" --arg perms "$file_perms" '. += [{
                "name": $name,
                "size": $size,
                "permissions": $perms
            }]')
        fi
    done

    if [[ ${#found_files[@]} -eq ${#required_files[@]} ]]; then
        database_exists="true"
        health_debug "NSS database files found: ${found_files[*]}"
    else
        error_message="Missing NSS database files"
        health_status="$HEALTH_CRASHED"
    fi

    # If database exists, try to collect certificate information
    if [[ "$database_exists" == "true" ]]; then
        # Load NSS password if not provided
        if [[ -z "$nss_password" ]]; then
            local password_file="${SIGUL_BASE_DIR:-/var/sigul}/secrets/nss_password"
            if [[ -f "$password_file" ]]; then
                nss_password=$(cat "$password_file" 2>/dev/null)
            fi
        fi

        if [[ -n "$nss_password" ]]; then
            # List certificates
            local cert_output
            if cert_output=$(echo "$nss_password" | certutil -L -d "$nss_dir" -f /dev/stdin 2>/dev/null); then
                # Parse certificate nicknames (skip header and empty lines)
                local cert_nicknames
                cert_nicknames=$(echo "$cert_output" | grep -v "Certificate Nickname" | grep -v "^$" | awk '{print $1}' | grep -v "^-")
                if [[ -n "$cert_nicknames" ]]; then
                    certificates=$(echo "$cert_nicknames" | jq -R . | jq -s .)
                    health_debug "Found certificates: $cert_nicknames"
                fi

                # Check for expected certificates based on role
                local expected_certs=()
                case "$role" in
                    "server")
                        expected_certs=("sigul-server-cert" "sigul-ca-cert")
                        ;;
                    "bridge")
                        expected_certs=("sigul-bridge-cert" "sigul-ca-cert")
                        ;;
                    "client")
                        expected_certs=("sigul-client-cert" "sigul-ca-cert")
                        ;;
                esac

                # Check for missing certificates
                for expected in "${expected_certs[@]}"; do
                    if ! echo "$cert_output" | grep -q "$expected"; then
                        missing_certificates=$(echo "$missing_certificates" | jq --arg cert "$expected" '. += [$cert]')
                    fi
                done
            else
                error_message="Failed to list certificates"
                health_status="$HEALTH_DEGRADED"
            fi

            # List private keys
            local key_output
            if key_output=$(echo "$nss_password" | certutil -K -d "$nss_dir" -f /dev/stdin 2>/dev/null); then
                # Parse private key nicknames
                local key_nicknames
                key_nicknames=$(echo "$key_output" | grep -E "^<.*>" | awk '{print $NF}')
                if [[ -n "$key_nicknames" ]]; then
                    private_keys=$(echo "$key_nicknames" | jq -R . | jq -s .)
                    health_debug "Found private keys: $key_nicknames"
                fi

                # Check for missing private keys
                local expected_keys=()
                case "$role" in
                    "server")
                        expected_keys=("sigul-server-cert")
                        ;;
                    "bridge")
                        expected_keys=("sigul-bridge-cert")
                        ;;
                    "client")
                        expected_keys=("sigul-client-cert")
                        ;;
                esac

                for expected in "${expected_keys[@]}"; do
                    if ! echo "$key_output" | grep -q "$expected"; then
                        missing_private_keys=$(echo "$missing_private_keys" | jq --arg key "$expected" '. += [$key]')
                    fi
                done
            else
                error_message="Failed to list private keys"
                health_status="$HEALTH_DEGRADED"
            fi

            # Determine overall health status
            local cert_count key_count missing_cert_count missing_key_count
            cert_count=$(echo "$certificates" | jq 'length')
            key_count=$(echo "$private_keys" | jq 'length')
            missing_cert_count=$(echo "$missing_certificates" | jq 'length')
            missing_key_count=$(echo "$missing_private_keys" | jq 'length')

            if [[ "$cert_count" -gt 0 && "$key_count" -gt 0 && "$missing_cert_count" -eq 0 && "$missing_key_count" -eq 0 ]]; then
                health_status="$HEALTH_HEALTHY"
            elif [[ "$cert_count" -gt 0 && "$missing_key_count" -gt 0 ]]; then
                health_status="$HEALTH_DEGRADED"  # Certs present but keys missing
            elif [[ "$cert_count" -gt 0 || "$key_count" -gt 0 ]]; then
                health_status="$HEALTH_DEGRADED"  # Some components present
            else
                health_status="$HEALTH_CRASHED"   # No certs or keys found
            fi
        else
            error_message="NSS password not available"
            health_status="$HEALTH_DEGRADED"
        fi
    fi

    # Generate JSON response
    jq -n \
        --arg role "$role" \
        --arg nss_dir "$nss_dir" \
        --argjson database_exists "$database_exists" \
        --argjson certificates "$certificates" \
        --argjson private_keys "$private_keys" \
        --argjson missing_certificates "$missing_certificates" \
        --argjson missing_private_keys "$missing_private_keys" \
        --argjson database_files "$database_files" \
        --arg health_status "$health_status" \
        --arg error_message "$error_message" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
            "role": $role,
            "nssDirectory": $nss_dir,
            "databaseExists": $database_exists,
            "certificates": $certificates,
            "privateKeys": $private_keys,
            "missingCertificates": $missing_certificates,
            "missingPrivateKeys": $missing_private_keys,
            "databaseFiles": $database_files,
            "healthStatus": $health_status,
            "errorMessage": $error_message,
            "checkedAt": $timestamp
        }'
}

# Emit structured JSON block
# Arguments:
#   $1 - Block name/type
#   $2 - Block data (can be JSON string or simple value)
#   $... - Additional key-value pairs (key1 value1 key2 value2 ...)
# Returns:
#   JSON object with structured block information
emit_json_block() {
    local block_name="$1"
    local block_data="$2"
    shift 2

    if [[ -z "$block_name" ]]; then
        health_error "Block name required for JSON block emission"
        echo '{"error": "block_name_required"}'
        return 1
    fi

    health_debug "Emitting JSON block: $block_name"

    # Start with base structure
    local json_block
    json_block=$(jq -n \
        --arg name "$block_name" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
            "blockName": $name,
            "timestamp": $timestamp
        }')

    # Add main data
    if [[ -n "$block_data" ]]; then
        # Try to parse as JSON, if it fails treat as string
        if echo "$block_data" | jq . >/dev/null 2>&1; then
            json_block=$(echo "$json_block" | jq --argjson data "$block_data" '.data = $data')
        else
            json_block=$(echo "$json_block" | jq --arg data "$block_data" '.data = $data')
        fi
    fi

    # Add additional key-value pairs
    while [[ $# -ge 2 ]]; do
        local key="$1"
        local value="$2"
        shift 2

        # Try to parse value as JSON, if it fails treat as string
        if echo "$value" | jq . >/dev/null 2>&1; then
            json_block=$(echo "$json_block" | jq --arg key "$key" --argjson value "$value" '.[$key] = $value')
        else
            json_block=$(echo "$json_block" | jq --arg key "$key" --arg value "$value" '.[$key] = $value')
        fi
    done

    echo "$json_block"
}

#######################################
# Composite health check functions
#######################################

# Perform comprehensive component health check
# Arguments:
#   $1 - Component name (server|bridge|client)
#   $2 - Container name (optional, defaults to sigul-{component})
# Returns:
#   JSON object with comprehensive health information
check_component_health() {
    local component="$1"
    local container_name="${2:-sigul-$component}"

    if [[ -z "$component" ]]; then
        health_error "Component name required for comprehensive health check"
        echo '{"error": "component_required"}'
        return 1
    fi

    health_debug "Performing comprehensive health check for: $component"

    local container_status nss_metadata port_status
    local overall_health="$HEALTH_HEALTHY"
    local issues=()

    # Check container status
    container_status=$(check_container_status "$container_name")
    local container_health
    container_health=$(echo "$container_status" | jq -r '.healthStatus')

    if [[ "$container_health" != "$HEALTH_HEALTHY" ]]; then
        overall_health="$container_health"
        issues+=("container_status")
    fi

    # Check NSS database (if container is running)
    local container_running
    container_running=$(echo "$container_status" | jq -r '.status')

    if [[ "$container_running" == "running" ]]; then
        # Check NSS database
        # Try to get NSS password, but don't fail if unavailable
        local nss_password=""
        if docker exec "$component" test -f "/var/sigul/secrets/${component}_nss_password" 2>/dev/null; then
            nss_password=$(docker exec "$component" cat "/var/sigul/secrets/${component}_nss_password" 2>/dev/null || echo "")
        fi
        nss_metadata=$(collect_nss_metadata "$component" "/var/sigul/nss/$component" "$nss_password")
        local nss_health
        nss_health=$(echo "$nss_metadata" | jq -r '.healthStatus')

        if [[ "$nss_health" != "$HEALTH_HEALTHY" ]]; then
            if [[ "$overall_health" == "$HEALTH_HEALTHY" ]]; then
                overall_health="$nss_health"
            elif [[ "$nss_health" == "$HEALTH_CRASHED" ]]; then
                overall_health="$HEALTH_CRASHED"
            fi
            issues+=("nss_database")
        fi

        # Check port connectivity (for bridge only)
        if [[ "$component" == "bridge" ]]; then
            port_status=$(check_port "localhost" "44334")
            local port_health
            port_health=$(echo "$port_status" | jq -r '.healthStatus')

            if [[ "$port_health" != "$HEALTH_HEALTHY" ]]; then
                if [[ "$overall_health" == "$HEALTH_HEALTHY" ]]; then
                    overall_health="$port_health"
                elif [[ "$port_health" == "$HEALTH_UNREACHABLE" ]]; then
                    overall_health="$HEALTH_UNREACHABLE"
                fi
                issues+=("port_connectivity")
            fi
        fi
    else
        nss_metadata='null'
        port_status='null'
        issues+=("container_not_running")
    fi

    # Convert issues array to JSON
    local issues_json
    issues_json=$(printf '%s\n' "${issues[@]}" | jq -R . | jq -s .)

    # Generate comprehensive response
    jq -n \
        --arg component "$component" \
        --arg container_name "$container_name" \
        --arg overall_health "$overall_health" \
        --argjson issues "$issues_json" \
        --argjson container_status "$container_status" \
        --argjson nss_metadata "${nss_metadata:-null}" \
        --argjson port_status "${port_status:-null}" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
            "component": $component,
            "containerName": $container_name,
            "overallHealth": $overall_health,
            "issues": $issues,
            "containerStatus": $container_status,
            "nssMetadata": $nss_metadata,
            "portStatus": $port_status,
            "checkedAt": $timestamp
        }'
}

#######################################
# Utility functions
#######################################

# Get health status color for display
# Arguments:
#   $1 - Health status
# Returns:
#   ANSI color code
get_health_color() {
    local health_status="$1"

    case "$health_status" in
        "$HEALTH_HEALTHY")
            echo "$HEALTH_GREEN"
            ;;
        "$HEALTH_DEGRADED")
            echo "$HEALTH_YELLOW"
            ;;
        "$HEALTH_UNREACHABLE")
            echo "$HEALTH_PURPLE"
            ;;
        "$HEALTH_CRASHED")
            echo "$HEALTH_RED"
            ;;
        *)
            echo "$HEALTH_NC"
            ;;
    esac
}

# Get health status emoji for display
# Arguments:
#   $1 - Health status
# Returns:
#   Emoji character
get_health_emoji() {
    local health_status="$1"

    case "$health_status" in
        "$HEALTH_HEALTHY")
            echo "✅"
            ;;
        "$HEALTH_DEGRADED")
            echo "⚠️ "
            ;;
        "$HEALTH_UNREACHABLE")
            echo "🔌"
            ;;
        "$HEALTH_CRASHED")
            echo "❌"
            ;;
        *)
            echo "❓"
            ;;
    esac
}

# Pretty print health status
# Arguments:
#   $1 - Health status
#   $2 - Description (optional)
print_health_status() {
    local health_status="$1"
    local description="${2:-$health_status}"

    local color emoji
    color=$(get_health_color "$health_status")
    emoji=$(get_health_emoji "$health_status")

    echo -e "${color}${emoji} ${description}${HEALTH_NC}"
}

# Check if health library dependencies are available
# Returns:
#   0 if all dependencies are available, 1 otherwise
check_health_dependencies() {
    local missing_deps=()

    # Check for required commands
    for cmd in jq nc docker; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        health_error "Missing required dependencies: ${missing_deps[*]}"
        return 1
    fi

    health_debug "All health library dependencies are available"
    return 0
}

#######################################
# Library initialization
#######################################

# Initialize health library (called automatically when sourced)
_initialize_health_library() {
    health_debug "Sigul Health Library v$SIGUL_HEALTH_LIB_VERSION loaded"

    # Check dependencies
    if ! check_health_dependencies; then
        health_warn "Health library dependencies not fully available"
    fi
}

# Auto-initialize when sourced
_initialize_health_library
