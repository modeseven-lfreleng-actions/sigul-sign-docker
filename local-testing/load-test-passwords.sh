#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Utility script to load stored test passwords for alignment with CI workflow
#
# This script loads passwords that were generated and stored during deployment,
# ensuring consistency between local testing and CI environments.
#
# Usage:
#   source ./load-test-passwords.sh
#   echo "Admin password: $SIGUL_ADMIN_PASSWORD"
#   echo "NSS password: $NSS_PASSWORD"

set -euo pipefail

# Get script directory
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Test artifacts directory (where passwords are stored)
readonly TEST_ARTIFACTS_DIR="${SCRIPT_DIR}/test-workspace/test-artifacts"

# Function to load a password from test artifacts
load_password_from_artifacts() {
    local password_type="$1"
    local password_file="${TEST_ARTIFACTS_DIR}/${password_type}-password"

    if [[ -f "$password_file" ]]; then
        cat "$password_file"
    else
        echo ""
        return 1
    fi
}

# Function to verify password file exists and is readable
verify_password_file() {
    local password_type="$1"
    local password_file="${TEST_ARTIFACTS_DIR}/${password_type}-password"

    if [[ ! -f "$password_file" ]]; then
        echo "ERROR: Password file not found: $password_file" >&2
        echo "       Run deployment script first to generate passwords" >&2
        return 1
    fi

    if [[ ! -r "$password_file" ]]; then
        echo "ERROR: Password file not readable: $password_file" >&2
        return 1
    fi

    return 0
}

# Function to load all test passwords into environment variables
load_test_passwords() {
    local verbose="${1:-false}"

    # Load admin password
    if verify_password_file "admin"; then
        SIGUL_ADMIN_PASSWORD=$(load_password_from_artifacts "admin")
        export SIGUL_ADMIN_PASSWORD
        if [[ "$verbose" == "true" ]]; then
            echo "✓ Loaded admin password (${#SIGUL_ADMIN_PASSWORD} characters)" >&2
        fi
    else
        echo "ERROR: Failed to load admin password" >&2
        return 1
    fi

    # Load NSS password
    if verify_password_file "nss"; then
        NSS_PASSWORD=$(load_password_from_artifacts "nss")
        export NSS_PASSWORD
        if [[ "$verbose" == "true" ]]; then
            echo "✓ Loaded NSS password (${#NSS_PASSWORD} characters)" >&2
        fi
    else
        echo "ERROR: Failed to load NSS password" >&2
        return 1
    fi

    # Set other standard environment variables
    export SIGUL_ADMIN_USER="${SIGUL_ADMIN_USER:-admin}"

    if [[ "$verbose" == "true" ]]; then
        echo "✓ Test passwords loaded successfully" >&2
        echo "  Admin user: $SIGUL_ADMIN_USER" >&2
        echo "  Test artifacts dir: $TEST_ARTIFACTS_DIR" >&2
    fi

    return 0
}

# Function to display password information (without revealing actual passwords)
show_password_info() {
    echo "=== Test Password Information ==="
    echo "Test artifacts directory: $TEST_ARTIFACTS_DIR"
    echo ""

    for password_type in "admin" "nss"; do
        local password_file="${TEST_ARTIFACTS_DIR}/${password_type}-password"
        if [[ -f "$password_file" ]]; then
            local password_length
            password_length=$(wc -c < "$password_file")
            local file_age
            file_age=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$password_file" 2>/dev/null || stat -c "%y" "$password_file" 2>/dev/null || echo "unknown")
            echo "✓ ${password_type^} password: ${password_length} bytes, created: $file_age"
        else
            echo "✗ ${password_type^} password: not found"
        fi
    done

    echo ""
    if [[ -n "${SIGUL_ADMIN_PASSWORD:-}" ]] && [[ -n "${NSS_PASSWORD:-}" ]]; then
        echo "✓ Passwords loaded in environment"
    else
        echo "✗ Passwords not loaded in environment (run load_test_passwords)"
    fi
}

# Function to validate that loaded passwords match stored files
validate_loaded_passwords() {
    local errors=0

    # Check admin password
    if [[ -n "${SIGUL_ADMIN_PASSWORD:-}" ]]; then
        local stored_admin_password
        if stored_admin_password=$(load_password_from_artifacts "admin" 2>/dev/null); then
            if [[ "$SIGUL_ADMIN_PASSWORD" == "$stored_admin_password" ]]; then
                echo "✓ Admin password matches stored file" >&2
            else
                echo "✗ Admin password does not match stored file" >&2
                ((errors++))
            fi
        else
            echo "✗ Cannot read stored admin password file" >&2
            ((errors++))
        fi
    else
        echo "✗ Admin password not loaded in environment" >&2
        ((errors++))
    fi

    # Check NSS password
    if [[ -n "${NSS_PASSWORD:-}" ]]; then
        local stored_nss_password
        if stored_nss_password=$(load_password_from_artifacts "nss" 2>/dev/null); then
            if [[ "$NSS_PASSWORD" == "$stored_nss_password" ]]; then
                echo "✓ NSS password matches stored file" >&2
            else
                echo "✗ NSS password does not match stored file" >&2
                ((errors++))
            fi
        else
            echo "✗ Cannot read stored NSS password file" >&2
            ((errors++))
        fi
    else
        echo "✗ NSS password not loaded in environment" >&2
        ((errors++))
    fi

    return $errors
}

# If script is run directly (not sourced), show password info
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Test Password Loader for Sigul Stack"
    echo "===================================="
    echo ""

    case "${1:-info}" in
        "load")
            if load_test_passwords true; then
                echo ""
                echo "✓ Passwords loaded successfully"
                echo "Run 'source $0' to load passwords into your shell environment"
            else
                echo "✗ Failed to load passwords"
                exit 1
            fi
            ;;
        "validate")
            if load_test_passwords false >/dev/null 2>&1; then
                validate_loaded_passwords
            else
                echo "✗ Cannot validate - passwords not available"
                exit 1
            fi
            ;;
        "info"|*)
            show_password_info
            echo ""
            echo "Usage:"
            echo "  $0 info      Show password file information (default)"
            echo "  $0 load      Load passwords and show status"
            echo "  $0 validate  Validate loaded passwords against stored files"
            echo ""
            echo "To load passwords into environment:"
            echo "  source $0"
            ;;
    esac
else
    # Script is being sourced, load passwords
    if load_test_passwords false; then
        echo "✓ Test passwords loaded from artifacts" >&2
    else
        echo "✗ Failed to load test passwords" >&2
        return 1
    fi
fi
