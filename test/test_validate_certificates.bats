#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# BATS tests for validate_certificates function from sigul-init.sh

load "setup_helper"

setup() {
    setup_test_env

    # Source the function under test
    load_function_under_test "scripts/sigul-init.sh"

    # Create basic directory structure for certificates
    mkdir -p "$SIGUL_BASE_DIR/secrets/certificates"
}

teardown() {
    teardown_test_env
}

# Test: validate_certificates with all valid certificates
@test "validate_certificates: success with all valid certificates" {
    # Setup
    create_mock_openssl "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    SIGUL_ROLE="server"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"Certificate validation successful"* ]]
}

# Test: validate_certificates with missing certificate file
@test "validate_certificates: fails with missing certificate file" {
    # Setup
    create_mock_openssl "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    # Missing server.crt intentionally
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    SIGUL_ROLE="server"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Certificate missing"* ]]
}

# Test: validate_certificates with expired certificate
@test "validate_certificates: fails with expired certificate" {
    # Setup
    create_mock_openssl "expired"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "expired"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    SIGUL_ROLE="server"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"expires within 24 hours"* ]]
}

# Test: validate_certificates with empty certificate file
@test "validate_certificates: fails with empty certificate file" {
    # Setup
    create_mock_openssl "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    touch "$SIGUL_BASE_DIR/secrets/certificates/server.crt"  # Empty file
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    SIGUL_ROLE="server"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Certificate file is empty"* ]]
}

# Test: validate_certificates for bridge role
@test "validate_certificates: success for bridge role with correct certificates" {
    # Setup
    create_mock_openssl "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/bridge.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/bridge-key.pem" "valid"

    SIGUL_ROLE="bridge"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"Certificate validation successful"* ]]
}

# Test: validate_certificates for client role
@test "validate_certificates: success for client role with correct certificates" {
    # Setup
    create_mock_openssl "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/client.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/client-key.pem" "valid"

    SIGUL_ROLE="client"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"Certificate validation successful"* ]]
}

# Test: validate_certificates with invalid certificate content
@test "validate_certificates: fails with invalid certificate content" {
    # Setup
    create_mock_openssl "invalid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "invalid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "invalid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    SIGUL_ROLE="server"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Certificate is invalid"* ]]
}

# Test: validate_certificates with missing certificates directory
@test "validate_certificates: fails with missing certificates directory" {
    # Setup - remove certificates directory
    rm -rf "$SIGUL_BASE_DIR/secrets/certificates"

    SIGUL_ROLE="server"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Certificates directory missing"* ]]
}

# Test: validate_certificates with wrong file permissions on private key
@test "validate_certificates: warns about private key permissions" {
    # Setup
    create_mock_openssl "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    # Set wrong permissions on private key
    chmod 644 "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem"

    SIGUL_ROLE="server"

    # Execute
    run validate_certificates

    # Verify - should still pass but warn about permissions
    [ "$status" -eq 0 ]
    [[ "$output" == *"Certificate validation successful"* ]]
}

# Test: validate_certificates debug output
@test "validate_certificates: provides debug information when DEBUG=true" {
    # Setup
    create_mock_openssl "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    SIGUL_ROLE="server"
    # shellcheck disable=SC2034
    DEBUG="true"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"Validating certificates for role: server"* ]]
}

# Test: validate_certificates handles unknown role gracefully
@test "validate_certificates: handles unknown role gracefully" {
    # Setup
    create_mock_openssl "valid"

    # shellcheck disable=SC2034
    SIGUL_ROLE="unknown_role"

    # Execute
    run validate_certificates

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Unknown role"* ]]
}
