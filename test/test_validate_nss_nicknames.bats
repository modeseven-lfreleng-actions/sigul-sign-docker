#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# BATS tests for validate_nss_nicknames function from sigul-init.sh

load "setup_helper"

setup() {
    setup_test_env

    # Source the function under test
    load_function_under_test "scripts/sigul-init.sh"

    # Create basic directory structure for NSS
    mkdir -p "$SIGUL_BASE_DIR/nss/server"
    mkdir -p "$SIGUL_BASE_DIR/nss/bridge"
    mkdir -p "$SIGUL_BASE_DIR/nss/client"

    # Create mock NSS password file
    create_mock_nss_password "test-password"
}

teardown() {
    teardown_test_env
}

# Test: validate_nss_nicknames with all expected certificates for server role
@test "validate_nss_nicknames: success with all expected server certificates" {
    # Setup
    create_mock_certutil "list-certs" "sigul-server-cert sigul-ca-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"NSS nickname validation passed"* ]]
}

# Test: validate_nss_nicknames with all expected certificates for bridge role
@test "validate_nss_nicknames: success with all expected bridge certificates" {
    # Setup
    create_mock_certutil "list-certs" "sigul-bridge-cert sigul-ca-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/bridge" "valid"

    SIGUL_ROLE="bridge"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"NSS nickname validation passed"* ]]
}

# Test: validate_nss_nicknames with all expected certificates for client role
@test "validate_nss_nicknames: success with all expected client certificates" {
    # Setup
    create_mock_certutil "list-certs" "sigul-client-cert sigul-ca-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/client" "valid"

    SIGUL_ROLE="client"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"NSS nickname validation passed"* ]]
}

# Test: validate_nss_nicknames with missing server certificate
@test "validate_nss_nicknames: fails with missing server certificate" {
    # Setup - only CA cert, missing server cert
    create_mock_certutil "list-certs" "sigul-ca-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Missing expected certificate nickname"* ]]
    [[ "$output" == *"sigul-server-cert"* ]]
}

# Test: validate_nss_nicknames with missing CA certificate
@test "validate_nss_nicknames: fails with missing CA certificate" {
    # Setup - only server cert, missing CA cert
    create_mock_certutil "list-certs" "sigul-server-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Missing expected certificate nickname"* ]]
    [[ "$output" == *"sigul-ca-cert"* ]]
}

# Test: validate_nss_nicknames with missing NSS database directory
@test "validate_nss_nicknames: fails with missing NSS database directory" {
    # Setup - remove NSS directory
    rm -rf "$SIGUL_BASE_DIR/nss/server"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"NSS database directory does not exist"* ]]
}

# Test: validate_nss_nicknames with missing NSS password
@test "validate_nss_nicknames: fails with missing NSS password" {
    # Setup - remove password file
    rm -f "$SIGUL_BASE_DIR/secrets/nss_password"
    create_mock_certutil "list-certs" "sigul-server-cert sigul-ca-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Failed to load NSS password"* ]]
}

# Test: validate_nss_nicknames with certutil command failure
@test "validate_nss_nicknames: handles certutil command failure gracefully" {
    # Setup - create certutil that fails
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
echo "certutil: database not accessible"
exit 1
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Failed to list NSS certificates"* ]]
}

# Test: validate_nss_nicknames with extra certificates (should still pass)
@test "validate_nss_nicknames: passes with extra certificates present" {
    # Setup - include extra certificate
    create_mock_certutil "list-certs" "sigul-server-cert sigul-ca-cert extra-test-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"NSS nickname validation passed"* ]]
}

# Test: validate_nss_nicknames debug output
@test "validate_nss_nicknames: provides debug information when DEBUG=true" {
    # Setup
    create_mock_certutil "list-certs" "sigul-server-cert sigul-ca-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"
    # shellcheck disable=SC2034
    DEBUG="true"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"Validating NSS certificate nicknames for role: server"* ]]
}

# Test: validate_nss_nicknames with empty certificate list
@test "validate_nss_nicknames: fails with completely empty NSS database" {
    # Setup - certutil returns only headers
    create_mock_certutil "list-certs" ""
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    SIGUL_ROLE="server"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Missing expected certificate nickname"* ]]
}

# Test: validate_nss_nicknames handles bridge role with different expected certs
@test "validate_nss_nicknames: validates bridge role specific certificates" {
    # Setup - missing bridge-specific cert
    create_mock_certutil "list-certs" "sigul-server-cert sigul-ca-cert"  # Wrong cert for bridge
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/bridge" "valid"

    SIGUL_ROLE="bridge"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Missing expected certificate nickname"* ]]
    [[ "$output" == *"sigul-bridge-cert"* ]]
}

# Test: validate_nss_nicknames handles client role with different expected certs
@test "validate_nss_nicknames: validates client role specific certificates" {
    # Setup - missing client-specific cert
    create_mock_certutil "list-certs" "sigul-server-cert sigul-ca-cert"  # Wrong cert for client
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/client" "valid"

    SIGUL_ROLE="client"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Missing expected certificate nickname"* ]]
    [[ "$output" == *"sigul-client-cert"* ]]
}

# Test: validate_nss_nicknames with unknown role
@test "validate_nss_nicknames: handles unknown role gracefully" {
    # Setup
    create_mock_certutil "list-certs" "some-cert"
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/unknown" "valid"

    SIGUL_ROLE="unknown_role"
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify - should handle gracefully, possibly with warning
    # The exact behavior depends on implementation
    [[ "$status" -ne 0 || "$output" == *"Unknown role"* || "$output" == *"NSS nickname validation passed"* ]]
}

# Test: validate_nss_nicknames certificate listing format parsing
@test "validate_nss_nicknames: correctly parses certutil output format" {
    # Setup - create more realistic certutil output
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
if [[ "$1" == "-L" ]]; then
    cat << CERTLIST
Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

sigul-ca-cert                                               CT,C,C
sigul-server-cert                                           u,u,u
CERTLIST
fi
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"

    # shellcheck disable=SC2034
    SIGUL_ROLE="server"
    # shellcheck disable=SC2034
    NSS_DIR="$SIGUL_BASE_DIR/nss"

    # Execute
    run validate_nss_nicknames

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"NSS nickname validation passed"* ]]
}
