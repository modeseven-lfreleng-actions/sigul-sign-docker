#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# BATS tests for NSS private key import functionality from sigul-init.sh

load "setup_helper"

setup() {
    setup_test_env

    # Source the function under test
    load_function_under_test "scripts/sigul-init.sh"

    # Create basic directory structure for NSS and certificates
    mkdir -p "$SIGUL_BASE_DIR/nss/server"
    mkdir -p "$SIGUL_BASE_DIR/nss/bridge"
    mkdir -p "$SIGUL_BASE_DIR/nss/client"
    mkdir -p "$SIGUL_BASE_DIR/secrets/certificates"

    # Create mock NSS password file
    create_mock_nss_password "test-password"
}

teardown() {
    teardown_test_env
}

# Test: import_nss_certificates with successful import for server role
@test "import_nss_certificates: success importing server certificates" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    # Create mock certutil that accepts imports
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
case "$1" in
    "-A")  # Add certificate
        echo "Certificate imported successfully"
        exit 0
        ;;
    "-L")  # List certificates (for checking existing)
        echo "Certificate Nickname                                         Trust Attributes"
        exit 1  # Not found initially
        ;;
    *)
        echo "Mock certutil: unknown option $1"
        exit 1
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    # Create mock pk12util for private key import
    cat > "$BATS_TEST_TMPDIR/bin/pk12util" << 'EOF'
#!/bin/bash
echo "Private key imported successfully"
exit 0
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/pk12util"

    SIGUL_ROLE="server"

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"certificate(s) to NSS database for role: server"* ]]
}

# Test: import_nss_certificates with missing NSS database
@test "import_nss_certificates: fails with missing NSS database" {
    # Setup - no NSS database created
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"

    SIGUL_ROLE="server"

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"NSS database does not exist"* ]]
}

# Test: import_nss_certificates with missing certificates
@test "import_nss_certificates: handles missing certificate files gracefully" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"
    # Don't create certificate files - they're missing

    create_mock_certutil "list-certs" ""

    SIGUL_ROLE="server"

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -eq 0 ]  # Should not fail, just skip missing files
    [[ "$output" == *"0 certificate(s) to NSS database"* ]]
}

# Test: import_nss_certificates skips already imported certificates
@test "import_nss_certificates: skips certificates already in NSS database" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"

    # Create certutil that shows certificate already exists
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
case "$1" in
    "-L")  # List certificates - show it exists
        if [[ "$*" == *"sigul-ca-cert"* ]] || [[ "$*" == *"sigul-server-cert"* ]]; then
            echo "Certificate exists"
            exit 0
        else
            echo "Certificate not found"
            exit 1
        fi
        ;;
    "-A")  # Should not be called since cert exists
        echo "ERROR: Should not try to import existing certificate"
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    SIGUL_ROLE="server"

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"already exists"* ]]
    [[ "$output" == *"skipping import"* ]]
}

# Test: import_nss_certificates handles private key import failure
@test "import_nss_certificates: handles private key import failure for daemon roles" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    # Create certutil that succeeds for certificate import
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
case "$1" in
    "-A")  # Add certificate
        echo "Certificate imported successfully"
        exit 0
        ;;
    "-L")  # List certificates - not found initially
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    # Create pk12util that fails for private key import
    cat > "$BATS_TEST_TMPDIR/bin/pk12util" << 'EOF'
#!/bin/bash
echo "ERROR: Failed to import private key"
exit 1
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/pk12util"

    SIGUL_ROLE="server"  # Daemon role - private key failure is fatal

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Failed to import private key"* ]]
    [[ "$output" == *"fatal for daemon roles"* ]]
}

# Test: import_nss_certificates handles private key import failure for client role
@test "import_nss_certificates: warns on private key import failure for client role" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/client" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/client.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/client-key.pem" "valid"

    # Create certutil that succeeds for certificate import
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
case "$1" in
    "-A")  # Add certificate
        echo "Certificate imported successfully"
        exit 0
        ;;
    "-L")  # List certificates - not found initially
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    # Create pk12util that fails for private key import
    cat > "$BATS_TEST_TMPDIR/bin/pk12util" << 'EOF'
#!/bin/bash
echo "ERROR: Failed to import private key"
exit 1
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/pk12util"

    SIGUL_ROLE="client"  # Non-daemon role - should warn but continue

    # Execute
    run import_nss_certificates "client"

    # Verify
    [ "$status" -eq 0 ]  # Should succeed despite key import failure
    [[ "$output" == *"Failed to import private key"* ]]
    [[ "$output" == *"Warning:"* ]]
}

# Test: import_nss_certificates handles PKCS12 file creation failure
@test "import_nss_certificates: handles PKCS12 file creation failure" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server-key.pem" "valid"

    # Create mock openssl that fails PKCS12 creation
    cat > "$BATS_TEST_TMPDIR/bin/openssl" << 'EOF'
#!/bin/bash
if [[ "$1" == "pkcs12" ]]; then
    echo "ERROR: Failed to create PKCS12 file"
    exit 1
else
    echo "mock openssl operation"
    exit 0
fi
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/openssl"

    create_mock_certutil "list-certs" ""

    SIGUL_ROLE="server"  # Daemon role - PKCS12 failure is fatal

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Failed to create PKCS#12 file"* ]]
    [[ "$output" == *"fatal for daemon roles"* ]]
}

# Test: import_nss_certificates with bridge role certificates
@test "import_nss_certificates: successfully imports bridge role certificates" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/bridge" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/bridge.crt" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/bridge-key.pem" "valid"

    # Create successful mock commands
    create_mock_certutil "list-certs" ""  # Not found initially
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
case "$1" in
    "-A")  # Add certificate
        echo "Certificate imported successfully"
        exit 0
        ;;
    "-L")  # List certificates - not found initially
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    cat > "$BATS_TEST_TMPDIR/bin/pk12util" << 'EOF'
#!/bin/bash
echo "Private key imported successfully"
exit 0
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/pk12util"

    SIGUL_ROLE="bridge"

    # Execute
    run import_nss_certificates "bridge"

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"certificate(s) to NSS database for role: bridge"* ]]
}

# Test: import_nss_certificates with missing NSS password
@test "import_nss_certificates: fails with missing NSS password" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"
    rm -f "$SIGUL_BASE_DIR/secrets/nss_password"  # Remove password file

    SIGUL_ROLE="server"

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -ne 0 ]
    [[ "$output" == *"Failed to load NSS password"* ]]
}

# Test: import_nss_certificates debug output
@test "import_nss_certificates: provides debug information when DEBUG=true" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/ca.crt" "valid"

    create_mock_certutil "list-certs" ""
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
case "$1" in
    "-A")  # Add certificate
        echo "Certificate imported successfully"
        exit 0
        ;;
    "-L")  # List certificates - not found initially
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    SIGUL_ROLE="server"
    # shellcheck disable=SC2034
    DEBUG="true"

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"Importing certificates to NSS database for role: server"* ]]
}

# Test: import_nss_certificates certificate nickname mapping
@test "import_nss_certificates: correctly maps certificate files to nicknames" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/bridge" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/bridge.crt" "valid"

    # Create certutil that logs the nickname being used
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
case "$1" in
    "-A")  # Add certificate - log the nickname
        for arg in "$@"; do
            if [[ "$prev_arg" == "-n" ]]; then
                echo "Importing with nickname: $arg"
                break
            fi
            prev_arg="$arg"
        done
        exit 0
        ;;
    "-L")  # List certificates - not found initially
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    SIGUL_ROLE="bridge"

    # Execute
    run import_nss_certificates "bridge"

    # Verify correct nickname mapping
    [ "$status" -eq 0 ]
    [[ "$output" == *"sigul-bridge-cert"* ]]
}

# Test: import_nss_certificates handles certificate import failure
@test "import_nss_certificates: handles certificate import failure gracefully" {
    # Setup
    create_mock_nss_database "$SIGUL_BASE_DIR/nss/server" "valid"
    create_mock_certificate "$SIGUL_BASE_DIR/secrets/certificates/server.crt" "valid"

    # Create certutil that fails certificate import
    cat > "$BATS_TEST_TMPDIR/bin/certutil" << 'EOF'
#!/bin/bash
case "$1" in
    "-A")  # Add certificate - fail
        echo "ERROR: Certificate import failed"
        exit 1
        ;;
    "-L")  # List certificates - not found initially
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/certutil"

    # shellcheck disable=SC2034
    SIGUL_ROLE="server"

    # Execute
    run import_nss_certificates "server"

    # Verify
    [ "$status" -eq 0 ]  # Should continue despite failure
    [[ "$output" == *"Failed to import certificate"* ]]
}
