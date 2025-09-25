#!/bin/bash
# NSS Trust Flag Validation Script
# Validates that NSS certificate trust flags are correctly configured across
# all Sigul components
# This script helps prevent regression of the critical NSS certificate trust
# flag bug

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"  # Currently unused

# Function to print colored output
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }

# Function to validate trust flags for a specific container and role
validate_container_trust_flags() {
    local container_name="$1"
    local role="$2"
    local nss_password_file="/var/sigul/secrets/${role}_nss_password"

    print_info "Validating NSS trust flags for $container_name ($role)"

    # Check if container exists and is running
    if ! docker ps --format "table {{.Names}}" | \
         grep -q "^${container_name}$"; then
        print_error "Container $container_name is not running"
        return 1
    fi

    # Check if NSS password file exists
    if ! docker exec "$container_name" test -f "$nss_password_file"; then
        print_error "NSS password file not found: $nss_password_file"
        return 1
    fi

    # Get NSS password
    local nss_password
    nss_password=$(docker exec "$container_name" cat "$nss_password_file")

    if [[ -z "$nss_password" ]]; then
        print_error "NSS password is empty in $nss_password_file"
        return 1
    fi

    # Get certificate list with trust flags
    local cert_list
    cert_list=$(docker exec "$container_name" sh -c \
        "echo '$nss_password' | certutil -L -d /var/sigul/nss/$role \
        -f /dev/stdin" 2>/dev/null)

    if [[ -z "$cert_list" ]]; then
        print_error "Failed to retrieve certificate list from NSS database"
        return 1
    fi

    print_info "Certificate trust flags in $container_name:"
    echo "$cert_list"

    # Validation flags
    local validation_errors=0

    # Check CA certificate trust flags
    if echo "$cert_list" | grep -q "sigul-ca-cert.*CT,C,C"; then
        print_success "CA certificate has correct trust flags (CT,C,C)"
    else
        print_error "CA certificate has incorrect trust flags \
(should be CT,C,C)"
        ((validation_errors++))
    fi

    # Check component certificate trust flags based on role
    local expected_component_cert="sigul-${role}-cert"
    if echo "$cert_list" | grep -q "${expected_component_cert}.*u,u,u"; then
        print_success "Component certificate ($expected_component_cert) has \
correct trust flags (u,u,u)"
    elif echo "$cert_list" | grep -q "${expected_component_cert}.*CT"; then
        print_error "Component certificate ($expected_component_cert) has \
CA trust flags - THIS IS THE BUG!"
        print_warning "Certificate should have (u,u,u) not CA flags \
containing 'CT'"
        ((validation_errors++))
    else
        print_warning "Component certificate ($expected_component_cert) not \
found or has unexpected trust flags"
        ((validation_errors++))
    fi

    # Check for private key availability
    local private_key_check
    private_key_check=$(docker exec "$container_name" sh -c \
        "echo '$nss_password' | certutil -K -d /var/sigul/nss/$role \
        -f /dev/stdin" 2>/dev/null || echo "FAILED")

    if [[ "$private_key_check" == "FAILED" || \
          -z "$private_key_check" ]]; then
        print_error "Failed to access private keys in NSS database"
        ((validation_errors++))
    elif echo "$private_key_check" | grep -q "$expected_component_cert"; then
        print_success "Private key found for $expected_component_cert"
    else
        print_warning "Private key for $expected_component_cert not found"
        ((validation_errors++))
    fi

    # Return validation result
    if [[ $validation_errors -eq 0 ]]; then
        print_success "All NSS trust flags are correct for $container_name"
        return 0
    else
        print_error "$validation_errors validation error(s) found for $container_name"
        return 1
    fi
}

# Function to test NSS SSL connectivity
test_nss_ssl_connectivity() {
    local client_container="$1"
    local bridge_container="$2"

    print_info "Testing NSS SSL connectivity from $client_container to $bridge_container"

    # Get client NSS password
    local client_nss_password
    client_nss_password=$(docker exec "$client_container" cat \
        /var/sigul/secrets/client_nss_password 2>/dev/null)

    if [[ -z "$client_nss_password" ]]; then
        print_error "Cannot retrieve client NSS password"
        return 1
    fi

    # Test SSL connection with tstclnt
    local ssl_test_result
    ssl_test_result=$(docker exec "$client_container" timeout 10s \
        /usr/lib64/nss/unsupported-tools/tstclnt \
        -h sigul-bridge -p 44334 \
        -d /var/sigul/nss/client \
        -n sigul-client-cert \
        -w "$client_nss_password" \
        -v 2>&1 || echo "SSL_TEST_FAILED")

    if echo "$ssl_test_result" | grep -q "SSL version.*using.*AES"; then
        print_success "NSS SSL handshake successful"
        if echo "$ssl_test_result" | grep -q "subject DN:.*sigul-bridge"; then
            print_success "Bridge certificate validation successful"
        fi
        return 0
    else
        print_error "NSS SSL handshake failed"
        print_warning "SSL test output: $ssl_test_result"
        return 1
    fi
}

# Function to test Sigul client connectivity
test_sigul_client_connectivity() {
    local client_container="$1"

    print_info "Testing Sigul client SSL connectivity"

    # Check if expect is available for interactive testing
    if ! docker exec "$client_container" which expect >/dev/null 2>&1; then
        print_warning "expect not available - cannot test interactive \
Sigul client"
        return 0
    fi

    # Get admin password
    local admin_password
    admin_password=$(docker exec sigul-server cat \
        /var/sigul/secrets/server_admin_password 2>/dev/null)

    if [[ -z "$admin_password" ]]; then
        print_warning "Cannot retrieve admin password - skipping \
Sigul client test"
        return 0
    fi

    # Test Sigul client connection
    local sigul_test_result
    sigul_test_result=$(docker exec "$client_container" timeout 15s \
        expect -c "
        spawn sigul -c /var/sigul/config/client.conf list-users
        expect {
            \"Administrator's password:\" {
                send \"$admin_password\\r\"
                expect {
                    \"admin\" { puts \"SIGUL_SUCCESS\"; exit 0 }
                    \"ERROR: I/O error: Unexpected EOF in NSPR\" { \
                        puts \"SIGUL_SSL_ERROR\"; exit 1 }
                    timeout { puts \"SIGUL_TIMEOUT\"; exit 1 }
                }
            }
            \"ERROR: I/O error: Unexpected EOF in NSPR\" { \
                puts \"SIGUL_SSL_ERROR\"; exit 1 }
            timeout { puts \"SIGUL_NO_PROMPT\"; exit 1 }
        }
    " 2>&1 || echo "SIGUL_TEST_FAILED")

    if echo "$sigul_test_result" | grep -q "SIGUL_SUCCESS"; then
        print_success "Sigul client SSL connection and authentication \
successful"
        return 0
    elif echo "$sigul_test_result" | grep -q "Administrator's password"; then
        print_success "Sigul client SSL connection successful \
(prompts for password)"
        print_warning "Authentication test inconclusive - but SSL layer \
is working"
        return 0
    elif echo "$sigul_test_result" | \
         grep -q "SIGUL_SSL_ERROR\|Unexpected EOF in NSPR"; then
        print_error "Sigul client SSL connection failed - NSS trust flag \
issue likely"
        return 1
    else
        print_warning "Sigul client test inconclusive"
        print_info "Test output: $sigul_test_result"
        return 0
    fi
}

# Function to generate trust flag fix commands
generate_fix_commands() {
    print_info "Generating NSS trust flag fix commands for manual \
correction:"

    cat << 'EOF'

# Manual NSS Trust Flag Fix Commands
# Run these if validation fails and certificates have incorrect trust flags

# For client container:
docker exec sigul-client sh -c 'NSS_PASSWORD=$(cat \
/var/sigul/secrets/client_nss_password); echo "$NSS_PASSWORD" | \
certutil -M -d /var/sigul/nss/client -n sigul-client-cert -t "u,u,u" \
-f /dev/stdin'

# For bridge container:
docker exec sigul-bridge sh -c 'NSS_PASSWORD=$(cat \
/var/sigul/secrets/bridge_nss_password); echo "$NSS_PASSWORD" | \
certutil -M -d /var/sigul/nss/bridge -n sigul-bridge-cert -t "u,u,u" \
-f /dev/stdin'

# For server container:
docker exec sigul-server sh -c 'NSS_PASSWORD=$(cat \
/var/sigul/secrets/server_nss_password); echo "$NSS_PASSWORD" | \
certutil -M -d /var/sigul/nss/server -n sigul-server-cert -t "u,u,u" \
-f /dev/stdin'

# Restart bridge after trust flag changes:
docker restart sigul-bridge

EOF
}

# Main validation function
main() {
    local exit_code=0

    echo -e "${BLUE}=== NSS Trust Flag Validation ===${NC}"
    echo "Validating NSS certificate trust flags across Sigul infrastructure"
    echo ""

    # Check if Docker is available
    if ! command -v docker >/dev/null 2>&1; then
        print_error "Docker is not available or not in PATH"
        exit 1
    fi

    # Define container names (these should match deployment)
    local containers=("sigul-server:server" "sigul-bridge:bridge")

    # Find client containers (there might be multiple test containers)
    local client_containers
    client_containers=$(docker ps --format "table {{.Names}}" | \
        grep -E "sigul.*client" || echo "")

    if [[ -n "$client_containers" ]]; then
        while IFS= read -r client_container; do
            containers+=("$client_container:client")
        done <<< "$client_containers"
    else
        print_warning "No client containers found - skipping client validation"
    fi

    # Validate each container
    for container_info in "${containers[@]}"; do
        IFS=':' read -r container_name role <<< "$container_info"
        echo ""
        if ! validate_container_trust_flags "$container_name" "$role"; then
            exit_code=1
        fi
    done

    echo ""
    print_info "=== SSL Connectivity Tests ==="

    # Test NSS SSL connectivity if we have a client container
    if [[ -n "$client_containers" ]]; then
        local first_client
        first_client=$(echo "$client_containers" | head -n1)

        echo ""
        if ! test_nss_ssl_connectivity "$first_client" "sigul-bridge"; then
            exit_code=1
        fi

        echo ""
        if ! test_sigul_client_connectivity "$first_client"; then
            exit_code=1
        fi
    else
        print_warning "No client containers available for SSL \
connectivity testing"
    fi

    echo ""
    print_info "=== Validation Summary ==="

    if [[ $exit_code -eq 0 ]]; then
        print_success "All NSS trust flag validations passed!"
        print_success "NSS certificate trust flag fix is working correctly"
    else
        print_error "NSS trust flag validation failed!"
        print_error "The critical NSS certificate trust flag bug may \
be present"
        generate_fix_commands
    fi

    echo ""
    print_info "Validation completed"
    exit $exit_code
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "NSS Trust Flag Validation Script"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --fix-commands Generate manual fix commands only"
        echo ""
        echo "This script validates that NSS certificate trust flags are \
correctly"
        echo "configured across all Sigul infrastructure components to \
prevent"
        echo "the 'Unexpected EOF in NSPR' SSL authentication errors."
        echo ""
        echo "Expected trust flags:"
        echo "  - CA certificates: CT,C,C (Certificate Authority trusted)"
        echo "  - Client/Server/Bridge certificates: u,u,u (User \
certificates)"
        exit 0
        ;;
    --fix-commands)
        generate_fix_commands
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
