<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Sigul Stack Debugging: Process, Findings, and Next Steps

## Executive Summary

**Critical Discovery**: The SSL issues we encountered in local testing **DO NOT exist in CI/CD environments** because CI/CD deploys fresh containers with automatically synchronized certificates, while our local testing used persistent containers with stale certificate states.

**Status**: ✅ **SSL LAYERS FULLY RESOLVED** - All SSL certificate exchange issues have been fixed with manual certificate import scripts.

**Current Focus**: Admin user creation EOFError in batch mode - the remaining blocker for functional integration tests.

---

## Root Cause Analysis: Why We Were Debugging the Wrong Thing

### The Fundamental Mistake

We were debugging SSL certificate issues in **persistent local containers** while CI/CD was working because it uses **fresh container deployments** that automatically include correct certificate synchronization.

### What Actually Happens in CI/CD vs Local Testing

#### CI/CD Environment (Working)

```
1. Fresh containers deployed from scratch
2. Each container generates/receives certificates during initialization
3. Certificate exchange happens automatically in init scripts
4. All NSS databases populated with correct peer certificates
5. SSL handshakes succeed immediately
```

#### Our Local Testing (Broken)

```
1. Containers persisted across multiple test runs
2. Certificates generated at different times/sessions
3. NSS databases contained stale/mismatched peer certificates
4. SSL handshakes failed with "Unexpected EOF in NSPR"
5. Manual certificate fixes required to restore functionality
```

### SSL Certificate Exchange Resolution

**CORRECTION**: The original assumption that certificate exchange happens automatically was **incorrect**. Fresh containers only contain their own certificates and the CA certificate, not peer certificates.

**Actual Solution**: Manual certificate exchange is required and has been implemented in `debug/fix_backend_ssl_certs.sh`.

**Bridge NSS Database (After Manual Fix)**

```
Certificate Nickname                Trust Attributes
sigul-ca-cert                      CT,C,C     ← CA certificate
sigul-bridge-cert                  CTu,Cu,Cu  ← Bridge's own cert
sigul-server-cert                  P,,        ← Server peer cert (MANUALLY IMPORTED)
sigul-client-cert                  P,,        ← Client peer cert (IMPORTED BY INTEGRATION SCRIPT)
```

**Server NSS Database (After Manual Fix)**

```
Certificate Nickname                Trust Attributes
sigul-ca-cert                      CT,C,C     ← CA certificate
sigul-server-cert                  CTu,Cu,Cu  ← Server's own cert
sigul-bridge-cert                  P,,        ← Bridge peer cert (MANUALLY IMPORTED)
```

This certificate exchange **must be performed manually** after each fresh deployment to enable SSL connectivity.

---

## SSL Architecture Clarification

### Actual Topology (Empirically Verified)

The Sigul stack uses **two independent TLS connections**, not nested tunnels:

#### TLS Connection 1: Client Access Plane

- **Direction**: Client → Bridge
- **Port**: 44334
- **Bridge role**: TLS Server (listens)
- **Authentication**: Mutual TLS (client cert required)
- **Status**: ✅ Working in fresh deployments

#### TLS Connection 2: Backend Control Plane

- **Direction**: Server → Bridge
- **Port**: 44333
- **Bridge role**: TLS Server (listens on both ports)
- **Authentication**: Mutual TLS (server cert required)
- **Status**: ✅ Working in fresh deployments

### Socket Verification Results

```bash
# Bridge container (listening on both ports)
$ docker exec sigul-bridge ss -tlnp | grep 4433
LISTEN 0 5 0.0.0.0:44334 0.0.0.0:*    # Client access
LISTEN 0 5 0.0.0.0:44333 0.0.0.0:*    # Server backend

# Server container (connects to bridge)
$ docker exec sigul-server ss -tn | grep 44333
ESTAB 0 0 172.20.0.3:43250 172.20.0.4:44333   # Connected to bridge
```

---

## Correct Local Testing Process

### Prerequisites: Always Use Fresh Containers

**CRITICAL**: Never debug SSL issues against persistent containers. Always deploy fresh.

### Step-by-Step Correct Process

#### 1. Clean Environment

```bash
# Complete cleanup of persistent state
docker compose -f docker-compose.sigul.yml down -v --remove-orphans
docker system prune -f
docker volume prune -f
```

#### 2. Deploy Fresh Infrastructure

```bash
# Set platform environment
export SIGUL_RUNNER_PLATFORM="linux-arm64"  # or linux-amd64
export SIGUL_SERVER_IMAGE="server-linux-arm64-image:test"
export SIGUL_BRIDGE_IMAGE="bridge-linux-arm64-image:test"

# Deploy fresh containers
./scripts/deploy-sigul-infrastructure.sh --verbose
```

#### 3. Fix SSL Certificate Exchange

```bash
# REQUIRED: Exchange server and bridge certificates
./debug/fix_backend_ssl_certs.sh --verbose

# Verify SSL topology is now complete
echo "=== Bridge NSS DB ==="
docker exec sigul-bridge certutil -L -d /var/sigul/nss/bridge

echo "=== Server NSS DB ==="
docker exec sigul-server certutil -L -d /var/sigul/nss/server

# Verify socket topology
echo "=== Socket Status ==="
docker exec sigul-bridge ss -tlnp | grep 4433
docker exec sigul-server ss -tn | grep 44333
```

#### 4. Run Integration Tests

```bash
export SIGUL_CLIENT_IMAGE="client-linux-arm64-image:test"
./scripts/run-integration-tests.sh --verbose
```

**Expected Result**: No SSL errors ("Unexpected EOF in NSPR"), but authentication failures (EOFError during admin user creation).

---

## Current Status and Next Focus Areas

### ✅ Resolved Issues

- SSL certificate exchange (implemented manual fix script: `debug/fix_backend_ssl_certs.sh`)
- TLS handshake failures between client↔bridge and server↔bridge
- Architecture confusion (two independent TLS connections, not nested tunnels)
- Local vs CI/CD testing discrepancy (fresh vs persistent containers)
- Network connectivity and socket topology verification

### 🎯 Current Focus Areas (Priority Order)

#### Priority 1: Admin User Creation Failure (ACTIVE ISSUE)

**Symptoms**:

```
EOFError: Unexpected EOF when reading a batch mode password
Administrator user name: Traceback (most recent call last):
  File "/usr/share/sigul/server_add_admin.py", line 68, in main
    password = utils.read_password(config, 'Administrator password: ')
  File "/usr/share/sigul/utils.py", line 1136, in read_password
    raise EOFError('Unexpected EOF when reading a batch mode password')
```

**Root Cause**: The `sigul_server_add_admin --batch` command expects username and password via stdin, but the password input is not being provided correctly.

**Investigation needed**:

- Fix stdin password piping in batch mode
- Alternative admin user creation methods
- Bypass admin creation for testing client-server connectivity

#### Priority 2: Authentication Layer Issues

**Symptoms**: Commands fail after SSL connection succeeds

**Investigation needed**:

- Admin password propagation between deployment and integration test scripts
- User database initialization timing
- NSS password configuration consistency

#### Priority 3: Application Layer Protocol

**Investigation needed**:

- End-to-end request/response flow through bridge forwarding
- Signing operation workflow after authentication succeeds
- Bridge request routing between client and server

---

## Debugging Tools and Verification Scripts

### SSL Certificate Exchange Fix (REQUIRED)

```bash
# Fix backend SSL certificate exchange between server and bridge
./debug/fix_backend_ssl_certs.sh --verbose
```

### Client Connection Testing

```bash
# Test basic client-server connectivity through SSL layer
./debug/test_client_connection.sh --verbose
```

### Integration Test Health Check

```bash
# Run integration tests (will fail at auth layer, but SSL should work)
export SIGUL_CLIENT_IMAGE="client-linux-arm64-image:test"
timeout 60 ./scripts/run-integration-tests.sh --verbose 2>&1 | grep -E "(SUCCESS|FAILED|ERROR|EOF)"
```

### SSL Layer Verification

```bash
# Verify all certificates are properly exchanged
echo "=== Bridge NSS Database ==="
docker exec sigul-bridge certutil -L -d /var/sigul/nss/bridge
echo "=== Server NSS Database ==="
docker exec sigul-server certutil -L -d /var/sigul/nss/server
```

---

## Lessons Learned

### What Went Wrong in Our Approach

1. **Persistent Container Assumption**: We assumed local testing should use long-running containers like a production environment
2. **Manual Fix Mentality**: We focused on manual certificate fixes rather than understanding automatic initialization
3. **CI/CD Disconnect**: We didn't verify that our local issues existed in the working CI/CD environment
4. **Architecture Misunderstanding**: We assumed nested SSL tunnels rather than independent TLS connections

### What to Do Differently

1. **Fresh Deployment First**: Always start debugging with completely fresh container deployments
2. **CI/CD Parity**: Ensure local testing mirrors CI/CD deployment process exactly
3. **Empirical Verification**: Use socket inspection and certificate enumeration before assuming problems
4. **Layer Isolation**: Verify each layer (SSL, auth, application) independently before investigating interactions

---

## Deployment Script Requirements

### Critical: Manual Certificate Exchange Required

The deployment scripts **DO NOT** perform automatic certificate exchange between server and bridge. This must be done manually after each deployment using the provided fix script.

**Required action after every deployment:**

```bash
./debug/fix_backend_ssl_certs.sh --verbose
```

### Next Steps for Deployment Scripts

1. **PRIORITY**: Fix admin user creation EOFError in batch mode
2. Integrate automatic certificate exchange into deployment process
3. Improve password propagation between deployment and integration testing
4. Better error handling and diagnostics for authentication failures

---

## Success Criteria for Next Phase

### ✅ SSL Layer (Completed)

- Manual certificate exchange script working (`debug/fix_backend_ssl_certs.sh`)
- No "Unexpected EOF in NSPR" errors after certificate fix
- TLS handshakes succeed on both port 44334 and 44333
- All peer certificates properly imported with correct trust flags

### 🎯 Authentication Layer (Current Target)

- **BLOCKER**: Admin user creation fails with EOFError in batch mode
- Fix stdin password piping to `sigul_server_add_admin --batch`
- Alternative: bypass admin creation for connectivity testing
- Integration tests should proceed past SSL to authentication failures

### 🎯 Application Layer (Future Target)

- Actual signing operations complete successfully
- Files can be signed and signatures verified
- End-to-end cryptographic workflow functional

---

## Key Commands for Next Phase Debugging

### Admin User Investigation

```bash
# Check server logs for admin creation failure
docker logs sigul-server | grep -A10 -B5 admin

# Verify admin password is available
docker exec sigul-server cat /var/sigul/secrets/server_admin_password

# Test manual admin creation (will likely fail with same EOFError)
admin_password=$(docker exec sigul-server cat /var/sigul/secrets/server_admin_password)
echo -e "admin\n$admin_password" | docker exec -i sigul-server \
    sigul_server_add_admin --config-file=/var/sigul/config/server.conf --batch
```

### SSL Layer Verification After Each Deployment

```bash
# REQUIRED: Fix certificate exchange before testing
./debug/fix_backend_ssl_certs.sh --verbose

# Test client connectivity (should work at SSL layer)
./debug/test_client_connection.sh --verbose
```

### Integration Test Debugging

```bash
# Run integration tests and check for SSL vs auth failures
export SIGUL_CLIENT_IMAGE="client-linux-arm64-image:test"
./scripts/run-integration-tests.sh --verbose 2>&1 | grep -E "(NSPR|EOF|admin|password)"
```

---

**Next Action**: Fix the EOFError in admin user creation batch mode. This is the primary blocker preventing integration tests from proceeding past the authentication layer.
