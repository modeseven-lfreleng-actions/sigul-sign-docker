<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Sigul Debugging Tools and Process

## Critical Process Rule: Fresh Containers Only

**🚨 NEVER debug SSL issues against persistent containers**

The Sigul stack works correctly in CI/CD because it uses fresh containers with automatic certificate synchronization. Local debugging must follow the same pattern.

## Quick Start: Correct Testing Process

```bash
# 1. Complete cleanup (removes stale certificate state)
./debug/correct_testing_process.sh --verbose

# 2. If that works, the issue is not SSL-related
# 3. Focus on authentication/application layer issues
```

## Available Tools

### `correct_testing_process.sh`

**Primary debugging tool** - Demonstrates the correct fresh-container process that mirrors CI/CD behavior.

```bash
./debug/correct_testing_process.sh --verbose --platform linux-arm64
```

### `verify_ssl_topology.sh`

Empirically determines SSL connection topology and certificate presence.

```bash
./debug/verify_ssl_topology.sh --verbose
```

### `fix_backend_ssl_certs.sh`

Manual certificate exchange fix (should NOT be needed for fresh deployments).

```bash
./debug/fix_backend_ssl_certs.sh --verbose
```

## Debugging Decision Tree

### 1. Start Here: Fresh Deployment Test

```bash
./debug/correct_testing_process.sh --verbose
```

**If this succeeds**: SSL layers work correctly, focus on authentication/application issues.

**If this fails with SSL errors**: There's a bug in the initialization scripts.

### 2. SSL Layer Issues

If you see "Unexpected EOF in NSPR" errors in fresh deployments:

```bash
# Verify certificate synchronization
./debug/verify_ssl_topology.sh --verbose

# Check initialization logs
docker logs sigul-bridge | grep -i cert
docker logs sigul-server | grep -i cert
```

### 3. Authentication Layer Issues

If SSL succeeds but commands fail with password/auth errors:

```bash
# Check admin password propagation
cat test-artifacts/admin-password

# Test manual authentication
echo "password" | docker exec -i sigul-client-integration \
    sigul -c /var/sigul/config/client.conf list-users
```

### 4. Application Layer Issues

If authentication succeeds but signing operations fail:

```bash
# Test signing workflow
echo "password" | docker exec -i sigul-client-integration \
    sigul -c /var/sigul/config/client.conf list-keys
```

## Common Mistakes to Avoid

### ❌ Wrong: Debugging Persistent Containers

```bash
# DON'T DO THIS - leads to SSL certificate confusion
docker exec sigul-bridge certutil -A ...  # manual cert fixes
```

### ✅ Right: Fresh Container Testing

```bash
# DO THIS - mirrors CI/CD behavior
docker compose down -v --remove-orphans
./scripts/deploy-sigul-infrastructure.sh --verbose
```

### ❌ Wrong: Assuming CI/CD Issues Exist Locally

Just because you see SSL errors locally doesn't mean CI/CD has the same problem.

### ✅ Right: Verify CI/CD Parity

Always test with fresh containers first to match CI/CD behavior.

## Layer Verification Checklist

### SSL Layer ✓

- [ ] Bridge listens on ports 44334 and 44333
- [ ] Server connects to bridge on port 44333
- [ ] Bridge NSS DB contains server and client certificates (P,,)
- [ ] Server NSS DB contains bridge certificate (P,,)
- [ ] No "Unexpected EOF in NSPR" errors

### Authentication Layer

- [ ] Admin user creation succeeds during deployment
- [ ] Ephemeral passwords propagated correctly
- [ ] `list-users` command works without SSL errors
- [ ] Password input handling works in container environment

### Application Layer

- [ ] `list-keys` command succeeds
- [ ] `new-key` operations work
- [ ] `sign-data` operations complete
- [ ] Signature files created and valid

## Architecture Reference

### SSL Connection Topology

```
Client (port varies) ─── TLS ───> Bridge:44334 (Client Access)
                                     │
                                     │ Bridge Process
                                     │
Server (port varies) ─── TLS ───> Bridge:44333 (Backend Control)
```

### Certificate Requirements

```
Bridge NSS DB must contain:
- sigul-ca-cert (CT,C,C)
- sigul-bridge-cert (CTu,Cu,Cu)
- sigul-server-cert (P,,)     ← For backend TLS
- sigul-client-cert (P,,)     ← For client TLS (added when client starts)

Server NSS DB must contain:
- sigul-ca-cert (CT,C,C)
- sigul-server-cert (CTu,Cu,Cu)
- sigul-bridge-cert (P,,)     ← For backend TLS
```

## Next Steps After SSL Resolution

Once SSL layers work correctly in fresh deployments, focus debugging on:

1. **Admin User Creation**: Server initialization process
2. **Password Handling**: Environment variable propagation
3. **Authentication Flow**: Client→Bridge→Server request routing
4. **Signing Operations**: End-to-end cryptographic workflow

The SSL certificate exchange is handled automatically by the initialization scripts and should not require manual intervention when using fresh container deployments.
