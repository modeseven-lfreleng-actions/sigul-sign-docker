<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Sigul Communication Troubleshooting Guide

This guide helps diagnose and fix communication issues between Sigul client,
bridge, and server components.

## Quick Start

1. **Run the debugging script**:

   ```bash
   chmod +x debug/reproduce-communication-issue.sh
   ./debug/reproduce-communication-issue.sh --quick --verbose
   ```

2. **Check the summary report**:

   ```bash
   # Look for the latest debug session
   ls -la debug/logs-*/SUMMARY_REPORT.md | tail -1
   ```

## Common Issues and Solutions

### 1. Exit Code 2 - Client-Server Communication Failure

**Symptoms:**

- All sigul commands fail with exit code 2
- Client can't connect to bridge/server
- Logs show connection timeouts or authentication failures

**Diagnosis:**

```bash
# Test client connectivity
docker exec sigul-client-debug sigul -c /var/sigul/config/client.conf list-users --password $(cat pki/admin_password)

# Check if containers can ping each other
docker exec sigul-server ping -c 3 sigul-bridge
docker exec sigul-bridge ping -c 3 sigul-server
```

**Common Causes:**

- **Certificate/PKI Issues**: Invalid or mismatched certificates
- **Network Connectivity**: Containers can't reach each other
- **Port Binding**: Bridge ports not accessible
- **NSS Database Problems**: Corrupted or missing NSS databases

### 2. Certificate/PKI Problems

**Symptoms:**

- SSL/TLS handshake failures
- Certificate validation errors
- NSS database errors

**Diagnosis:**

```bash
# Check certificate files exist
docker exec sigul-server find /var/sigul/secrets/certificates \
  -name "*.crt" -exec ls -la {} \;

# Check certificate chains
docker exec sigul-server openssl verify \
  -CAfile /var/sigul/secrets/certificates/ca.crt \
  /var/sigul/secrets/certificates/server.crt

# Check NSS certificate nicknames
docker exec sigul-server certutil -L -d /var/sigul/nss/server
```

**Solutions:**

- Regenerate certificates with proper CA chain
- Verify certificate dates (not expired)
- Check NSS database integrity
- Ensure consistent certificate nicknames

### 3. Network Connectivity Issues

**Symptoms:**

- Connection refused errors
- Timeout errors
- DNS resolution failures

**Diagnosis:**

```bash
# Check network connectivity
docker network ls --filter name=sigul
docker network inspect $(docker network ls --filter name=sigul \
  --format "{{.Name}}" | head -1)

# Test port connectivity
docker exec sigul-server nc -zv sigul-bridge 44334
docker exec sigul-bridge nc -zv sigul-server 44333
```

**Solutions:**

- Verify containers are on the same Docker network
- Check bridge port configuration (44334 for client, 44333 for server)
- Ensure no port conflicts with host system
- Verify DNS resolution between containers

### 4. NSS Database Corruption

**Symptoms:**

- NSS initialization failures
- Certificate import errors
- "database corrupted" errors

**Diagnosis:**

```bash
# Check NSS database files
docker exec sigul-server find /var/sigul/nss -name "*.db" -exec ls -la {} \;

# Test NSS database integrity
docker exec sigul-server certutil -V -n sigul-server-cert -d /var/sigul/nss/server
```

**Solutions:**

- Clean and recreate NSS databases
- Re-import all certificates with correct nicknames
- Verify NSS password files are accessible

## Advanced Debugging

### Enable Sigul Debug Mode

Add debug flags to sigul commands:
```bash
# Enable detailed verbosity
docker exec sigul-client-debug sigul \
  -c /var/sigul/config/client.conf -v \
  list-users --password $(cat pki/admin_password)
```

### Manual Step-by-Step Testing

1. **Test each component individually**:

   ```bash
   # Test server startup
   docker logs sigul-server | grep -i error

   # Test bridge startup
   docker logs sigul-bridge | grep -i error

   # Test client initialization
   docker logs sigul-client-debug | grep -i error
   ```

2. **Test network layer**:

   ```bash
   # From client to bridge
   docker exec sigul-client-debug telnet sigul-bridge 44334

   # From bridge to server
   docker exec sigul-bridge telnet sigul-server 44333
   ```

3. **Test certificate layer**:

   ```bash
   # Test SSL connection manually
   docker exec sigul-client-debug openssl s_client \
     -connect sigul-bridge:44334 \
     -cert /var/sigul/secrets/certificates/client.crt \
     -key /var/sigul/secrets/certificates/client.key
   ```

### Configuration Validation

Check critical configuration values:

**Client Configuration** (`/var/sigul/config/client.conf`):

```ini
[client]
bridge-hostname = sigul-bridge
bridge-port = 44334
```

**Bridge Configuration** (`/var/sigul/config/bridge.conf`):

```ini
[bridge]
client-listen-port = 44334
server-listen-port = 44333
server-hostname = sigul-server
```

**Server Configuration** (`/var/sigul/config/server.conf`):

```ini
[server]
bridge-hostname = sigul-bridge
bridge-port = 44333
```

## Debugging Workflow

1. **Start with quick test**:

   ```bash
   ./debug/reproduce-communication-issue.sh --quick --verbose
   ```

2. **Focus on specific areas**:

   ```bash
   # Certificate issues
   ./debug/reproduce-communication-issue.sh --debug-certs --verbose

   # Network issues
   ./debug/reproduce-communication-issue.sh --debug-network --verbose
   ```

3. **Full reproduction**:

   ```bash
   ./debug/reproduce-communication-issue.sh --full --clean-start --verbose
   ```

4. **Review logs systematically**:
   - Check `SUMMARY_REPORT.md` for overview
   - Review `client-cmd-*.log` for specific command failures
   - Check `logs-*.log` for container startup issues
   - Examine `certs-*.log` for certificate problems

## Known Working Configuration

The following configuration should work for local testing:

- **Network**: Single Docker bridge network
- **Certificates**: Self-signed CA with proper certificate chain
- **Ports**: 44334 (client-bridge), 44333 (bridge-server)
- **NSS**: Separate databases for each component with proper nicknames

## Getting Help

If the issue persists:

1. **Collect full diagnostics**:

   ```bash
   ./debug/reproduce-communication-issue.sh --full --verbose
   ```

2. **Provide the following information**:
   - Platform/architecture (`uname -a`)
   - Docker version (`docker version`)
   - Complete log directory from debug session
   - Specific error messages from sigul commands

3. **Include test reproduction steps**:
   - Commands that fail
   - Expected vs actual behavior
   - Any configuration changes made

## Reference Links

- [Sigul Documentation](https://pagure.io/sigul)
- [NSS Tools Documentation](https://firefox-source-docs.mozilla.org/security/nss/legacy/tools/)
- [Docker Networking](https://docs.docker.com/network/)
