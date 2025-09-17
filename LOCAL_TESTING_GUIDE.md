# Local Sigul Testing Environment - Complete Guide

This guide provides a comprehensive solution for testing the Sigul stack locally on macOS ARM64 systems, bypassing the challenges encountered in GitHub CI deployment.

## Overview

We've created a complete local testing environment that allows you to:

- **Test the full Sigul stack locally** before deploying to CI
- **Debug certificate and configuration issues** with full container access
- **Iterate quickly** on deployment scripts and configurations
- **Validate ARM64 compatibility** on Apple Silicon Macs
- **Get detailed diagnostics** when things go wrong

## Problem Statement

The original GitHub CI workflow (`build-test.yaml`) was experiencing deployment issues:

- Certificate installation/setup problems
- Container deployment failures preventing process startup
- Difficulty getting useful feedback/logs from containers
- Time wasted on CI debugging cycles

## Solution Architecture

### Local Testing Stack

The solution provides three main components:

1. **Deployment Automation** (`deploy-local-sigul-stack.sh`)
   - Automated container building for ARM64
   - Environment configuration generation
   - Certificate and PKI setup
   - Health checks and integration tests

2. **Environment Management** (`manage-local-env.sh`)
   - Easy start/stop/restart operations
   - Log viewing and analysis
   - Container shell access
   - Health monitoring

3. **Component Testing** (`test-components.sh`)
   - Individual component validation
   - Detailed diagnostic collection
   - Build, configuration, startup, and health testing
   - Network connectivity validation

### Container Components

- **sigul-server**: Core signing service with SQLite database
- **sigul-bridge**: Communication bridge (ports 44334/44333)
- **sigul-client-test**: Client environment for testing
- **network-tester**: Network connectivity diagnostics
- **health-monitor**: Real-time service monitoring
- **debug-helper**: Debug tools and utilities

## Quick Start

### Prerequisites

- Docker Desktop for macOS (with ARM64 support)
- macOS running on Apple Silicon (ARM64)
- At least 5GB free disk space

### Option 1: Interactive Setup (Recommended)

```bash
cd sigul-sign-docker
./local-testing/getting-started.sh
```

This provides a guided setup experience with explanations.

### Option 2: Direct Deployment

```bash
cd sigul-sign-docker
./local-testing/deploy-local-sigul-stack.sh --build-local --verbose
```

### Option 3: Validation First

```bash
cd sigul-sign-docker
./local-testing/validate-setup.sh --verbose
```

Check prerequisites before attempting deployment.

## Key Features

### 1. ARM64 Optimization

All containers are built specifically for ARM64 architecture:

- Platform-specific builds using Docker BuildKit
- Optimized for Apple Silicon performance
- Consistent with CI multi-architecture approach

### 2. Unified Directory Structure

All components use `/var/sigul` for consistency:

- `/var/sigul/config/` - Configuration files
- `/var/sigul/secrets/` - Certificates and keys
- `/var/sigul/nss/` - NSS databases
- `/var/sigul/logs/` - Application logs

### 3. Certificate Management

Automated PKI setup using existing scripts:

- CA certificate generation
- Component-specific certificates
- NSS database initialization
- Certificate validation testing

### 4. Comprehensive Monitoring

Multiple monitoring and debugging tools:

- Real-time health checks
- Process monitoring
- Network connectivity testing
- Log analysis and collection

### 5. Environment Isolation

Clean Docker environment with:

- Dedicated Docker network (172.20.0.0/16)
- Volume persistence for data
- Service discovery via DNS
- Port mapping for external access

## Daily Workflow

### Starting Your Session

```bash
# Quick start
./local-testing/manage-local-env.sh start

# Check everything is running
./local-testing/manage-local-env.sh status
```

### Development and Testing

```bash
# Make code changes...

# Test specific component
./local-testing/test-components.sh server startup --verbose

# Check logs
./local-testing/manage-local-env.sh logs server

# Debug in container
./local-testing/manage-local-env.sh shell server
```

### Debugging Issues

```bash
# Start comprehensive debug session
./local-testing/manage-local-env.sh debug

# Test network connectivity
./local-testing/test-components.sh network

# Analyze logs for errors
./local-testing/test-components.sh server logs
```

### Clean Restart

```bash
# Complete environment reset
./local-testing/manage-local-env.sh reset
```

## Troubleshooting Common Issues

### Container Build Failures

**Symptoms**: Docker build errors, missing dependencies
**Solution**:

```bash
# Check build logs
./local-testing/test-components.sh server build --verbose

# Clean and rebuild
./local-testing/manage-local-env.sh clean
./local-testing/deploy-local-sigul-stack.sh --build-local --debug
```

### Service Startup Problems

**Symptoms**: Containers exit immediately, process not running
**Solution**:

```bash
# Test startup sequence
./local-testing/test-components.sh server startup --debug

# Check initialization logs
./local-testing/manage-local-env.sh logs server

# Validate configuration
./local-testing/test-components.sh server config
```

### Certificate Issues

**Symptoms**: SSL/TLS errors, missing certificates
**Solution**:

```bash
# Test certificate generation
./local-testing/test-components.sh certs detailed

# Check certificate directories
./local-testing/manage-local-env.sh shell server
ls -la /var/sigul/secrets/certificates/
```

### Network Connectivity Problems

**Symptoms**: Bridge unreachable, connection timeouts
**Solution**:

```bash
# Test network connectivity
./local-testing/test-components.sh network

# Debug with network tools
./local-testing/manage-local-env.sh shell network-tester
nc -z sigul-bridge 44334
```

## Integration with CI

### Development Workflow

1. **Local Development**

   ```bash
   # Test changes locally
   ./local-testing/deploy-local-sigul-stack.sh --build-local
   ```

2. **Validation**

   ```bash
   # Run comprehensive tests
   ./local-testing/test-components.sh all --save-logs
   ```

3. **CI Deployment**

   ```bash
   # Push to GitHub - CI will use similar deployment process
   git push origin feature-branch
   ```

### Differences from CI

| Aspect | Local Environment | GitHub CI |
|--------|------------------|-----------|
| Platform | ARM64 only | AMD64 + ARM64 |
| Artifacts | Local build | GitHub artifacts |
| Debugging | Full shell access | Log files only |
| Iteration | Immediate | Commit/push cycle |
| Resources | Local Docker | GitHub runners |

### Transferring Lessons to CI

The local environment helps you:

1. **Validate deployment scripts** before CI runs
2. **Debug certificate issues** with full access
3. **Test configuration changes** quickly
4. **Understand timing dependencies** between services
5. **Develop health check improvements**

## Advanced Usage

### Custom Configuration

Edit the generated environment file:

```bash
vim local-testing/.env
./local-testing/manage-local-env.sh restart
```

### Manual Container Operations

```bash
# Direct Docker Compose usage
docker compose -f docker-compose.sigul.yml ps
docker compose -f docker-compose.sigul.yml logs -f sigul-server
docker compose -f docker-compose.sigul.yml exec sigul-server bash
```

### Running Specific Test Suites

```bash
# Test only certificate generation
./local-testing/test-components.sh certs

# Test only network connectivity
./local-testing/test-components.sh network

# Test specific component in detail
./local-testing/test-components.sh bridge detailed --save-logs
```

### Performance Monitoring

```bash
# Monitor container resources
docker stats

# Check disk usage
docker system df

# Monitor in real-time
./local-testing/manage-local-env.sh monitor
```

## Directory Structure

```
local-testing/
├── deploy-local-sigul-stack.sh    # Main deployment automation
├── manage-local-env.sh            # Day-to-day environment management
├── test-components.sh             # Component testing and validation
├── getting-started.sh             # Interactive setup guide
├── validate-setup.sh              # Prerequisites validation
├── .env                          # Environment configuration (generated)
├── .env.sample                   # Sample environment file
├── test-workspace/               # Test files for signing operations
├── diagnostics-*/                # Diagnostic output (timestamped)
└── test-results-*/               # Test results (timestamped)
```

## Benefits of This Approach

### 1. Faster Development Cycle

- **Immediate feedback** instead of waiting for CI
- **Full debugging access** to containers and logs
- **Quick iteration** on configuration changes

### 2. Better Problem Diagnosis

- **Complete log access** from all components
- **Shell access** for manual investigation
- **Network debugging tools** built-in

### 3. Reduced CI Waste

- **Pre-validate changes** before pushing to CI
- **Solve issues locally** instead of in expensive CI time
- **Test ARM64 compatibility** on actual hardware

### 4. Learning and Documentation

- **Understand the full stack** through hands-on experience
- **Document working configurations** for CI improvement
- **Develop operational knowledge** for troubleshooting

## Next Steps

### Immediate Actions

1. **Run the validation script** to check your environment
2. **Deploy the stack locally** using the getting-started guide
3. **Familiarize yourself** with the management commands
4. **Test a complete workflow** from build to health checks

### Integration Development

1. **Use local environment** to refine deployment scripts
2. **Test certificate generation** and validation thoroughly
3. **Develop health check improvements** based on local observations
4. **Document working configurations** for CI enhancement

### CI Enhancement

1. **Apply lessons learned** to GitHub workflow improvements
2. **Enhance error reporting** in CI based on local debugging
3. **Optimize timing and dependencies** discovered locally
4. **Implement better health checks** validated locally

## Support and Maintenance

### Getting Help

1. **Check the logs** using management scripts
2. **Run diagnostic tests** with component testing
3. **Review configuration** in the .env file
4. **Try a clean reset** if issues persist

### Keeping Updated

1. **Pull latest changes** from the repository
2. **Rebuild containers** after significant changes
3. **Update environment** configuration as needed
4. **Test new features** locally before CI deployment

## Conclusion

This local testing environment provides a comprehensive solution for developing, testing, and debugging the Sigul stack outside of the GitHub CI environment. By providing immediate feedback, full debugging access, and ARM64 compatibility testing, it significantly reduces the time and frustration of CI-based development while ensuring robust deployments.

The environment serves as both a development tool and a validation platform, helping ensure that changes work correctly before consuming expensive CI resources and enabling rapid iteration on improvements to the deployment process.
