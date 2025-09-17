# Local Sigul Testing Environment

This directory contains scripts and tools for setting up and testing a complete Sigul infrastructure locally on macOS ARM64 systems. This approach allows you to test certificate setup, deployment scripts, health checks, and integration workflows before deploying to GitHub CI.

## Overview

The local testing environment provides:

- **Complete Sigul Stack**: Server, Bridge, and Client components
- **ARM64 Support**: Optimized for macOS Apple Silicon
- **Certificate Management**: Automated PKI setup and validation
- **Health Monitoring**: Real-time service health checks
- **Debug Tools**: Comprehensive logging and diagnostics
- **Integration Tests**: End-to-end workflow validation

## Quick Start

### Prerequisites

1. **Docker Desktop** for macOS with ARM64 support
2. **Docker Compose** (included with Docker Desktop)
3. **macOS ARM64** (Apple Silicon)

### Initial Setup

1. Clone the repository and navigate to the project root:

```bash
cd sigul-sign-docker
```

2. Deploy the complete Sigul stack:

```bash
./local-testing/deploy-local-sigul-stack.sh --build-local --verbose
```

3. Check the stack status:

```bash
./local-testing/manage-local-env.sh status
```

## Scripts Overview

### Main Scripts

| Script | Purpose | Usage |
|--------|---------|--------|
| `deploy-local-sigul-stack.sh` | Complete deployment automation | Initial setup and full deployments |
| `manage-local-env.sh` | Day-to-day environment management | Start, stop, logs, debugging |
| `test-components.sh` | Individual component testing | Isolated testing and debugging |

### Deployment Script

**`deploy-local-sigul-stack.sh`** - Complete Sigul stack deployment

```bash
# Build and deploy locally
./local-testing/deploy-local-sigul-stack.sh --build-local --verbose

# Clean deployment with debug output
./local-testing/deploy-local-sigul-stack.sh --clean --debug --build-local

# Quick deployment without tests
./local-testing/deploy-local-sigul-stack.sh --build-local --skip-tests
```

**Key Features:**

- Builds ARM64 containers locally
- Generates certificates and configuration
- Sets up Docker Compose environment
- Runs health checks and integration tests
- Collects comprehensive diagnostics

### Environment Management Script

**`manage-local-env.sh`** - Easy environment management

```bash
# Start the stack
./local-testing/manage-local-env.sh start

# Check status
./local-testing/manage-local-env.sh status

# View logs
./local-testing/manage-local-env.sh logs server
./local-testing/manage-local-env.sh logs -f  # Follow all logs

# Open shell in container
./local-testing/manage-local-env.sh shell server
./local-testing/manage-local-env.sh shell bridge

# Run health tests
./local-testing/manage-local-env.sh test

# Stop the stack
./local-testing/manage-local-env.sh stop

# Complete reset
./local-testing/manage-local-env.sh reset
```

### Component Testing Script

**`test-components.sh`** - Detailed component testing

```bash
# Test specific component
./local-testing/test-components.sh server build
./local-testing/test-components.sh bridge startup --verbose
./local-testing/test-components.sh client health

# Test certificates
./local-testing/test-components.sh certs detailed

# Test network connectivity
./local-testing/test-components.sh network

# Test all components
./local-testing/test-components.sh all --save-logs
```

## Common Workflows

### Initial Development Setup

```bash
# 1. Deploy the complete stack
./local-testing/deploy-local-sigul-stack.sh --build-local --verbose

# 2. Check everything is running
./local-testing/manage-local-env.sh status

# 3. Run comprehensive tests
./local-testing/test-components.sh all
```

### Daily Development

```bash
# Start your work session
./local-testing/manage-local-env.sh start

# Make changes to code/configs...

# Test specific component
./local-testing/test-components.sh server startup --verbose

# Check logs for issues
./local-testing/manage-local-env.sh logs server

# Debug in container
./local-testing/manage-local-env.sh shell server

# Stop when done
./local-testing/manage-local-env.sh stop
```

### Debugging Issues

```bash
# Start debug session
./local-testing/manage-local-env.sh debug

# Check container status
./local-testing/manage-local-env.sh status

# Analyze logs
./local-testing/test-components.sh server logs

# Test network connectivity
./local-testing/test-components.sh network

# Open debug shell
./local-testing/manage-local-env.sh shell debug-helper
```

### Clean Restart

```bash
# Complete environment reset
./local-testing/manage-local-env.sh reset

# Or manual clean and rebuild
./local-testing/manage-local-env.sh clean
./local-testing/deploy-local-sigul-stack.sh --build-local
```

## Architecture

### Container Components

- **sigul-server**: Core signing service with SQLite database
- **sigul-bridge**: Communication bridge between client and server
- **sigul-client-test**: Client environment for testing
- **network-tester**: Network connectivity testing
- **health-monitor**: Real-time service monitoring
- **debug-helper**: Debug tools and utilities

### Directory Structure

```
local-testing/
├── deploy-local-sigul-stack.sh    # Main deployment script
├── manage-local-env.sh            # Environment management
├── test-components.sh             # Component testing
├── .env                          # Environment configuration (generated)
├── test-workspace/               # Test files for signing
├── diagnostics-*/                # Diagnostic output (timestamped)
└── test-results-*/               # Test results (timestamped)
```

### Network Configuration

- **Bridge Port**: 44334 (client connections)
- **Internal Network**: 172.20.0.0/16
- **DNS**: Automatic service discovery
- **Volumes**: Persistent data for each component

## Troubleshooting

### Common Issues

#### Container Build Failures

```bash
# Check build logs
./local-testing/test-components.sh server build --verbose

# Clean Docker cache
docker builder prune -f

# Rebuild from scratch
./local-testing/manage-local-env.sh clean
./local-testing/deploy-local-sigul-stack.sh --build-local
```

#### Service Startup Issues

```bash
# Check specific service
./local-testing/test-components.sh server startup --debug

# View detailed logs
./local-testing/manage-local-env.sh logs server

# Check health status
./local-testing/test-components.sh server health
```

#### Certificate Problems

```bash
# Test certificate generation
./local-testing/test-components.sh certs detailed

# Check certificate directories
./local-testing/manage-local-env.sh shell server
ls -la /var/sigul/secrets/certificates/
```

#### Network Connectivity

```bash
# Test network connectivity
./local-testing/test-components.sh network

# Debug with network tester
./local-testing/manage-local-env.sh shell network-tester
nc -z sigul-bridge 44334
```

### Debug Mode

Enable debug mode for detailed output:

```bash
# Environment variable
export DEBUG=true

# Or use debug flag
./local-testing/deploy-local-sigul-stack.sh --debug --build-local
./local-testing/manage-local-env.sh debug
```

### Log Locations

- **Container Logs**: `docker compose logs <service>`
- **Build Logs**: `local-testing/test-results-*/`
- **Diagnostics**: `local-testing/diagnostics-*/`
- **Environment**: `local-testing/.env`

## Integration with CI

This local environment mimics the GitHub CI workflow, making it easy to:

1. **Test Changes Locally**: Validate before pushing to CI
2. **Debug CI Issues**: Reproduce problems locally
3. **Develop Improvements**: Iterate on deployment scripts
4. **Validate Fixes**: Ensure solutions work end-to-end

### Differences from CI

- **Platform**: ARM64 locally vs AMD64/ARM64 in CI
- **Artifacts**: Local build vs GitHub artifact download
- **Timing**: Faster feedback loop locally
- **Debugging**: Full shell access and persistent containers

## Advanced Usage

### Custom Configuration

Edit the generated `.env` file to customize:

```bash
# Edit environment
vim local-testing/.env

# Restart with new config
./local-testing/manage-local-env.sh restart
```

### Running Specific Profiles

```bash
# Start with monitoring
docker compose -f docker-compose.sigul.yml --profile monitoring up -d

# Start with debug tools
docker compose -f docker-compose.sigul.yml --profile debug up -d
```

### Manual Container Management

```bash
# Direct Docker Compose usage
cd sigul-sign-docker
docker compose -f docker-compose.sigul.yml ps
docker compose -f docker-compose.sigul.yml logs -f sigul-server
docker compose -f docker-compose.sigul.yml exec sigul-server bash
```

## Performance Optimization

### Docker Build Cache

The scripts use BuildKit for optimized builds:

```bash
# Clear build cache if needed
docker builder prune -f

# View cache usage
docker system df
```

### Resource Usage

Monitor resource usage:

```bash
# Container resources
docker stats

# System resources
docker system df
docker system events
```

## Contributing

When working on the local testing environment:

1. **Test Your Changes**: Use the component testing script
2. **Update Documentation**: Keep this README current
3. **Validate Integration**: Ensure CI compatibility
4. **Add Tests**: Extend test coverage as needed

## Support

For issues with the local testing environment:

1. **Check Logs**: Use the management script to view logs
2. **Run Diagnostics**: Use the component testing script
3. **Review Configuration**: Check the generated `.env` file
4. **Clean Reset**: Try a complete environment reset

The local testing environment is designed to provide quick feedback and comprehensive debugging capabilities for the Sigul stack development and deployment process.
