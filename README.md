# Docker Pilot

Docker installation and TUI management tool, designed specifically for SLES 15+. Zero external dependencies, single binary.

## Features

- ✅ **Truly zero dependencies** - Statically compiled Go binary, no Python or runtime required
- ✅ **Interactive configuration** - Friendly menu guide with Quick/Advanced modes
- ✅ **Enterprise best practices** - Built-in Registry, HTTP Proxy, and container network CIDR configuration
- ✅ **Network conflict detection** - Automatically detects if CIDR conflicts with internal network
- ✅ **Idempotent** - Safe to run multiple times, automatic config backup
- ✅ **Built-in lazydocker TUI** - Powerful Docker management interface (no separate installation required)
- ✅ **Container-aware** - Gracefully handles running inside containers
- ✅ **Security scanning** - Scan containers and images for CVE vulnerabilities
- ✅ **AI health inspection** - AI-powered container health analysis

## Usage

### Configuration (Default Command)

```bash
# Run installation and configuration wizard (defaults to `config` command)
sudo ./docker-pilot

# Or explicitly
sudo ./docker-pilot config
```

`config` command has two modes:
- **Quick mode (default)**: Install Docker only, skip configuration
- **Advanced mode**: Full setup with registry, proxy, and network configuration

### TUI Management

```bash
# Launch built-in lazydocker TUI for container management
./docker-pilot tui
```

### Security Scanning

```bash
# Scan containers and images for CVE vulnerabilities
sudo ./docker-pilot scan
```

### AI Health Inspection

```bash
# AI-powered analysis of container health status
sudo ./docker-pilot ai-inspect
```

### Help

```bash
# Show available commands
./docker-pilot --help
```

## Configuration Options

| Configuration | Description | Default |
|---------------|-------------|---------|
| **Registry** | Enterprise internal registry mirror address | registry.example.com |
| **HTTP Proxy** | Enterprise HTTP/HTTPS proxy | http://proxy.example.com:8080 |
| **Container CIDR** | Container bridge network, avoid internal conflicts | 172.31.0.0/16 |

## Configuration File Locations

- Docker daemon config: `/etc/docker/daemon.json`
- Systemd proxy config: `/etc/systemd/system/docker.service.d/http-proxy.conf`

## Development

### Requirements

- Go 1.26+

### Build

```bash
# Build (automatically downloads embedded lazydocker if missing)
make build

# Build and compress
make compress

# Run tests
make test

# Refresh embedded lazydocker manually (if needed)
make ref-embed

# Tab completion should work automatically in most shells (zsh/bash)
make <tab>
```

### Test in Container

```bash
# Build and run in SUSE container
make test-container
```

### Enterprise Customization

Modify default values in `internal/config/config.go` to adapt to your enterprise environment:

```go
const (
    DefaultRegistry   = "your-registry.com"
    DefaultHTTPProxy  = "http://your-proxy:8080"
    DefaultHTTPSProxy = "http://your-proxy:8080"
    DefaultNoProxy    = "localhost,127.0.0.1,.your-company.com"
    DefaultBIP        = "172.31.0.1/16"
)
```

## Project Structure

```
docker-pilot/
├── cmd/
│   ├── main.go          # Program entry, commands: config/scan/ai-inspect
│   ├── tui.go           # LazyDocker TUI command
│   └── embed/           # Embedded lazydocker binary
├── internal/
│   ├── install/         # Docker installation logic
│   ├── config/          # Configuration handling (Registry/Proxy/CIDR)
│   ├── system/          # System checks, service management, utilities
│   └── ui/              # Interactive UI, color output, forms
├── scripts/
│   └── ref-embed.sh     # Script to refresh embedded binaries
├── Dockerfile           # Container test environment
├── Makefile
├── go.mod
└── README.md
```

## Important Notes

- Must run with sudo for system modifications
- SLES 15+ only
- Docker service restarts automatically after configuration changes
- Current user is automatically added to `docker` group
- When running inside a container, installation steps are skipped
