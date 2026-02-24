# ferm-nftables Build System

Docker-based build system for creating Debian packages targeting any Debian release.

## Quick Start

```bash
# Build for bookworm (default)
./build.sh

# Build for trixie
./build.sh trixie

# Build for sid
./build.sh sid

# Or use make
make build
make build-trixie
make build-sid
```

## Requirements

- Docker

## Output

Packages are created in the project root:
- `ferm-nftables_1.0.0~{timestamp}+{codename}_amd64.deb`

## Docker Build System

The `Dockerfile` contains the build environment with:
- build-essential
- devscripts
- dh-python
- python3-all

## Supported Debian Versions

- bookworm (Debian 12) - stable
- trixie (Debian 13) - testing
- sid - unstable

## Notes

- Version includes Unix timestamp for uniqueness
- Package codename matches target Debian release
- Systemd service file included in package
