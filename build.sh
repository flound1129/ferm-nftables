#!/bin/bash
set -e

CODENAME="${1:-bookworm}"
TIMESTAMP=$(date +%s)

echo "Building ferm for Debian ${CODENAME}..."

IMAGE="ferm-nftables-build:latest"

docker build --network=host -t "$IMAGE" .

docker run --rm --net=host \
    -v "$(pwd):/build" \
    -e "CODENAME=${CODENAME}" \
    -e "TIMESTAMP=${TIMESTAMP}" \
    "$IMAGE" \
    bash -c '
        export DEBIAN_FRONTEND=noninteractive
        
        # Update sources for the target codename
        sed -i "s/bookworm/${CODENAME}/g" /etc/apt/sources.list 2>/dev/null || true
        for f in /etc/apt/sources.list.d/*.list; do
            sed -i "s/bookworm/${CODENAME}/g" "$f" 2>/dev/null || true
        done
        
        cd /build
        
        # Reset and update changelog - use more specific patterns
        git checkout debian/changelog 2>/dev/null || true
        sed -i "s/bookworm/${CODENAME}/g" debian/changelog
        sed -i "s/~[0-9]*/~${TIMESTAMP}/g" debian/changelog
        
        # Reset and update pkg/DEBIAN/control
        rm -rf pkg
        mkdir -p pkg/DEBIAN pkg/usr/bin pkg/usr/share/man/man1 pkg/lib/systemd/system pkg/usr/lib/python3/dist-packages
        
        # Install Python package
        cp -r ferm pkg/usr/lib/python3/dist-packages/
        
        # Create wrapper script
        cat > pkg/usr/bin/ferm << EOF
#!/usr/bin/python3
import sys
import os
sys.path.insert(0, '/usr/lib/python3/dist-packages')
from ferm.apply import main
sys.exit(main())
EOF
        chmod +x pkg/usr/bin/ferm
        
        cp debian/ferm.1 pkg/usr/share/man/man1/
        gzip pkg/usr/share/man/man1/ferm.1
        
        cp debian/ferm-nftables.service pkg/lib/systemd/system/ferm.service
        
        cat > pkg/DEBIAN/control << EOF
Package: ferm
Version: 1.0.0~${TIMESTAMP}+${CODENAME}
Architecture: all
Depends: python3, iptables, nftables
Conflicts: ferm
Replaces: ferm
Maintainer: OpenCode <opencode@example.com>
Description: ferm syntax parser for iptables-nftables
 ferm is a Python implementation that parses firewall rules in ferm
 syntax and generates iptables-nftables commands. It provides the same
 configuration syntax as the original ferm tool but uses iptables-nftables
 (nftables backend) instead of iptables-legacy.
EOF
        
        # Build package
        dpkg-deb --build pkg ferm_1.0.0~${TIMESTAMP}+${CODENAME}_amd64.deb
        
        echo "Built: ferm_1.0.0~${TIMESTAMP}+${CODENAME}_amd64.deb"
    '
