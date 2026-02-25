#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <deb-file>"
    exit 1
fi

DEB_FILE="$1"

if [ ! -f "$DEB_FILE" ]; then
    echo "Error: File not found: $DEB_FILE"
    exit 1
fi

DEB_NAME=$(basename "$DEB_FILE")

echo "Deploying $DEB_NAME to testbox..."

scp "$DEB_FILE" root@testbox:/tmp/

ssh root@testbox << EOF
    set -e
    
    echo "Installing ferm-nftables..."
    dpkg -i /tmp/${DEB_NAME} || apt-get install -f -y
    
    echo "Verifying installation..."
    ferm -V
    
    echo "Testing ferm-nft..."
    cat > /tmp/test.ferm << 'TESTEOF'
table filter {
    chain INPUT {
        policy ACCEPT;
    }
}
TESTEOF
    ferm --noexec --lines /tmp/test.ferm
    
    echo "Deployment successful!"
EOF
