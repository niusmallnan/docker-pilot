#!/bin/bash
set -e

# Download and embed lazydocker (Linux amd64)
# With caching: if file exists, skip download unless forced

EMBED_DIR="cmd/embed"
mkdir -p "$EMBED_DIR"

FORCE_REDOWNLOAD=${FORCE_REDOWNLOAD:-false}

# ===== lazydocker =====
LAZYDOCKER_PATH="$EMBED_DIR/lazydocker"
if [ -f "$LAZYDOCKER_PATH" ] && [ "$FORCE_REDOWNLOAD" != "true" ]; then
    echo "lazydocker already exists, skipping download (use FORCE_REDOWNLOAD=true to override)"
else
    echo "Fetching latest lazydocker version..."
    GITHUB_LATEST_VERSION=$(curl -L -s -H 'Accept: application/json' https://github.com/jesseduffield/lazydocker/releases/latest | sed -e 's/.*"tag_name":"\([^"]*\)".*/\1/')
    GITHUB_FILE="lazydocker_${GITHUB_LATEST_VERSION//v/}_Linux_x86_64.tar.gz"
    GITHUB_URL="https://github.com/jesseduffield/lazydocker/releases/download/${GITHUB_LATEST_VERSION}/${GITHUB_FILE}"

    echo "Downloading $GITHUB_URL..."
    curl -L -o /tmp/lazydocker.tar.gz "$GITHUB_URL"

    echo "Extracting..."
    tar -xzf /tmp/lazydocker.tar.gz -C /tmp lazydocker

    echo "Compressing with upx..."
    upx --best --lzma /tmp/lazydocker

    echo "Moving to $EMBED_DIR/..."
    mv /tmp/lazydocker "$LAZYDOCKER_PATH"

    rm -f /tmp/lazydocker.tar.gz
fi
echo "lazydocker ready! File size: $(du -h "$LAZYDOCKER_PATH" | cut -f1)"

echo ""
echo "All binaries embedded successfully!"
