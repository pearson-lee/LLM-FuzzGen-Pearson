#!/bin/bash

# ==============================================================================
# Script Setup and Helper Functions
# ==============================================================================

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTERNAL_DIR="$BASE_DIR/external"

cd "$BASE_DIR" || exit 1

# Function to handle errors and exit
fail() {
    echo "Error: $1" >&2
    exit 1
}



# ==============================================================================
# System Requirements Check
# ==============================================================================

echo "[+] Checking system requirements..."

# Check OS
if ! lsb_release -a 2>&1 | grep -q "Ubuntu 22.04"; then
    fail "System is not Ubuntu 22.04. Please use the recommended OS."
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1)
if [[ "$PYTHON_VERSION" != "Python 3.11"* ]]; then
    fail "Python version is not 3.11.x. Found: $PYTHON_VERSION. Please install the recommended Python version."
fi

# Check Docker installation
if ! command -v docker &> /dev/null; then
    fail "Docker is not installed. Please install Docker."
fi

echo "[+] System requirements met."


# ==============================================================================
# Main Project Requirements Installation
# ==============================================================================

echo "[+] Installing main project requirements..."
python -m pip install -r requirements.txt || fail "Failed to install main project requirements"


# ==============================================================================
# External Repositories Setup
# ==============================================================================

# Install the local Fuzz Introspector web API and package used by this snapshot.
echo "[+] Installing Fuzz Introspector Python requirements..."
python -m pip install -r "$EXTERNAL_DIR/fuzz-introspector/tools/web-fuzzing-introspection/requirements.txt" || fail "Failed to install Fuzz Introspector web requirements"
python -m pip install -e "$EXTERNAL_DIR/fuzz-introspector/src" || fail "Failed to install the local Fuzz Introspector package"
echo "[+] External repositories setup is complete."


# ==============================================================================
# Docker Images Build
# ==============================================================================

echo "[+] Building OSS-Fuzz base images..."
cd "$EXTERNAL_DIR/oss-fuzz" || fail "Failed to change directory to oss-fuzz"

# Ask user if they want to use Taiwan's apt repo
read -p "Do you want to use Taiwan's apt repository? (y/n): " choice
case "$choice" in
    y|Y )
        echo "[+] Building with Taiwan's apt repository..."
        ./infra/base-images/all.sh || fail "Failed to build OSS-Fuzz base images with all.sh"
        ;;
    n|N )
        echo "[+] Building with default repository..."
        docker pull gcr.io/oss-fuzz-base/base-image@sha256:a1fd7287efaefa39df54216edaa7b732d33eb54c06155fa9ebc7dbdc2e1d9286 || fail "Failed to pull base-image"
        docker tag gcr.io/oss-fuzz-base/base-image@sha256:a1fd7287efaefa39df54216edaa7b732d33eb54c06155fa9ebc7dbdc2e1d9286 gcr.io/oss-fuzz-base/base-image:latest || fail "Failed to tag base-image with latest"
        docker pull gcr.io/oss-fuzz-base/base-clang@sha256:fd173151d9281639f85eff98e998a1601189bc93665b6d9a18a2ecbe24682d76 || fail "Failed to pull base-clang image"
        docker tag gcr.io/oss-fuzz-base/base-clang@sha256:fd173151d9281639f85eff98e998a1601189bc93665b6d9a18a2ecbe24682d76 gcr.io/oss-fuzz-base/base-clang:latest || fail "Failed to tag base-clang with latest"
        docker build -t gcr.io/oss-fuzz-base/base-builder infra/base-images/base-builder || fail "Failed to build base-builder image"
        docker build -t gcr.io/oss-fuzz-base/base-builder-ruby infra/base-images/base-builder-ruby || fail "Failed to build base-builder-ruby image"
        docker build -t gcr.io/oss-fuzz-base/base-runner infra/base-images/base-runner || fail "Failed to build base-runner image"
        ;;
    * )
        fail "Invalid choice. Please run the script again and enter 'y' or 'n'."
        ;;
esac


# ==============================================================================
# Completion
# ==============================================================================

echo "[+] Setup completed successfully"
