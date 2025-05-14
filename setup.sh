#!/bin/bash

# ==============================================================================
# Script Setup and Helper Functions
# ==============================================================================

BASE_DIR="$(pwd)"
EXTERNAL_DIR="$BASE_DIR/external"

# Function to handle errors and exit
fail() {
    echo "Error: $1" >&2
    exit 1
}

# Function to prompt user to delete a directory if it exists
prompt_delete_dir() {
    local folder="$1"
    read -p "The folder '$folder' already exists. Do you want to delete it and continue? (y/n): " choice
    case "$choice" in
        y|Y ) sudo rm -rf "$folder" || fail "Failed to delete $folder";;
        n|N ) echo "Exiting..."; exit 0;;
        * ) echo "Invalid choice"; prompt_delete_dir "$folder";;
    esac
}

# Function to set up a repository: clone, enter directory, and checkout a commit
setup_repo() {
    local repo_url="$1"
    local folder="$2"
    local commit="$3"

    echo "[+] Cloning $folder..."
    git clone --depth 1 "$repo_url" "$folder" || fail "Failed to clone $folder"

    cd "$folder" || fail "Failed to enter $folder"
    git fetch --depth 1 origin "$commit" || fail "Failed to fetch specified commit in $folder"
    git checkout "$commit" || fail "Failed to checkout specified commit in $folder"

    git apply "$EXTERNAL_DIR/patches/$folder.patch" || fail "Failed to apply patch for $folder"
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

# Check if fuzz-introspector or oss-fuzz folders exist and prompt to delete
for folder in fuzz-introspector oss-fuzz; do
    [ -d "$EXTERNAL_DIR/$folder" ] && prompt_delete_dir "$EXTERNAL_DIR/$folder"
done

echo "[+] Setting up Fuzz Introspector..."
cd "$EXTERNAL_DIR" || fail "Failed to change directory to external"
setup_repo "https://github.com/ossf/fuzz-introspector" "fuzz-introspector" "8944d0b001754f60a602c95a816880f885f1e38d"

# Install Python requirements for Fuzz Introspector
echo "[+] Installing Fuzz Introspector Python requirements..."
python -m pip install -r "$EXTERNAL_DIR/fuzz-introspector/tools/web-fuzzing-introspection/requirements.txt" || fail "Failed to install Fuzz Introspector Python requirements"

echo "[+] Setting up OSS-Fuzz..."
cd "$EXTERNAL_DIR" || fail "Failed to change directory to external"
setup_repo "https://github.com/google/oss-fuzz" "oss-fuzz" "9f58c388aa52b9641260211a546ceb42b23f9fcf"


# ==============================================================================
# Docker Images Build
# ==============================================================================

echo "[+] Building OSS-Fuzz base images..."
cd "$EXTERNAL_DIR/oss-fuzz" || fail "Failed to change directory to oss-fuzz"
docker pull gcr.io/oss-fuzz-base/base-image@sha256:a1fd7287efaefa39df54216edaa7b732d33eb54c06155fa9ebc7dbdc2e1d9286 || fail "Failed to pull base-image"
docker tag gcr.io/oss-fuzz-base/base-image@sha256:a1fd7287efaefa39df54216edaa7b732d33eb54c06155fa9ebc7dbdc2e1d9286 gcr.io/oss-fuzz-base/base-image:latest || fail "Failed to tag base-image with latest"
docker pull gcr.io/oss-fuzz-base/base-clang@sha256:fd173151d9281639f85eff98e998a1601189bc93665b6d9a18a2ecbe24682d76 || fail "Failed to pull base-clang image"
docker tag gcr.io/oss-fuzz-base/base-clang@sha256:fd173151d9281639f85eff98e998a1601189bc93665b6d9a18a2ecbe24682d76 gcr.io/oss-fuzz-base/base-clang:latest || fail "Failed to tag base-clang with latest"
docker build -t gcr.io/oss-fuzz-base/base-builder infra/base-images/base-builder || fail "Failed to build base-builder image"
docker build -t gcr.io/oss-fuzz-base/base-runner infra/base-images/base-runner || fail "Failed to build base-runner image"


# ==============================================================================
# Completion
# ==============================================================================

echo "[+] Setup completed successfully"