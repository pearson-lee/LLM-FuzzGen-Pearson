#!/bin/bash

BASE_DIR="$(pwd)"
EXTERNAL_DIR="$BASE_DIR/external"

fail() {
    echo "Error: $1" >&2
    exit 1
}

[ -d "$EXTERNAL_DIR" ] || fail "external folder not found. Please create it."
cd "$EXTERNAL_DIR" || fail "Failed to enter external directory"

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

echo "[+] Setting up Fuzz Introspector..."
setup_repo "https://github.com/ossf/fuzz-introspector" "fuzz-introspector" "3b3e201783d9854b5b6dd4c3199c0189413b7223"

# Install Python requirements for Fuzz Introspector
pushd tools/web-fuzzing-introspection > /dev/null || fail "Failed to change directory to tools/web-fuzzing-introspection"
python3 -m pip install -r requirements.txt || fail "Failed to install Python requirements"
popd > /dev/null

cd "$EXTERNAL_DIR" || fail "Failed to change directory to external"

echo "[+] Setting up OSS-Fuzz..."
setup_repo "https://github.com/google/oss-fuzz" "oss-fuzz" "d5c068896b9f28483dbd7d2f15920b8c5e1b202d"

echo "[+] Setup completed successfully"