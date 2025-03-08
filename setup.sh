#!/bin/bash

BASE_DIR="$(pwd)"
EXTERNAL_DIR="$BASE_DIR/external"

fail() {
    echo "Error: $1" >&2
    exit 1
}

# Install main project requirements
echo "[+] Installing main project requirements..."
python -m pip install -r requirements.txt || fail "Failed to install main project requirements"

prompt_delete_dir() {
    local folder="$1"
    read -p "The folder '$folder' already exists. Do you want to delete it and continue? (y/n): " choice
    case "$choice" in 
        y|Y ) rm -rf "$folder" || fail "Failed to delete $folder";;
        n|N ) echo "Exiting..."; exit 0;;
        * ) echo "Invalid choice"; prompt_delete_dir "$folder";;
    esac
}

# Check if fuzz-introspector or oss-fuzz folders exist
if [ -d "$EXTERNAL_DIR/fuzz-introspector" ] || [ -d "$EXTERNAL_DIR/oss-fuzz" ]; then
    if [ -d "$EXTERNAL_DIR/fuzz-introspector" ]; then
        prompt_delete_dir "$EXTERNAL_DIR/fuzz-introspector"
    fi
    if [ -d "$EXTERNAL_DIR/oss-fuzz" ]; then
        prompt_delete_dir "$EXTERNAL_DIR/oss-fuzz"
    fi
fi

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

cd "$EXTERNAL_DIR" || fail "Failed to change directory to external"

echo "[+] Setting up Fuzz Introspector..."
setup_repo "https://github.com/ossf/fuzz-introspector" "fuzz-introspector" "f16dbf645a593a2a830cbb131d21669d10c07f6f"

# Install Python requirements for Fuzz Introspector
pushd tools/web-fuzzing-introspection > /dev/null || fail "Failed to change directory to tools/web-fuzzing-introspection"
python -m pip install -r requirements.txt || fail "Failed to install Python requirements"
popd > /dev/null

cd "$EXTERNAL_DIR" || fail "Failed to change directory to external"

echo "[+] Setting up OSS-Fuzz..."
setup_repo "https://github.com/google/oss-fuzz" "oss-fuzz" "26f36ff7ce9cd61856621ba197f8e8db24b15ad9"

echo "[+] Setup completed successfully"