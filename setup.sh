#!/bin/bash

# Help function
show_help() {
    echo "Usage: ./setup.sh [--clean]"
    echo "  --clean    Remove existing work directory before setup"
    exit 0
}

# Parse arguments
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    show_help
fi

if [ "$1" = "--clean" ]; then
    echo "Cleaning existing work directory..."
    rm -rf work
fi

if [ -d "work" ]; then
    echo "\"work\" directory is already set up."
    echo "Please use --clean option to remove and recreate the directory."
    exit 0
fi

# Create and track work directory
mkdir -p work || { echo "Error: Failed to create work directory" >&2; exit 1; }
cd work || { echo "Error: Failed to change to work directory" >&2; exit 1; }
WORK=$(pwd)

echo "[+] Setting up Fuzz Introspector..."
if ! git clone https://github.com/ossf/fuzz-introspector; then
    echo "Error: Failed to clone fuzz-introspector" >&2
    exit 1
fi

cd fuzz-introspector/tools/web-fuzzing-introspection || { echo "Error: Failed to change directory" >&2; exit 1; }
if ! python3 -m pip install -r ./requirements.txt; then
    echo "Error: Failed to install Python requirements" >&2
    exit 1
fi
cd "$WORK" || { echo "Error: Failed to return to work directory" >&2; exit 1; }

echo "[+] Making a local OSS-Fuzz folder..."
if ! git clone https://github.com/google/oss-fuzz; then
    echo "Error: Failed to clone oss-fuzz" >&2
    exit 1
fi

echo "[+] Setup completed successfully"