#!/bin/bash

# Define common paths
OSS_FUZZ_PATH="./external/oss-fuzz"
INTROSPECTOR_DB_PATH="./external/fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db"

# Display help message if no arguments provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <project1> <project2> ..."
    echo "This script will clean up fuzzing artifacts for the specified projects."
    exit 1
fi

# Process each project name provided as an argument
for project in "$@"; do
    echo "Cleaning up artifacts for project: $project"
    
    # 1. Delete fuzz_*_fuzzer.* files in the oss-fuzz projects directory
    echo "  Removing fuzzer files from oss-fuzz projects..."
    find "${OSS_FUZZ_PATH}/projects/$project" -name "fuzz_*_fuzzer.*" -type f -exec rm -v {} \;
    
    # 2. Delete project-specific output directory
    echo "  Removing build output directory..."
    if [ -d "${OSS_FUZZ_PATH}/build/out/$project" ]; then
        rm -rf "${OSS_FUZZ_PATH}/build/out/$project"
        echo "  Deleted: ${OSS_FUZZ_PATH}/build/out/$project"
    else
        echo "  Directory not found: ${OSS_FUZZ_PATH}/build/out/$project"
    fi
done

# 3. Delete fuzz-introspector database files
echo "Cleaning up fuzz-introspector database files..."

# Delete db-projects directory
if [ -d "${INTROSPECTOR_DB_PATH}/db-projects" ]; then
    rm -rf "${INTROSPECTOR_DB_PATH}/db-projects"
    echo "Deleted: ${INTROSPECTOR_DB_PATH}/db-projects"
fi

# Delete JSON files in the db directory
find "${INTROSPECTOR_DB_PATH}" -name "*.json" -type f -exec rm -v {} \;

# Delete db-archive.zip
if [ -f "${INTROSPECTOR_DB_PATH}/db-archive.zip" ]; then
    rm "${INTROSPECTOR_DB_PATH}/db-archive.zip"
    echo "Deleted: ${INTROSPECTOR_DB_PATH}/db-archive.zip"
fi

echo "Clean up completed successfully."