#!/bin/bash

set -e

PROJECT="tinyxml2"
DOCKER_IMAGE="gcr.io/oss-fuzz/$PROJECT"

echo "================================================"
echo "Testing KLEE Integration for $PROJECT"
echo "================================================"

# 確認 KLEE harness 存在
KLEE_HARNESS="./external/oss-fuzz/projects/$PROJECT/klee_harness_test.cpp"
if [ ! -f "$KLEE_HARNESS" ]; then
    echo "[ERROR] klee_harness_test.cpp not found!"
    echo "Expected location: $KLEE_HARNESS"
    exit 1
fi

echo "[OK] KLEE harness found at: $KLEE_HARNESS"

# Step 1: Build with KLEE support
echo ""
echo "[Step 1] Building project with KLEE support..."
docker run --rm \
    -v "$(pwd)/external/oss-fuzz/projects/$PROJECT:/src" \
    -e BUILD_KLEE=1 \
    -e SANITIZER=address \
    "$DOCKER_IMAGE" \
    bash -c "
        echo 'Current directory:' \$(pwd)
        echo 'Contents of /src:'
        ls -la /src/
        
        # 確認 KLEE harness 存在於 Docker 內
        if [ ! -f /src/klee_harness_test.cpp ]; then
            echo '[ERROR] klee_harness_test.cpp not found in /src/'
            echo 'Available .cpp files:'
            ls -la /src/*.cpp
            exit 1
        fi
        
        echo '[OK] KLEE harness found in container'
        
        # 進入 tinyxml2 目錄並編譯
        cd /src/tinyxml2
        bash /src/build.sh
    "

echo ""
echo "[Step 1] ✓ Build completed"

# Step 2: Check if bitcode was generated
echo ""
echo "[Step 2] Checking generated bitcode files..."
docker run --rm \
    -v "$(pwd)/external/oss-fuzz/projects/$PROJECT:/src" \
    "$DOCKER_IMAGE" \
    bash -c "
        if [ -d /out/klee ]; then
            echo 'Contents of /out/klee/:'
            ls -lh /out/klee/
        else
            echo '[ERROR] /out/klee/ directory not found'
            echo 'Contents of /out/:'
            ls -la /out/
            exit 1
        fi
    "

echo ""
echo "[Step 2] ✓ Bitcode files verified"

# Step 3: Run KLEE
echo ""
echo "[Step 3] Running KLEE on the harness..."
mkdir -p ./klee_output

docker run --rm \
    -v "$(pwd)/external/oss-fuzz/projects/$PROJECT:/src" \
    -v "$(pwd)/klee_output:/tmp/klee_output" \
    "$DOCKER_IMAGE" \
    bash -c "
        # Install KLEE if needed
        echo 'Installing KLEE...'
        apt-get update -qq && apt-get install -y -qq klee klee-uclibc > /dev/null 2>&1 || true
        
        # Verify KLEE installation
        if ! command -v klee &> /dev/null; then
            echo '[ERROR] KLEE installation failed'
            exit 1
        fi
        
        echo '[OK] KLEE installed'
        klee --version
        
        # Check if bitcode exists
        BITCODE_FILE='/out/klee/klee_harness_linked.bc'
        if [ ! -f \"\$BITCODE_FILE\" ]; then
            echo '[ERROR] Bitcode file not found at' \$BITCODE_FILE
            echo 'Available files in /out/klee/:'
            ls -la /out/klee/
            exit 1
        fi
        
        echo '[OK] Bitcode file found'
        
        # Run KLEE
        echo ''
        echo 'Running KLEE with 60 second timeout...'
        klee \
            --output-dir=/tmp/klee_output \
            --max-time=60 \
            --search=dfs \
            --optimize \
            --libc=uclibc \
            --posix-runtime \
            \$BITCODE_FILE 2>&1 | head -n 50
        
        # Show results
        echo ''
        echo '================================================'
        echo 'KLEE Execution Results:'
        echo '================================================'
        
        if [ -d /tmp/klee_output ]; then
            echo 'Output directory contents:'
            ls -lh /tmp/klee_output/ | head -n 20
            
            echo ''
            KTEST_COUNT=\$(ls /tmp/klee_output/*.ktest 2>/dev/null | wc -l)
            echo \"Test cases generated: \$KTEST_COUNT\"
            
            # Show first test case details
            if [ \$KTEST_COUNT -gt 0 ]; then
                FIRST_KTEST=\$(ls /tmp/klee_output/*.ktest 2>/dev/null | head -n 1)
                echo ''
                echo 'First test case details:'
                ktest-tool \"\$FIRST_KTEST\" 2>/dev/null || echo 'ktest-tool not available'
            fi
        else
            echo '[ERROR] KLEE output directory not created'
        fi
    "

echo ""
echo "[Step 3] ✓ KLEE execution completed"

# Step 4: Show local results
echo ""
echo "[Step 4] Checking local output..."
if [ -d "./klee_output" ]; then
    echo "KLEE output saved to: $(pwd)/klee_output/"
    echo "Files:"
    ls -lh ./klee_output/ 2>/dev/null | head -n 20 || echo "No files found"
else
    echo "[WARNING] No output directory found locally"
fi

echo ""
echo "================================================"
echo "✓ All tests completed!"
echo "================================================"
echo ""
echo "Summary:"
echo "  - Bitcode location (in Docker): /out/klee/"
echo "  - KLEE output: $(pwd)/klee_output/"
echo ""
echo "Next steps:"
echo "  1. Check ./klee_output/ for generated test cases"
echo "  2. Extract seeds using ktest-tool"
echo "  3. Add seeds to libFuzzer corpus"