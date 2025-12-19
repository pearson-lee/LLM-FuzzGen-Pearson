#!/bin/bash

set -e

PROJECT="tinyxml2"
KLEE_IMAGE="klee/klee:2.3"

echo "=========================================="
echo "Running KLEE on $PROJECT"
echo "=========================================="

# 檢查 bitcode 是否存在
if [ ! -f "./klee_build_output/klee_0921013457_20251210_linked.bc" ]; then
    echo "ERROR: Bitcode not found!"
    echo "Please run ./build_klee_harness.sh first"
    exit 1
fi

echo "✓ Bitcode found"
echo ""

# 創建輸出目錄
mkdir -p ./klee_output

# 執行 KLEE
echo "Running KLEE (max 60 seconds)..."
echo "Output will be saved to: ./klee_output/"
echo ""

docker run --rm \
    -v "$(pwd)/klee_build_output:/work" \
    -v "$(pwd)/klee_output:/output" \
    $KLEE_IMAGE \
    bash -c "
        set -e
        
        echo '=== Running KLEE ==='
        echo ''
        
        # 執行 KLEE
        klee \
            --output-dir=/output \
            --max-time=60 \
            --max-memory=2048 \
            --search=dfs \
            --optimize \
            --libc=uclibc \
            --posix-runtime \
            /work/klee/klee_harness_linked.bc
        
        echo ''
        echo '=== KLEE Completed ==='
        echo ''
        echo 'Output files:'
        ls -lh /output/ | head -n 20
        echo ''
        
        # 統計測試案例數量
        TEST_COUNT=\$(ls /output/*.ktest 2>/dev/null | wc -l)
        echo \"Generated test cases: \$TEST_COUNT\"
        
        # 顯示統計資訊
        if [ -f /output/run.stats ]; then
            echo ''
            echo 'Statistics (last 10 lines):'
            tail -n 10 /output/run.stats
        fi
        
        # 顯示第一個測試案例
        if [ \$TEST_COUNT -gt 0 ]; then
            FIRST_TEST=\$(ls /output/*.ktest 2>/dev/null | head -n 1)
            echo ''
            echo 'First test case:'
            ktest-tool \"\$FIRST_TEST\" 2>/dev/null || echo 'Could not read test case'
        fi
    "

echo ""
echo "=========================================="
echo "✓ KLEE execution completed!"
echo "=========================================="
echo ""

# 顯示本地結果
if [ -d "./klee_output" ]; then
    echo "Results saved to: $(pwd)/klee_output/"
    echo ""
    
    TEST_COUNT=$(ls ./klee_output/*.ktest 2>/dev/null | wc -l)
    echo "Test cases generated: $TEST_COUNT"
    echo ""
    
    if [ $TEST_COUNT -gt 0 ]; then
        echo "Test case files:"
        ls -lh ./klee_output/*.ktest | head -n 10
        echo ""
        echo "To extract inputs for fuzzing, use:"
        echo "  ./extract_klee_seeds.sh"
    fi
else
    echo "WARNING: No output directory found"
fi