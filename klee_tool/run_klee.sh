#!/bin/bash
set -e

# Usage: ./run_klee.sh <project_name> <bitcode_file_in_klee_dir>
# Example: ./run_klee.sh tinyxml2 klee_0921013457_20251210_linked.bc

if [ $# -lt 2 ]; then
  echo "Usage: $0 <project_name> <bitcode_file>"
  echo "Example: $0 tinyxml2 klee_0921013457_20251210_linked.bc"
  echo "Available bitcode files under ./klee_build_output/klee/:"
  ls -1 "./klee_build_output/klee"/*.bc 2>/dev/null | sed 's|.*/||' || true
  exit 1
fi

PROJECT="$1"
BC_NAME="$2"

KLEE_IMAGE="${KLEE_IMAGE:-klee/klee:3.0}"
MAX_TESTS="${MAX_TESTS:-10}"

echo "=========================================="
echo "Running KLEE on $PROJECT"
echo "=========================================="

BC_DIR="./klee_build_output/klee"
BC_LOCAL="$BC_DIR/$BC_NAME"

if [ ! -f "$BC_LOCAL" ]; then
  echo "ERROR: 找不到檔案 '$BC_NAME' 於 $BC_DIR"
  echo "Available bitcode files:"
  ls -1 "$BC_DIR"/*.bc 2>/dev/null | sed 's|.*/||' || true
  exit 1
fi

echo "Bitcode found: $BC_LOCAL"

mkdir -p ./klee_output
RUN_ID="$(date +%Y%m%d_%H%M%S)"
echo "Run ID: $RUN_ID"

echo "Running KLEE (max 60 seconds, up to ${MAX_TESTS} tests)..."
echo "Output will be saved to: ./klee_output/$RUN_ID/"
echo ""

docker run --rm --ulimit=stack=-1:-1 \
  -v "$(pwd)/klee_build_output:/work" \
  -v "$(pwd)/klee_output:/output" \
  "$KLEE_IMAGE" \
  bash -c "
    set -e
    echo '=== Running KLEE ==='
    klee \
      --output-dir="/output/$RUN_ID" \
      --max-time=60 \
      --max-memory=2048 \
      --max-tests="$MAX_TESTS" \
      --search=dfs \
      --optimize \
      --libc=uclibc \
      --posix-runtime \
      "/work/klee/$(basename "$BC_LOCAL")"

    echo ''
    echo '=== KLEE Completed ==='
    echo ''
    echo 'Output files:'
    ls -lh \"/output/$RUN_ID\" | head -n 20
    echo ''

    TEST_COUNT=\$(ls \"/output/$RUN_ID\"/*.ktest 2>/dev/null | wc -l)
    echo \"Generated test cases: \$TEST_COUNT\"

    if [ -f \"/output/$RUN_ID/run.stats\" ]; then
      echo ''
      echo 'Statistics (last 10 lines):'
      tail -n 10 \"/output/$RUN_ID/run.stats\"
    fi

    if [ -f \"/output/$RUN_ID/messages.txt\" ]; then
      echo ''
      echo 'Messages (last 20 lines):'
      tail -n 20 \"/output/$RUN_ID/messages.txt\"
    fi

    if [ \$TEST_COUNT -gt 0 ]; then
      FIRST_TEST=\$(ls \"/output/$RUN_ID\"/*.ktest 2>/dev/null | head -n 1)
      echo ''
      echo 'First test case:'
      ktest-tool \"\$FIRST_TEST\" 2>/dev/null || echo 'Could not read test case'
    fi
  "

echo ""
echo "=========================================="
echo "KLEE execution completed!"
echo "=========================================="
echo ""

RESULT_DIR="./klee_output/$RUN_ID"
if [ -d "$RESULT_DIR" ]; then
  echo "Results saved to: $(pwd)/$RESULT_DIR"
  echo ""
  TEST_COUNT=$(ls "$RESULT_DIR"/*.ktest 2>/dev/null | wc -l)
  echo "Test cases generated: $TEST_COUNT"
  echo ""
  if [ "$TEST_COUNT" -gt 0 ]; then
    echo "Test case files:"
    ls -lh "$RESULT_DIR"/*.ktest | head -n 10
  fi
  if [ -f "$RESULT_DIR/messages.txt" ]; then
    echo ""
    echo "Messages (last 20 lines):"
    tail -n 20 "$RESULT_DIR/messages.txt"
  fi
  echo ""
  echo "To extract inputs for fuzzing, use:"
  echo "  ./extract_klee_seeds.sh \"$RESULT_DIR\""
else
  echo "WARNING: No output directory found at $RESULT_DIR"
fi