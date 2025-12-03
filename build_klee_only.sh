#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <project-name> <harness-path>"
  exit 1
fi

PROJECT="$1"
HARNESS="$2"
KLEE_IMAGE="${KLEE_IMAGE:-klee/klee:latest}"

WORKDIR="$(pwd)"

HOST_SOURCE_DIR="$WORKDIR/external/oss-fuzz/build/out/$PROJECT/$PROJECT/source_code"

docker run --rm \
  --user root \
  -e PROJECT="$PROJECT" \
  -e HARNESS="$HARNESS" \
  -v "$HOST_SOURCE_DIR:/src/source_code" \
  -v "$WORKDIR/external/oss-fuzz/projects/$PROJECT:/src/project" \
  -v "$WORKDIR/klee_build_output:/out" \
  "$KLEE_IMAGE" bash -c '
set -e

echo "=== Inside KLEE Container ==="

if ! command -v clang++ >/dev/null 2>&1 && ! command -v clang++-14 >/dev/null 2>&1; then
  echo "clang++ not found. Installing..."
  apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y clang llvm || {
    echo "Failed to install clang/llvm"; exit 1;
  }
fi

CXX="$(command -v clang++ || command -v clang++-14 || echo /usr/lib/llvm-14/bin/clang++)"
echo "Using compiler: $CXX"
$CXX --version || true

mkdir -p /out/klee
rm -f /out/klee/*.bc

echo "[1/3] Compiling project sources..."
# 遞迴尋找所有 .cpp (排除 main)
while IFS= read -r -d "" SRC; do
  if grep -qE "int[[:space:]]+main[[:space:]]*\\(" "$SRC"; then
    echo "  -> Skipping $(basename "$SRC") (contains main)"
    continue
  fi
  OBJ="/out/klee/$(basename "${SRC%.cpp}").bc"
  echo "  -> $(basename "$SRC")"
  $CXX -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone \
      -I/src/source_code -I/src/project -I/src/project/include \
      "$SRC" -o "$OBJ"
done < <(find /src/source_code -type f -name "*.cpp" -print0)

echo "[2/3] Compiling harness..."
HF="$HARNESS"
FOUND=""

# 1. 嘗試絕對路徑 (容器內)
if [ -f "$HF" ]; then
  FOUND="$HF"
# 2. 嘗試相對路徑：先找 /src/project，再找 /src/source_code (遞迴)
else
  if [ -f "/src/project/$HF" ]; then
    FOUND="/src/project/$HF"
  else
    # 在 source_code 下遞迴尋找該檔名
    FOUND="$(find /src/source_code -name "$(basename "$HF")" | head -n 1)"
  fi
fi

if [ -z "$FOUND" ] || [ ! -f "$FOUND" ]; then
  echo "Error: Harness not found!"
  echo "  Input was: $HARNESS"
  echo "  Searched in: /src/project and /src/source_code"
  echo "  Debug: Listing /src/source_code:"
  ls -R /src/source_code | head -n 20
  exit 1
fi

HF="$FOUND"
BASE_NAME="$(basename "${HF%.*}")"
OUT="/out/klee/${BASE_NAME}.bc"
echo "  -> $HF"

$CXX -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone \
    -I/src/source_code -I/src/project -I/src/project/include \
    "$HF" -o "$OUT"

echo "[3/3] Linking bitcode..."
LINKED_BC="/out/klee/${BASE_NAME}_linked.bc"
llvm-link /out/klee/*.bc -o "$LINKED_BC"
echo "Done. Output: $LINKED_BC"
'