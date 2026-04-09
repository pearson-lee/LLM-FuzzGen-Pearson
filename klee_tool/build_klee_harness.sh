#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <project-name> <harness-path>"
  exit 1
fi

PROJECT="$1"
HARNESS="$2"
KLEE_IMAGE="${KLEE_IMAGE:-klee/klee:3.0}"

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

# Detect LLVM major and pick matching toolchain
LLVM_MAJOR="$(llvm-config --version 2>/dev/null | cut -d. -f1 || true)"
CXX=""
for c in "clang++-$LLVM_MAJOR" "clang-$LLVM_MAJOR" "clang++"; do
  if command -v "$c" >/dev/null 2>&1; then CXX="$c"; break; fi
done
if [ -z "$CXX" ]; then
  echo "clang++ not found; installing matching version (best effort)..."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "clang-$LLVM_MAJOR" "llvm-$LLVM_MAJOR" || DEBIAN_FRONTEND=noninteractive apt-get install -y clang llvm
  CXX="$(command -v "clang++-$LLVM_MAJOR" || command -v clang++)"
fi

echo "Using compiler: $CXX"
$CXX --version || true
mkdir -p /out/klee
rm -f /out/klee/*.bc || true

LLVMLINK=""
for l in "llvm-link-$LLVM_MAJOR" "llvm-link"; do
  if command -v "$l" >/dev/null 2>&1; then LLVMLINK="$l"; break; fi
done
if [ -z "$LLVMLINK" ]; then
  echo "llvm-link not found"; exit 1
fi

echo "[1/3] Compiling project sources..."
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

if [ -f "$HF" ]; then
  FOUND="$HF"
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
"$LLVMLINK" /out/klee/*.bc -o "$LINKED_BC"
echo "Done. Output: $LINKED_BC"
'