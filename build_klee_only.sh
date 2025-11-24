#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <project-name>"
  exit 1
fi

PROJECT="$1"
KLEE_IMAGE="${KLEE_IMAGE:-klee/klee:latest}"

WORKDIR="$(pwd)"

docker run --rm \
  --user root \
  -e PROJECT="$PROJECT" \
  -v "$WORKDIR/external/oss-fuzz/build/out/$PROJECT/project_source:/src/project_source" \
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

echo "[1/3] Compiling project sources (excluding any with main) into LLVM bitcode objects..."
rm -f /out/klee/*.bc
for SRC in /src/project_source/tinyxml2/*.cpp; do
  if grep -qE "int[[:space:]]+main[[:space:]]*\\(" "$SRC"; then
    echo "  -> Skipping $(basename "$SRC") (contains main)"
    continue
  fi
  OBJ="/out/klee/$(basename "${SRC%.cpp}").bc"
  echo "  -> $(basename "$SRC")"
  $CXX -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone \
      -I/src/project_source/tinyxml2 \
      "$SRC" -o "$OBJ"
done

echo "[2/3] Compiling harness..."
$CXX -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone \
    -I/src/project_source/tinyxml2 \
    /src/project/klee_harness_test.cpp \
    -o /out/klee/harness.bc

echo "[3/3] Linking bitcode..."
llvm-link /out/klee/*.bc -o /out/klee/klee_linked.bc
llvm-dis /out/klee/klee_linked.bc -o /out/klee/klee_linked.ll

echo "Done."
'