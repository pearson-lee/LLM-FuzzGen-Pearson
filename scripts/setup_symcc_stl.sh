#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/kyliechien/LLM-FuzzGen}"
LLVM_DIR="${LLVM_DIR:-$ROOT_DIR/llvm-project-14}"
SYMCC_DIR="${SYMCC_DIR:-$ROOT_DIR/symcc}"
SYMCC_SIMPLE_BUILD_DIR="${SYMCC_SIMPLE_BUILD_DIR:-$SYMCC_DIR/build_simple}"
LIBCXX_BUILD_DIR="${LIBCXX_BUILD_DIR:-$ROOT_DIR/libcxx_symcc_build}"
LIBCXX_INSTALL_DIR="${LIBCXX_INSTALL_DIR:-$ROOT_DIR/libcxx_symcc_install}"
LLVM_GIT_REF="${LLVM_GIT_REF:-llvmorg-14.0.6}"

echo "[1/4] Checking required commands"
for cmd in git cmake ninja; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

echo "[2/4] Preparing llvm-project source"
if [ ! -d "$LLVM_DIR/.git" ]; then
  git clone -b "$LLVM_GIT_REF" --depth 1 \
    https://github.com/llvm/llvm-project.git "$LLVM_DIR"
else
  echo "Using existing LLVM source at $LLVM_DIR"
fi

echo "[3/4] Building SymCC simple backend"
mkdir -p "$SYMCC_SIMPLE_BUILD_DIR"
cmake -S "$SYMCC_DIR" -B "$SYMCC_SIMPLE_BUILD_DIR" -G Ninja \
  -DSYMCC_RT_BACKEND=simple \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DZ3_TRUST_SYSTEM_VERSION=on
ninja -C "$SYMCC_SIMPLE_BUILD_DIR"

echo "[4/4] Building instrumented libc++"
rm -rf "$LIBCXX_BUILD_DIR" "$LIBCXX_INSTALL_DIR"
mkdir -p "$LIBCXX_BUILD_DIR"

export SYMCC_REGULAR_LIBCXX=yes
export SYMCC_NO_SYMBOLIC_INPUT=yes

cmake -S "$LLVM_DIR/llvm" -B "$LIBCXX_BUILD_DIR" -G Ninja \
  -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;cxx-headers" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$LIBCXX_INSTALL_DIR" \
  -DCMAKE_C_COMPILER="$SYMCC_SIMPLE_BUILD_DIR/symcc" \
  -DCMAKE_CXX_COMPILER="$SYMCC_SIMPLE_BUILD_DIR/sym++"

ninja -C "$LIBCXX_BUILD_DIR" distribution
ninja -C "$LIBCXX_BUILD_DIR" install-distribution

unset SYMCC_REGULAR_LIBCXX
unset SYMCC_NO_SYMBOLIC_INPUT

cat <<EOF

SymCC STL setup completed.

Use it like this:

SYMCC_LIBCXX_PATH=$LIBCXX_INSTALL_DIR \\
$SYMCC_SIMPLE_BUILD_DIR/sym++ -O0 -g -o testSymccSTL_sym $ROOT_DIR/testSymccSTL.cpp

Quick test:
printf 'hello' | $ROOT_DIR/testSymccSTL_sym

EOF
