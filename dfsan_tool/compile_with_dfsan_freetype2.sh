#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  compile_with_dfsan_freetype2.sh [--target <name>] [--sync-from <path>] [--work-tree <path>] [--output-dir <path>] [--no-sync]

Purpose:
  Build a DFSan-instrumented FreeType fuzz target with the original project
  build flow, while minimizing taint-baseline bias sources.

Default target:
  cff-render

Default source sync:
  Sync edited sources from:
    ./Judge/freetype/src/freetype2-testing
  into the buildable work tree:
    ./Judge/freetype/worktree/freetype2-testing
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_SYNC_FROM="${ROOT_DIR}/Judge/freetype/src/freetype2-testing"
DEFAULT_WORK_TREE="${ROOT_DIR}/Judge/freetype/worktree/freetype2-testing"
DEFAULT_OUTPUT_DIR="${ROOT_DIR}/dfsan_build"

TARGET_NAME="cff-render"
SYNC_FROM="${DEFAULT_SYNC_FROM}"
WORK_TREE="${DEFAULT_WORK_TREE}"
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
DO_SYNC=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET_NAME="${2:?missing value for --target}"
            shift 2
            ;;
        --sync-from)
            SYNC_FROM="${2:?missing value for --sync-from}"
            shift 2
            ;;
        --work-tree)
            WORK_TREE="${2:?missing value for --work-tree}"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="${2:?missing value for --output-dir}"
            shift 2
            ;;
        --no-sync)
            DO_SYNC=0
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

SCRIPTS_DIR="${WORK_TREE}/fuzzing/scripts"
BUILD_SCRIPTS_DIR="${SCRIPTS_DIR}/build"
FREETYPE_DIR="${WORK_TREE}/external/freetype2"
FUZZING_BUILD_DIR="${WORK_TREE}/fuzzing/build"
ABI_LIST="${OUTPUT_DIR}/dfsan_abi_list.txt"

ZLIB_LIB="${WORK_TREE}/external/zlib/usr/lib-asan/libz.a"
BZIP2_LIB="${WORK_TREE}/external/bzip2/libbz2.a"
BROTLI_LIB="${WORK_TREE}/external/brotli/build/libbrotlidec-static.a"
LIBPNG_LIB="${WORK_TREE}/external/libpng/usr/lib-asan/libpng.a"

require_dir() {
    local path="$1"
    local label="$2"
    if [[ ! -d "$path" ]]; then
        echo "[error] Missing ${label}: $path" >&2
        exit 1
    fi
}

require_file() {
    local path="$1"
    local label="$2"
    if [[ ! -f "$path" ]]; then
        echo "[error] Missing ${label}: $path" >&2
        exit 1
    fi
}

run_build_script() {
    local script_name="$1"
    shift || true
    local script_path="${BUILD_SCRIPTS_DIR}/${script_name}"
    require_file "$script_path" "build script"
    (
        cd "$SCRIPTS_DIR"
        bash "build/${script_name}" "$@"
    )
}

require_dir "$WORK_TREE" "work tree"
require_dir "${WORK_TREE}/fuzzing" "fuzzing directory"
require_dir "$SCRIPTS_DIR" "fuzzing scripts"
require_dir "$BUILD_SCRIPTS_DIR" "build scripts"
require_dir "${WORK_TREE}/external" "external dependency directory"
require_dir "$FREETYPE_DIR" "FreeType source directory"

mkdir -p "$OUTPUT_DIR"

cat > "$ABI_LIST" <<'EOF'
# Keep the ABI list intentionally minimal.
# Broad std::* ignore rules can erase real taint flow through the harness.

# Called by libFuzzer runtime with the original ABI.
fun:LLVMFuzzerTestOneInput=uninstrumented

# Logging / debug output only.
fun:printf=uninstrumented
fun:fprintf=uninstrumented
fun:puts=uninstrumented
fun:fwrite=uninstrumented

# C++ EH personalities may stay external to the instrumented slice.
fun:__gxx_personality_v0=uninstrumented
fun:__cxa_begin_catch=uninstrumented
fun:__cxa_end_catch=uninstrumented
fun:__clang_call_terminate=uninstrumented
EOF

DFSAN_FLAGS=(
    -fsanitize=dataflow
    -fsanitize-ignorelist="${ABI_LIST}"
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
    -g
    -O1
    -DDFSAN_ENABLED
)

export SANITIZER="dataflow"
export FUZZING_ENGINE="${FUZZING_ENGINE:-libfuzzer}"
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"
export CFLAGS="${CFLAGS:-} ${DFSAN_FLAGS[*]}"
export CXXFLAGS="${CXXFLAGS:-} ${DFSAN_FLAGS[*]}"
export LDFLAGS="${LDFLAGS:-} -fsanitize=dataflow"

# Keep both variables to match different build wrappers.
export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
export CMAKE_FUZZING_ENGINE="${CMAKE_FUZZING_ENGINE:-$LIB_FUZZING_ENGINE}"
export CMAKE_DRIVER_EXE_NAME="${CMAKE_DRIVER_EXE_NAME:-driver}"
export FUZZ_TARGET_TYPE="${FUZZ_TARGET_TYPE:-libfuzzer}"

sync_tree() {
    local src="$1"
    local dst="$2"

    require_dir "$src" "sync source tree"

    echo "[sync] external/freetype2"
    rsync -a \
        --delete \
        --exclude '.git' \
        --exclude 'objs' \
        --exclude 'builds' \
        --exclude 'docs' \
        --exclude 'devel' \
        "$src/external/freetype2/" \
        "$dst/external/freetype2/"

    echo "[sync] fuzzing/src"
    rsync -a \
        --delete \
        --exclude '.git' \
        "$src/fuzzing/src/" \
        "$dst/fuzzing/src/"
}

bootstrap_if_needed() {
    local need_bootstrap=0

    [[ -f "$ZLIB_LIB" ]] || need_bootstrap=1
    [[ -f "$BZIP2_LIB" ]] || need_bootstrap=1
    [[ -f "$BROTLI_LIB" ]] || need_bootstrap=1
    [[ -f "$LIBPNG_LIB" ]] || need_bootstrap=1
    [[ -f "${FREETYPE_DIR}/Makefile" ]] || need_bootstrap=1
    [[ -f "${FUZZING_BUILD_DIR}/build.ninja" ]] || need_bootstrap=1

    if [[ "$need_bootstrap" -eq 1 ]]; then
        echo "[bootstrap] initializing external deps + FreeType + targets"
        run_build_script "zlib.sh"
        run_build_script "bzip2.sh"
        run_build_script "brotli.sh"
        run_build_script "libpng.sh"
        run_build_script "freetype.sh"
        run_build_script "targets.sh"
    fi
}

rebuild_all_no_init() {
    echo "[build] rebuilding external deps (no-init)"
    run_build_script "zlib.sh" --no-init
    run_build_script "bzip2.sh" --no-init
    run_build_script "brotli.sh" --no-init
    run_build_script "libpng.sh" --no-init

    echo "[build] rebuilding instrumented FreeType (no-init)"
    run_build_script "freetype.sh" --no-init

    echo "[build] rebuilding fuzz targets (no-init)"
    run_build_script "targets.sh" --no-init
}

if [[ "$DO_SYNC" -eq 1 ]]; then
    require_dir "$SYNC_FROM" "sync source tree"
fi

echo "[info] target: ${TARGET_NAME}"
echo "[info] work tree: ${WORK_TREE}"
echo "[info] output dir: ${OUTPUT_DIR}"
echo "[info] DFSan ABI list: ${ABI_LIST}"
echo "[info] compiler: CC=${CC}, CXX=${CXX}"

bootstrap_if_needed

if [[ "$DO_SYNC" -eq 1 ]]; then
    sync_tree "$SYNC_FROM" "$WORK_TREE"
fi

rebuild_all_no_init

BUILT_BIN="${FUZZING_BUILD_DIR}/bin/${TARGET_NAME}"
require_file "$BUILT_BIN" "built target binary"

cp "$BUILT_BIN" "${OUTPUT_DIR}/${TARGET_NAME}_dfsan"

cat <<EOF
[done] DFSan build finished
  Binary: ${OUTPUT_DIR}/${TARGET_NAME}_dfsan
  ABI list: ${ABI_LIST}

Important:
  - This build uses the real project build chain (deps + FreeType + target).
  - It avoids the common baseline bias from "compile only selected files".
  - DFSan remains best-effort taint analysis; validate key blockers with manual root-cause checks.
EOF