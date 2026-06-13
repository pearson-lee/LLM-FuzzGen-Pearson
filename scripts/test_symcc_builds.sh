#!/bin/bash
# Test SymCC build support for each project.
# Usage:
#   ./scripts/test_symcc_builds.sh [--flavor symcc_native|symcc_library|symcc_replay|all] [--projects "proj1 proj2 ..."]
#
# Defaults: all flavors, all projects.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HELPER="$REPO_ROOT/external/oss-fuzz/infra/helper.py"
BUILD_OUT="$REPO_ROOT/external/oss-fuzz/build/out"
SYMCC_BIN="${SYMCC_BIN:-$REPO_ROOT/symcc/build_llvm18}"
LOG_DIR="${LOG_DIR:-$REPO_ROOT/logs/symcc_test}"

mkdir -p "$LOG_DIR"

# -- argument parsing --
FLAVOR="all"
PROJECTS="libpcap libvpx cjson tomlplusplus zlib tinyxml2 lcms libtiff"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --flavor)    FLAVOR="$2";    shift 2 ;;
    --projects)  PROJECTS="$2";  shift 2 ;;
    *)           echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

# -- project metadata --
# format: "<symcc_native_artifact>|<symcc_library_artifact>"
# empty = N/A (skip)
declare -A NATIVE_ARTIFACT
NATIVE_ARTIFACT[libpcap]="symcc_native/libpcap.a"
NATIVE_ARTIFACT[libvpx]="symcc_native/libvpx.a"
NATIVE_ARTIFACT[cjson]="symcc_native/libcjson.a"
NATIVE_ARTIFACT[tomlplusplus]=""     # header-only
NATIVE_ARTIFACT[zlib]="symcc_native/libz.a"
NATIVE_ARTIFACT[tinyxml2]="symcc_native/libtinyxml2.a"
NATIVE_ARTIFACT[lcms]="symcc_native/liblcms2.a"
NATIVE_ARTIFACT[libtiff]="symcc_native/libtiff_combined.a"

declare -A LIBRARY_ARTIFACT
LIBRARY_ARTIFACT[libpcap]="symcc_library/libpcap.a"
LIBRARY_ARTIFACT[libvpx]="symcc_library/libvpx.a"
LIBRARY_ARTIFACT[cjson]="symcc_library/libcjson.a"
LIBRARY_ARTIFACT[tomlplusplus]=""   # header-only
LIBRARY_ARTIFACT[zlib]="symcc_library/libz.a"
LIBRARY_ARTIFACT[tinyxml2]="symcc_library/libtinyxml2.a"
LIBRARY_ARTIFACT[lcms]="symcc_library/liblcms2.a"
LIBRARY_ARTIFACT[libtiff]="symcc_library/libtiff_combined.a"

# -- helpers --
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'

PASS="${GREEN}PASS${RESET}"
FAIL="${RED}FAIL${RESET}"
SKIP="${YELLOW}SKIP${RESET}"

declare -A RESULTS
declare -A RESULT_DETAIL
any_fail=0

run_build() {
  local proj="$1" flavor="$2"
  local logfile="$LOG_DIR/${proj}_${flavor}.log"
  local rc=0

  case "$flavor" in
    symcc_native)
      python3 "$HELPER" build_fuzzers "$proj" --sanitizer=none --clean \
        -e LLM_FUZZGEN_BUILD_FLAVOR=symcc_native \
        -e LLM_FUZZGEN_EXPORT_NATIVE_ARTIFACTS=1 \
        >"$logfile" 2>&1 || rc=$?
      ;;
    symcc_library)
      if [ ! -x "$SYMCC_BIN/symcc" ]; then
        echo "[skip] SYMCC_BIN not found: $SYMCC_BIN" >>"$logfile"
        return 2   # special: skip due to missing symcc
      fi
      # libz3.so.4 is needed by libsymcc-rt.so at link time. Mount symcc/lib/
      # as /symcc-libs (separate from the read-only /symcc-bin mount) so the
      # container's LD_LIBRARY_PATH can find it.
      local libz3_dir="$REPO_ROOT/symcc/lib"
      local extra_vols="${SYMCC_BIN}:/symcc-bin:ro"
      if [ -d "$libz3_dir" ] && [ -f "$libz3_dir/libz3.so.4" ]; then
        extra_vols="${extra_vols}|${libz3_dir}:/symcc-libs:ro"
      fi
      python3 "$HELPER" build_fuzzers "$proj" --sanitizer=none --clean \
        -e LLM_FUZZGEN_BUILD_FLAVOR=symcc_library \
        -e LLM_FUZZGEN_BUILD_SYMCC_LIBRARY=1 \
        -e "LLM_FUZZGEN_EXTRA_VOLUMES=${extra_vols}" \
        >"$logfile" 2>&1 || rc=$?
      ;;
    symcc_replay)
      python3 "$HELPER" build_fuzzers "$proj" --sanitizer=coverage --clean \
        -e LLM_FUZZGEN_BUILD_FLAVOR=symcc_replay \
        -e LLM_FUZZGEN_BUILD_SYMCC_REPLAY=1 \
        >"$logfile" 2>&1 || rc=$?
      ;;
  esac

  return $rc
}

check_artifact() {
  local proj="$1" flavor="$2"
  local artifact_rel=""

  case "$flavor" in
    symcc_native)  artifact_rel="${NATIVE_ARTIFACT[$proj]:-}" ;;
    symcc_library) artifact_rel="${LIBRARY_ARTIFACT[$proj]:-}" ;;
    symcc_replay)  echo ""; return 0 ;;  # no fixed artifact to check
  esac

  [ -z "$artifact_rel" ] && { echo ""; return 3; }  # N/A

  local path="$BUILD_OUT/$proj/$artifact_rel"
  if [ -f "$path" ]; then
    local size
    size=$(du -sh "$path" 2>/dev/null | cut -f1)
    echo "${artifact_rel##*/} ($size)"
    return 0
  else
    echo "(artifact not found: $artifact_rel)"
    return 1
  fi
}

validate_symcc_instrumentation() {
  local proj="$1" flavor="$2"
  local artifact_rel=""

  case "$flavor" in
    symcc_library) artifact_rel="${LIBRARY_ARTIFACT[$proj]:-}" ;;
    *)             return 0 ;;
  esac

  [ -z "$artifact_rel" ] && return 0

  local path="$BUILD_OUT/$proj/$artifact_rel"
  [ -f "$path" ] || return 0

  # Must have _sym_* undefined refs (SymCC runtime hooks).
  # Use grep -c (reads full input) not grep -q (exits early → nm SIGPIPE → pipefail false-positive).
  # Use || true not || echo 0: grep -c already outputs "0" on no-match; || true just suppresses exit 1.
  local sym_count sancov_count
  sym_count=$(nm -A "$path" 2>/dev/null | grep -cE '[[:space:]]U[[:space:]]+_sym_' || true)
  if [ "${sym_count:-0}" -eq 0 ]; then
    echo "  ${RED}[warn]${RESET} $artifact_rel: missing _sym_* refs — may NOT be SymCC-instrumented"
  else
    echo "  ${GREEN}[ok]${RESET}   $artifact_rel: $sym_count _sym_* refs found (SymCC instrumented)"
  fi

  # Must NOT have sanitizer coverage symbols
  sancov_count=$(nm -A "$path" 2>/dev/null | grep -cE '__sanitizer_cov_|__sancov_' || true)
  if [ "${sancov_count:-0}" -gt 0 ]; then
    echo "  ${RED}[warn]${RESET} $artifact_rel: sanitizer coverage symbols present — coverage pollution"
  fi
}

# -- main loop --
echo ""
echo "SymCC build test — $(date '+%Y-%m-%d %H:%M:%S')"
echo "SYMCC_BIN: $SYMCC_BIN"
echo "LOG_DIR:   $LOG_DIR"
echo ""

ALL_FLAVORS="symcc_native symcc_library symcc_replay"

for proj in $PROJECTS; do
  for flavor in $ALL_FLAVORS; do
    [ "$FLAVOR" != "all" ] && [ "$FLAVOR" != "$flavor" ] && continue

    # Skip header-only for native/library
    if [ "$flavor" = "symcc_native" ] && [ -z "${NATIVE_ARTIFACT[$proj]:-}" ]; then
      RESULTS["$proj/$flavor"]="skip"
      RESULT_DETAIL["$proj/$flavor"]="header-only"
      continue
    fi
    if [ "$flavor" = "symcc_library" ] && [ -z "${LIBRARY_ARTIFACT[$proj]:-}" ]; then
      RESULTS["$proj/$flavor"]="skip"
      RESULT_DETAIL["$proj/$flavor"]="header-only"
      continue
    fi

    printf "Building %-15s / %-18s ... " "$proj" "$flavor"
    run_build "$proj" "$flavor"
    build_rc=$?

    if [ "$build_rc" -eq 2 ]; then
      RESULTS["$proj/$flavor"]="skip"
      RESULT_DETAIL["$proj/$flavor"]="SYMCC_BIN not found"
      echo -e "${SKIP} (SYMCC_BIN missing)"
      continue
    fi

    if [ "$build_rc" -ne 0 ]; then
      RESULTS["$proj/$flavor"]="fail"
      RESULT_DETAIL["$proj/$flavor"]="build error (see $LOG_DIR/${proj}_${flavor}.log)"
      echo -e "${FAIL}"
      any_fail=1
      continue
    fi

    artifact_info="$(check_artifact "$proj" "$flavor")"
    artifact_rc=$?

    if [ "$artifact_rc" -eq 3 ]; then
      # should not happen (already handled above)
      RESULTS["$proj/$flavor"]="skip"
      RESULT_DETAIL["$proj/$flavor"]="N/A"
      echo -e "${SKIP}"
    elif [ "$artifact_rc" -ne 0 ]; then
      RESULTS["$proj/$flavor"]="fail"
      RESULT_DETAIL["$proj/$flavor"]="$artifact_info"
      echo -e "${FAIL}  $artifact_info"
      any_fail=1
    else
      if [ "$flavor" = "symcc_replay" ]; then
        RESULTS["$proj/$flavor"]="pass"
        RESULT_DETAIL["$proj/$flavor"]="build ok"
        echo -e "${PASS}  (build ok)"
      else
        RESULTS["$proj/$flavor"]="pass"
        RESULT_DETAIL["$proj/$flavor"]="$artifact_info"
        echo -e "${PASS}  $artifact_info"
        validate_symcc_instrumentation "$proj" "$flavor"
      fi
    fi
  done
done

# -- summary --
echo ""
echo "================================================================"
echo " SymCC Build Test Summary"
echo "================================================================"
printf "%-18s  %-18s  %s\n" "Project" "Flavor" "Result"
echo "----------------------------------------------------------------"

for proj in $PROJECTS; do
  for flavor in $ALL_FLAVORS; do
    [ "$FLAVOR" != "all" ] && [ "$FLAVOR" != "$flavor" ] && continue
    key="$proj/$flavor"
    result="${RESULTS[$key]:-}"
    detail="${RESULT_DETAIL[$key]:-}"
    [ -z "$result" ] && continue

    case "$result" in
      pass) label="${GREEN}PASS${RESET}" ;;
      fail) label="${RED}FAIL${RESET}" ;;
      skip) label="${YELLOW}SKIP${RESET}" ;;
    esac

    printf "%-18s  %-18s  " "$proj" "$flavor"
    echo -e "${label}  ${detail}"
  done
done

echo ""
if [ "$any_fail" -eq 1 ]; then
  echo -e "${RED}Some builds FAILED.${RESET} Check logs in $LOG_DIR/"
  exit 1
else
  echo -e "${GREEN}All tested builds passed.${RESET}"
  exit 0
fi
