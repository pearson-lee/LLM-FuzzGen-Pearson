#!/usr/bin/env bash

# Fail on any error, undefined variables, and prevent masking pipeline errors
set -euo pipefail

# Script constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OSS_FUZZ_DIR="${SCRIPT_DIR}/work/oss-fuzz"
readonly FI_DIR="${SCRIPT_DIR}/work/fuzz-introspector"
readonly DEFAULT_SECONDS=30
readonly WEBAPP_PORT=8080

# Logging functions
log() { echo "[+] $*" >&2; }
error() { echo "[!] $*" >&2; }
die() { error "$*"; exit 1; }

# Usage/help message
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] PROJECT_NAME...

Options:
    --clean         Clean build directories and exit
    --seconds N     Set execution time (default: ${DEFAULT_SECONDS})
    -h, --help     Show this help message

Arguments:
    PROJECT_NAME    One or more OSS-Fuzz project names
EOF
    exit "${1:-0}"
}

# Cleanup function
cleanup() {
    log "Shutting down webserver..."
    curl --silent "http://localhost:${WEBAPP_PORT}/api/shutdown" || true
}

# Generate introspector report for a project
generate_report() {
    local project="$1"
    local seconds="$2"
    log "Creating introspector reports for $project"
    if ! python3 "${OSS_FUZZ_DIR}/infra/helper.py" introspector --seconds "$seconds" "$project"; then
        error "Failed to generate report for $project"
        return 1
    fi
}

main() {
    local seconds="$DEFAULT_SECONDS"
    local projects=()

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --clean)
                log "Cleaning build directories..."
                rm -rf "${OSS_FUZZ_DIR}/build"
                rm -rf "${FI_DIR}"/tools/web-fuzzing-introspection/app/static/assets/db/db-projects
                rm -f "${FI_DIR}"/tools/web-fuzzing-introspection/app/static/assets/db/*.json
                rm -f "${FI_DIR}/tools/web-fuzzing-introspection/app/static/assets/db/db-archive.zip"
                rm -f "${OSS_FUZZ_DIR}/projects/*/fuzz_*_fuzzer.*"
                exit 0
                ;;
            --seconds)
                [[ -n "${2:-}" ]] || die "Missing value for --seconds"
                seconds="$2"
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                projects+=("$1")
                ;;
        esac
        shift
    done

    # Validate inputs
    [[ ${#projects[@]} -gt 0 ]] || die "At least one project name required"
    [[ "$seconds" =~ ^[0-9]+$ ]] || die "Seconds must be a positive integer"

    # Setup trap for cleanup
    trap cleanup EXIT

    # Process projects
    log "Targeting projects: ${projects[*]}"
    for project in "${projects[@]}"; do
        generate_report "$project" "$seconds" &
    done

    # Wait for all background processes
    wait

    # Initialize and start web server
    log "Creating and launching webapp"
    cd "${FI_DIR}/tools/web-fuzzing-introspection/app/static/assets/db/" || die "Failed to change directory"
    python3 ./web_db_creator_from_summary.py --local-oss-fuzz "${OSS_FUZZ_DIR}"

    cd "${FI_DIR}/tools/web-fuzzing-introspection/app/" || die "Failed to change directory"
    FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ="${OSS_FUZZ_DIR}" python3 ./main.py
}

main "$@"