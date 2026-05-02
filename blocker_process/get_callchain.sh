#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <fuzzer-binary> <corpus-file-or-dir> <breakpoint>"
    echo "Example: $0 ./fuzz_target ./seeds_input/ tinyxml2.cpp:1972"
    echo "Example: $0 ./fuzz_target ./seed.xml tinyxml2.cpp:1972"
    exit 1
fi

FUZZER_BIN=$1
CORPUS_PATH=$2
BREAKPOINT=$3

echo "[*] Fuzzer binary  : $FUZZER_BIN"
echo "[*] Corpus path    : $CORPUS_PATH"
echo "[*] Breakpoint     : $BREAKPOINT"
echo "[*] Collecting runtime call chain with GDB..."
echo "---------------------------------------------------"

ARTIFACT_PREFIX="/tmp/llm-fuzzgen-gdb-artifacts/"
mkdir -p "$ARTIFACT_PREFIX"

if [ -d "$CORPUS_PATH" ]; then
    mapfile -t SEED_LIST < <(find "$CORPUS_PATH" -maxdepth 1 -type f | sort)
    if [ "${#SEED_LIST[@]}" -eq 0 ]; then
        echo "[error] no replayable seed files found in corpus directory: $CORPUS_PATH"
        exit 1
    fi
elif [ -f "$CORPUS_PATH" ]; then
    SEED_LIST=("$CORPUS_PATH")
else
    echo "[error] corpus path not found: $CORPUS_PATH"
    exit 1
fi

echo "[*] Seed count     : ${#SEED_LIST[@]}"

TOTAL_SEEDS=${#SEED_LIST[@]}
CURRENT_INDEX=0

for RUN_ARG in "${SEED_LIST[@]}"; do
    CURRENT_INDEX=$((CURRENT_INDEX + 1))
    echo "[*] Progress       : $CURRENT_INDEX/$TOTAL_SEEDS"

    GDB_OUTPUT=$(gdb -batch \
        -ex "set pagination off" \
        -ex "set print frame-arguments all" \
        -ex "break $BREAKPOINT" \
        -ex "run -runs=0 -rss_limit_mb=0 -timeout=0 -artifact_prefix=$ARTIFACT_PREFIX $RUN_ARG" \
        -ex "echo \n\n================ ACTUAL CALL CHAIN ================\n\n" \
        -ex "backtrace 64" \
        -ex "quit" \
        "$FUZZER_BIN" 2>&1)

    if printf '%s\n' "$GDB_OUTPUT" | grep -q "ptrace: Operation not permitted"; then
        echo "[error] GDB could not start the target process because ptrace is not permitted."
        echo "[error] Raw GDB output:"
        printf '%s\n' "$GDB_OUTPUT"
        exit 2
    fi

    if printf '%s\n' "$GDB_OUTPUT" | grep -q "During startup program exited"; then
        echo "[error] GDB failed before the target started, so no breakpoint/call chain could be collected."
        echo "[error] Raw GDB output:"
        printf '%s\n' "$GDB_OUTPUT"
        exit 2
    fi

    if printf '%s\n' "$GDB_OUTPUT" | grep -Eq '^#0 '; then
        echo "[*] Hit seed       : $RUN_ARG"
        echo
        echo "================ ACTUAL CALL CHAIN ================"
        printf '%s\n' "$GDB_OUTPUT" | awk '
            /^#0 / { printing=1 }
            printing { print }
        '
        exit 0
    fi
done

echo "[warn] no existing seed hit the breakpoint: $BREAKPOINT"
exit 1
