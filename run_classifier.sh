#!/bin/bash

# 指定包含指令的檔案路徑
COMMAND_FILE="classify_command/tinyxml2_dynamic_classify_command.txt"

usage() {
    echo "Usage: $0 [-n NUM]"
    echo "  -n NUM   Run only the first NUM command blocks from $COMMAND_FILE (blocks separated by blank lines)"
    exit 1
}

NUM=""
while getopts ":n:h" opt; do
    case $opt in
        n) NUM="$OPTARG" ;;
        h) usage ;;
        \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
        :) echo "Option -$OPTARG requires an argument." >&2; usage ;;
    esac
done
shift $((OPTIND - 1))

# 確保檔案存在
if [ ! -f "$COMMAND_FILE" ]; then
    echo "找不到檔案: $COMMAND_FILE"
    exit 1
fi

if [ -z "$NUM" ]; then
    # 執行全部命令，保留 Windows CRLF 的情況
    sed 's/\r$//' "$COMMAND_FILE" | bash
else
    # 驗證 NUM 為正整數
    if ! [[ "$NUM" =~ ^[1-9][0-9]*$ ]]; then
        echo "-n requires a positive integer" >&2
        exit 1
    fi
    # 將檔案以空白行為分隔（paragraph mode）取前 NUM 個區塊，再執行
    awk -v n="$NUM" 'BEGIN{RS=""; ORS="\n\n"} NR<=n{print}' "$COMMAND_FILE" | sed 's/\r$//' | bash
fi