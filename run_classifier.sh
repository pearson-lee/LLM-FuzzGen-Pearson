#!/bin/bash

# 指定包含指令的檔案路徑
COMMAND_FILE="classify_command/tinyxml2_dynamic_classify_command.txt"

# 確保檔案存在
if [ ! -f "$COMMAND_FILE" ]; then
    echo "找不到檔案: $COMMAND_FILE"
    exit 1
fi

sed 's/\r$//' "$COMMAND_FILE" | bash