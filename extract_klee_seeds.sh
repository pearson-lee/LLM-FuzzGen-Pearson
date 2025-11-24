#!/bin/bash

set -e

KLEE_IMAGE="klee/klee:2.3"

echo "=========================================="
echo "Extracting KLEE test cases to seeds"
echo "=========================================="

# 檢查測試案例是否存在
if [ ! -d "./klee_output" ] || [ -z "$(ls -A ./klee_output/*.ktest 2>/dev/null)" ]; then
    echo "ERROR: No KLEE test cases found!"
    echo "Please run ./run_klee.sh first"
    exit 1
fi

# 創建種子目錄
mkdir -p ./klee_seeds

echo "Extracting test cases..."
echo ""

docker run --rm \
    -v "$(pwd)/klee_output:/input" \
    -v "$(pwd)/klee_seeds:/output" \
    $KLEE_IMAGE \
    bash -c "
        cd /input
        COUNT=0
        
        for ktest in *.ktest; do
            if [ -f \"\$ktest\" ]; then
                # 提取輸入資料
                ktest-tool --write-ints \"\$ktest\" > /tmp/temp.txt
                
                # 解析並儲存為二進位檔案
                python3 << 'PYTHON'
import sys
import re

with open('/tmp/temp.txt', 'r') as f:
    content = f.read()
    
# 找到 input 物件的資料
match = re.search(r\"name: b'input'.*?data: b'(.*?)'\", content, re.DOTALL)
if match:
    data_str = match.group(1)
    # 轉換為 bytes
    data = data_str.encode('latin1').decode('unicode_escape').encode('latin1')
    sys.stdout.buffer.write(data)
PYTHON
                
                if [ \$? -eq 0 ]; then
                    mv /tmp/temp.txt \"/output/seed_\${ktest%.ktest}\"
                    COUNT=\$((COUNT + 1))
                fi
            fi
        done
        
        echo \"Extracted \$COUNT seeds\"
    "

echo ""
echo "=========================================="
echo "✓ Seed extraction completed!"
echo "=========================================="
echo ""

if [ -d "./klee_seeds" ]; then
    SEED_COUNT=$(ls ./klee_seeds/ 2>/dev/null | wc -l)
    echo "Seeds saved to: $(pwd)/klee_seeds/"
    echo "Total seeds: $SEED_COUNT"
    echo ""
    
    if [ $SEED_COUNT -gt 0 ]; then
        echo "Sample seeds:"
        ls -lh ./klee_seeds/ | head -n 10
        echo ""
        echo "Add these to your fuzzer corpus:"
        echo "  cp ./klee_seeds/* /path/to/fuzzer/corpus/"
    fi
fi