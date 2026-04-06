import re

def strip_comments(code: str) -> str:
    result = []
    i = 0
    n = len(code)

    while i < n:
        # 1. C++ Raw string literal: R"delimiter(...)delimiter"
        if code[i] == 'R' and i + 1 < n and code[i+1] == '"':
            j = i + 2
            delimiter = []
            while j < n and code[j] != '(' and code[j] != '"':
                delimiter.append(code[j])
                j += 1
            if j < n and code[j] == '(':
                end_marker = ')' + ''.join(delimiter) + '"'
                end_idx = code.find(end_marker, j + 1)
                if end_idx != -1:
                    result.append(code[i:end_idx + len(end_marker)])
                    i = end_idx + len(end_marker)
                    continue
            result.append(code[i])
            i += 1
            continue

        # 2. 行尾註解 //
        if code[i:i+2] == '//':
            i += 2
            while i < n:
                # [修正] 處理 C++ Line Splicing: 單行註解尾部帶有 \ 且緊接換行
                if code[i] == '\\' and i + 1 < n and code[i+1] == '\n':
                    i += 2
                    result.append('\n') # 保持換行，維持行號
                    continue
                
                if code[i] == '\n':
                    break # 遇到一般的換行則跳出，讓 Rule 6 處理這個 \n
                i += 1
            continue

        # 3. 區塊註解 /* */
        if code[i:i+2] == '/*':
            i += 2
            newlines = 0
            while i < n and code[i:i+2] != '*/':
                if code[i] == '\n':
                    newlines += 1 # 紀錄被註解吃掉的換行數
                i += 1
            i += 2  # 跳過 */
            
            # [修正] 補充流失的換行符號，維持 Fuzz Target 程式碼行號絕對一致
            if newlines > 0:
                result.append('\n' * newlines)
            continue

        # 4. 字串字面量 "..."（含 escape）
        if code[i] == '"':
            result.append(code[i])
            i += 1
            while i < n:
                if code[i] == '\\' and i + 1 < n:
                    result.append(code[i:i+2])
                    i += 2
                elif code[i] == '"':
                    result.append(code[i])
                    i += 1
                    break
                else:
                    result.append(code[i])
                    i += 1
            continue

        # 5. 字元字面量 '...'（含 escape）
        if code[i] == "'":
            result.append(code[i])
            i += 1
            while i < n:
                if code[i] == '\\' and i + 1 < n:
                    result.append(code[i:i+2])
                    i += 2
                elif code[i] == "'":
                    result.append(code[i])
                    i += 1
                    break
                else:
                    result.append(code[i])
                    i += 1
            continue

        # 6. 一般字元
        result.append(code[i])
        i += 1

    stripped = ''.join(result)
    
    # [強烈建議] 註解掉這行，保留原本的空行，可以讓人類看原始檔與處理後的檔案時，行號完全一致
    # stripped = re.sub(r'\n[ \t]*\n', '\n', stripped)
    
    return stripped