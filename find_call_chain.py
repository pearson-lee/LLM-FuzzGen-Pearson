import logging
import re
from external.introspector import Introspector

logging.basicConfig(level=logging.WARNING)

def find_signature_by_name(ins: Introspector, project_name: str, target_func_name: str) -> str:
    all_funcs = ins.get_all_functions(project_name)
    escaped_name = re.escape(target_func_name)
    pattern = re.compile(rf"{escaped_name}\s*\(")
    
    candidates = []
    for func in all_funcs:
        sig = func.get("function_signature", "")
        if pattern.search(sig):
            candidates.append(sig)
            
    if not candidates:
        return ""
    if len(candidates) > 1:
        print(f"   [警告] 找到多個多載 (Overload) 函式，預設選擇第一個: {candidates[0]}")
    return candidates[0]

def build_call_chain_source(project_name: str, target_func_name: str, max_depth: int = 5) -> str:
    ins = Introspector()
    
    print(f"\n[1] 正在尋找目標函數 '{target_func_name}' 的 Signature...")
    start_sig = find_signature_by_name(ins, project_name, target_func_name)
    if not start_sig:
        print("錯誤: 找不到匹配的函數")
        return ""
    print(f"找到目標函數 Signature: {start_sig}")

    # 使用 BFS (廣度優先) 的概念來尋找一條通往 Fuzzer 的路徑
    # 佇列裡面儲存: [(目前的節點, [歷史路徑路徑])]
    queue = [(start_sig, [start_sig])]
    best_path = []
    
    print("\n[2] 開始反向追蹤 Call Chain (搜尋所有 Caller)...")
    
    # 防止無限迴圈的全域 visited 集合
    visited = set([start_sig])
    
    while queue:
        current_sig, path = queue.pop(0)
        
        # 檢查深度
        if len(path) > max_depth + 1:
            continue
            
        print(f"   目前檢查: {current_sig} (Depth {len(path)-1})")
        
        # 如果抵達了 Fuzzer 相關函數，這就是最好的路徑！
        if "LLVMFuzzerTestOneInput" in current_sig or "fuzzgen" in current_sig.lower():
            print("   >>> 成功找到抵達 Fuzz Target 的路徑！")
            best_path = path
            break

        callers = ins.get_function_cross_references(project_name, current_sig)
        callers = [c for c in callers if c.get("src_func_signature")]
        
        # 如果走到死胡同但還沒找到 fuzzer，先把這條路徑存起來當作備用 (Fallback)
        # 這樣如果真的都沒有完美路徑，我們至少能提供最長的一條給 LLM
        if not callers and len(path) > len(best_path):
            best_path = path
            
        for c in callers:
            parent_sig = c["src_func_signature"]
            
            # 重要：避免遞迴造成的無限迴圈！
            if parent_sig not in path:
                if parent_sig not in visited:
                    visited.add(parent_sig)
                    queue.append((parent_sig, [parent_sig] + path)) # 把 parent 放前面
    
    if not best_path:
        best_path = [start_sig] # 最差的情況只回傳自己
        
    print("\n[3] 正在提取尋找到的路徑上的原始碼...")
    combined_source = ""
    for signature in best_path:
        print(f"   抓取程式碼: {signature}")
        code = ins.function_source_code(project_name, signature)
        if code:
            combined_source += f"// --- Function: {signature} ---\n"
            combined_source += code + "\n\n"
        else:
            combined_source += f"// --- Function: {signature} (Source Code NOT FOUND) ---\n\n"
            
    return combined_source

def main():
    TEST_PROJECT = "tinyxml2"
    TEST_TARGET_FUNC = "XMLNode::ParseDeep"
    result = build_call_chain_source(TEST_PROJECT, TEST_TARGET_FUNC, max_depth=8) # 可以把 depth 調高一點
    if result:
        print("\n\n================== 合併結果 ==================")
        print(result)

if __name__ == "__main__":
    main()