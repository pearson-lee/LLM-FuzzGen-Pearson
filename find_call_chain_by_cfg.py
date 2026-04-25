import sys
import os
from types import SimpleNamespace
from typing import List, Optional, Any

sys.path.insert(0, os.path.abspath("external/fuzz-introspector/src"))

from external.introspector import Introspector
from fuzz_introspector import utils, cfg_load

PROJECT_NAME = "tinyxml2"
DATA_PATH = "fuzzerLogFile-0-AA7rfCazZm.data"

def get_mangled_function_name(introspector: Introspector, project_name: str, func_name: str) -> str:
    func_name_list = introspector.get_all_functions(project_name)
    query_name_normalized = func_name.replace(' ', '')
    
    for func in func_name_list:
        target_name_normalized = func.get('function_name', '').replace(' ', '')
        if target_name_normalized == query_name_normalized:
            return func.get('raw_function_name', '')
            
    print(f"[Warning] Could not find mangled name for '{func_name}' in project '{project_name}'")
    return ""


def find_closest_callsite_to_blocker(all_nodes: List[Any], target_raw_name: str, branch_line_number: int) -> Optional[Any]:
    if not target_raw_name:
        return None

    for idx, node in enumerate(all_nodes):
        # 1. 找到目標函式的進入點
        if node.dst_function_name == target_raw_name:
            target_inner_depth = node.depth + 1
            closest_node = node  # 預設為函式進入點本身
            
            # 2. 往下尋找函式內部的呼叫 (Heuristic search)
            for next_node in all_nodes[idx + 1:]:
                # 若深度小於等於目標進入點的深度，代表已經 Return 離開該函式
                if target_inner_depth > next_node.depth:
                    break  
                    
                # 若為函式內部的同層級呼叫，且發生在 Blocker 分支之前或同行
                if (target_inner_depth == next_node.depth and 
                    branch_line_number >= next_node.src_linenumber):
                    closest_node = next_node
            
            # 找到精確節點後直接回傳，不再繼續遍歷外層
            return closest_node

    return None


def build_call_chain(target_node: Any) -> List[Any]:
    """
    從目標節點往上回溯，建構出 Root 到 Target 的 Call chain。
    """
    if not target_node:
        return []
        
    chain = []
    current_node = target_node
    while current_node is not None:
        chain.append(current_node)
        current_node = current_node.parent_calltree_callsite
        
    chain.reverse()
    return chain

def get_call_chain_structure(chain: List[Any]) -> str:
    """
    產生包含 depth、函式名稱與檔案位置的 Call chain 樹狀字串。
    """
    if not chain:
        return "Empty call chain."
        
    lines = ["Call chain (Root -> Target):"]
    for node in chain:
        indent = "  " * int(node.depth)
        demangled_name = utils.demangle_cpp_func(node.dst_function_name)
        lines.append(
            f"{indent}-> depth={node.depth} "
            f"demangled={demangled_name} "
            f"file={node.dst_function_source_file} "
            f"line={node.src_linenumber}"
        )
        
    return "\n".join(lines)

def get_node_source_code(introspector: Introspector, project_name: str, raw_name: str) -> str:
    """
    透過 raw function name (mangled name) 找出對應的 function signature，
    並呼叫 function_source_code 獲取其原始碼。
    """
    if not raw_name:
        return ""
        
    func_info_list = introspector.get_all_functions(project_name)
    target_signature = ""
    
    # 尋找匹配的 raw_function_name 以取得 function_signature
    for func in func_info_list:
        if func.get('raw_function_name', '') == raw_name:
            target_signature = func.get('function_signature', '')
            break
            
    if target_signature:
        return introspector.function_source_code(project_name, target_signature)
        
    return ""

def get_unique_source_codes(chain: List[Any], introspector: Introspector, project_name: str) -> str:
    """
    收集 Call chain 中所有不重複的原始碼，並合併成一個字串。
    """
    if not chain:
        return ""
        
    seen_functions = set()
    collected_sources = []
    
    for node in chain:
        raw_name = node.dst_function_name
        
        # 如果這個函式已經拿過原始碼，就跳過
        if raw_name in seen_functions:
            continue
            
        seen_functions.add(raw_name)
        
        source_code = get_node_source_code(introspector, project_name, raw_name)
        if source_code:
            collected_sources.append(source_code)
            
    return "\n\n".join(collected_sources)


def main():
    # 初始化 Introspector (建立一次即可重複使用快取)
    introspector = Introspector()
    
    # 1. 讀取並解析 Calltree
    if not os.path.exists(DATA_PATH):
        print(f"[Error] Data file not found: {DATA_PATH}")
        return

    with open(DATA_PATH, "r", encoding="utf-8", errors="ignore") as f:
        cfg_content = f.read()

    root_node = cfg_load.data_file_read_calltree(cfg_content)
    if not root_node:
        print("[Error] Failed to parse calltree root.")
        return

    all_nodes = cfg_load.extract_all_callsites(root_node)

    # 2. 模擬 Blocker 資料
    blocker = SimpleNamespace(
        blocked_side="0",
        blocked_unique_not_covered_complexity=20,
        blocked_unique_reachable_complexity=20,
        blocked_unique_functions=["tinyxml2::StrPair::CollapseWhitespace()"],
        blocked_not_covered_complexity=20,
        blocked_reachable_complexity=20,
        sides_hitcount_diff=1800,
        source_file="/src/tinyxml2/tinyxml2.cpp",
        branch_line_number="372",
        blocked_side_line_numder="373",
        function_name="tinyxml2::StrPair::GetStr()",
        coverage_report_link=""
    )

    # 3. 執行搜尋與建構 Call chain
    raw_blocker_name = get_mangled_function_name(introspector, PROJECT_NAME, blocker.function_name) 
    branch_linenumber = int(blocker.branch_line_number)

    target_node = find_closest_callsite_to_blocker(all_nodes, raw_blocker_name, branch_linenumber)
    
    if target_node:
        call_chain = build_call_chain(target_node)
            
            # 取得資訊 1: Call chain 結構
        chain_structure_info = get_call_chain_structure(call_chain)
            
            # 取得資訊 2: 不重複的原始碼
        unique_code_info = get_unique_source_codes(call_chain, introspector, PROJECT_NAME)
            
            # [示範] 印出或是回傳給您的 LLM 模組
        print("=== Information 1: Call Chain Structure ===")
        print(chain_structure_info)
        print("\n=== Information 2: Unique Source Codes ===")
        print(unique_code_info)
            
            # 這個腳本如果未來被當作 module import，您可以改成:
            # return {"chain_structure": chain_structure_info, "source_codes": unique_code_info}
    else:
        print("[Info] No matching callsite found for the specified blocker.")

if __name__ == "__main__":
    main()