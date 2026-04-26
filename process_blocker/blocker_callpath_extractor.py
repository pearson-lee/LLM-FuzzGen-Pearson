import sys
import os
from types import SimpleNamespace
from typing import List, Optional, Any
import yaml
from global_blocker_selector import aggregate_and_score_blockers
from typing import Optional
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "external", "fuzz-introspector", "src"))

from external.introspector import Introspector
from fuzz_introspector import utils, cfg_load

PROJECT_NAME = "tinyxml2"

def get_data_file_for_target(yaml_path: str, target_name: str) -> Optional[str]:
    if not os.path.exists(yaml_path):
        print(f"[Error] YAML file not found at: {yaml_path}")
        return None

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            
        if not data or "pairings" not in data:
            return None

        for pair in data["pairings"]:
            executable_path = pair.get("executable_path", "")
            base_name = os.path.basename(executable_path)
            
            if base_name == target_name:
                log_file = pair.get("fuzzer_log_file")
                file_name = f"{log_file}.data" if not log_file.endswith(".data") else log_file
                
                yaml_dir = os.path.dirname(yaml_path)
                return os.path.join(yaml_dir, file_name)
                
    except Exception as e:
        print(f"[Error] Failed to parse YAML {yaml_path}: {e}")
        
    return None

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
        if node.dst_function_name == target_raw_name:
            target_inner_depth = node.depth + 1
            closest_node = node
            
            for next_node in all_nodes[idx + 1:]:
                if target_inner_depth > next_node.depth:
                    break  
                    
                if (target_inner_depth == next_node.depth and 
                    branch_line_number >= next_node.src_linenumber):
                    closest_node = next_node
            
            return closest_node

    return None


def build_call_chain(target_node: Any) -> List[Any]:
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
    if not raw_name:
        return ""
        
    func_info_list = introspector.get_all_functions(project_name)
    target_signature = ""
    
    for func in func_info_list:
        if func.get('raw_function_name', '') == raw_name:
            target_signature = func.get('function_signature', '')
            break
            
    if target_signature:
        return introspector.function_source_code(project_name, target_signature)
        
    return ""

def get_unique_source_codes(chain: List[Any], introspector: Introspector, project_name: str) -> str:
    if not chain:
        return ""
        
    seen_functions = set()
    collected_sources = []
    
    for node in chain:
        raw_name = node.dst_function_name
        
        if raw_name in seen_functions:
            continue
            
        seen_functions.add(raw_name)
        
        source_code = get_node_source_code(introspector, project_name, raw_name)
        if source_code:
            collected_sources.append(source_code)
            
    return "\n\n".join(collected_sources)


def main():
    json_path = "branch-blockers.json"
    print("[Info] Analyzing global blockers...")
    global_blockers = aggregate_and_score_blockers(json_path, top_k=12)
    
    if not global_blockers:
        print("[Error] No global blockers found or file missing.")
        return
        
    top1_blocker_dict = global_blockers[0]
    
    blocker = top1_blocker_dict 

    print(f"[Info] Target Top-1 Blocker selected in function: {blocker['function_name']}")
    print(f"[Info] Best Target evaluated: {blocker['best_target']}")
    print(blocker)

    yaml_file = "/home/kyliechien/LLM-FuzzGen/external/oss-fuzz/build/out/tinyxml2/inspector/exe_to_fuzz_introspector_logs.yaml"
    
    target = blocker['best_target'] 
    cfg_file_path = get_data_file_for_target(yaml_file, target)

    if not cfg_file_path or not os.path.exists(cfg_file_path):
        print(f"[Error] Data file not found for target {target}: {cfg_file_path}")
        return

    # Initialize Introspector
    introspector = Introspector()

    with open(cfg_file_path, "r", encoding="utf-8", errors="ignore") as f:
        cfg_content = f.read()

    root_node = cfg_load.data_file_read_calltree(cfg_content)
    if not root_node:
        print("[Error] Failed to parse calltree root.")
        return

    all_nodes = cfg_load.extract_all_callsites(root_node)

    # Execute search and construct the Call chain
    raw_blocker_name = get_mangled_function_name(introspector, PROJECT_NAME, blocker['function_name']) 
    print(f"[Info] Raw blocker function name (mangled): {raw_blocker_name}")
    branch_line_number = int(blocker['branch_line_number'])

    target_node = find_closest_callsite_to_blocker(all_nodes, raw_blocker_name, branch_line_number)
    
    if target_node:
        call_chain = build_call_chain(target_node)
        chain_structure_info = get_call_chain_structure(call_chain)
        unique_code_info = get_unique_source_codes(call_chain, introspector, PROJECT_NAME)
            
        print("\n=== Information 1: Call Chain Structure ===")
        print(chain_structure_info)
        print("\n=== Information 2: Unique Source Codes ===")
        print(unique_code_info)
    else:
        print("[Info] No matching callsite found for the specified blocker.")

if __name__ == "__main__":
    main()