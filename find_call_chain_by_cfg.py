import sys
import os
from types import SimpleNamespace
from typing import List, Optional, Any
import yaml
from typing import Optional
sys.path.insert(0, os.path.abspath("external/fuzz-introspector/src"))

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
                return f"{log_file}.data" if not log_file.endswith(".data") else log_file
                
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
        # 1. Find the entry point of the target function
        if node.dst_function_name == target_raw_name:
            target_inner_depth = node.depth + 1
            closest_node = node  # Default to the function entry point itself
            
            # 2. Search downwards for internal function calls (Heuristic search)
            for next_node in all_nodes[idx + 1:]:
                # If the depth is less than or equal to the intended target entry depth, 
                # it means the execution has returned and left the function
                if target_inner_depth > next_node.depth:
                    break  
                    
                # If it is a call at the same level inside the function, 
                # and occurs before or on the exact same line as the blocker branch
                if (target_inner_depth == next_node.depth and 
                    branch_line_number >= next_node.src_linenumber):
                    closest_node = next_node
            
            # Return the exact node once found, stop traversing the outer layers
            return closest_node

    return None


def build_call_chain(target_node: Any) -> List[Any]:
    """
    Trace upwards from the target node to construct the Call chain from Root to Target.
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
    Generate a formatted call chain tree string containing depth, function name, and file location.
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
    Find the corresponding function signature using the raw function name (mangled name),
    and call function_source_code to retrieve its source code.
    """
    if not raw_name:
        return ""
        
    func_info_list = introspector.get_all_functions(project_name)
    target_signature = ""
    
    # Search for the matching raw_function_name to obtain the function_signature
    for func in func_info_list:
        if func.get('raw_function_name', '') == raw_name:
            target_signature = func.get('function_signature', '')
            break
            
    if target_signature:
        return introspector.function_source_code(project_name, target_signature)
        
    return ""

def get_unique_source_codes(chain: List[Any], introspector: Introspector, project_name: str) -> str:
    """
    Collect all unique source codes from the Call chain, and combine them into a single string.
    """
    if not chain:
        return ""
        
    seen_functions = set()
    collected_sources = []
    
    for node in chain:
        raw_name = node.dst_function_name
        
        # Skip if we already collected the source code for this function
        if raw_name in seen_functions:
            continue
            
        seen_functions.add(raw_name)
        
        source_code = get_node_source_code(introspector, project_name, raw_name)
        if source_code:
            collected_sources.append(source_code)
            
    return "\n\n".join(collected_sources)


def main():
    yaml_file = "/home/kyliechien/LLM-FuzzGen/external/oss-fuzz/build/out/tinyxml2/inspector/exe_to_fuzz_introspector_logs.yaml"
    target = "llm_fuzzgen0626133053"
    cfg_file_path = get_data_file_for_target(yaml_file, target)
    


    # Initialize Introspector (create once to reuse the cache)
    introspector = Introspector()
    
    # 1. Read and parse the Calltree
    if not os.path.exists(cfg_file_path):
        print(f"[Error] Data file not found: {cfg_file_path}")
        return

    with open(cfg_file_path, "r", encoding="utf-8", errors="ignore") as f:
        cfg_content = f.read()

    root_node = cfg_load.data_file_read_calltree(cfg_content)
    if not root_node:
        print("[Error] Failed to parse calltree root.")
        return

    all_nodes = cfg_load.extract_all_callsites(root_node)

    # 2. Mock Blocker data
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
    )

    # 3. Execute search and construct the Call chain
    raw_blocker_name = get_mangled_function_name(introspector, PROJECT_NAME, blocker.function_name) 
    branch_linenumber = int(blocker.branch_line_number)

    target_node = find_closest_callsite_to_blocker(all_nodes, raw_blocker_name, branch_linenumber)
    
    if target_node:
        call_chain = build_call_chain(target_node)
            
        # Get Information 1: Call chain structure
        chain_structure_info = get_call_chain_structure(call_chain)
            
        # Get Information 2: Unique source codes
        unique_code_info = get_unique_source_codes(call_chain, introspector, PROJECT_NAME)
            
        # [Demo] Print out or return to your LLM module
        print("=== Information 1: Call Chain Structure ===")
        print(chain_structure_info)
        print("\n=== Information 2: Unique Source Codes ===")
        print(unique_code_info)
            
        # If this script is imported as a module in the future, you could change this to:
        # return {"chain_structure": chain_structure_info, "source_codes": unique_code_info}
    else:
        print("[Info] No matching callsite found for the specified blocker.")

if __name__ == "__main__":
    main()