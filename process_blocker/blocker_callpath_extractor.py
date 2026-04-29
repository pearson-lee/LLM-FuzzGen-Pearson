import sys
import os
import subprocess
import re
from types import SimpleNamespace
from typing import List, Optional, Any
import yaml
from global_blocker_selector import aggregate_and_score_blockers
from typing import Optional
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "external", "fuzz-introspector", "src"))

try:
    from external.introspector import Introspector
    from fuzz_introspector import utils, cfg_load
    INTROSPECTOR_AVAILABLE = True
    INTROSPECTOR_IMPORT_ERROR = ""
except Exception as exc:
    Introspector = Any  # type: ignore
    utils = None  # type: ignore
    cfg_load = None  # type: ignore
    INTROSPECTOR_AVAILABLE = False
    INTROSPECTOR_IMPORT_ERROR = str(exc)

PROJECT_NAME = "tinyxml2"
DEFAULT_OUT_DIR = os.path.join(PROJECT_ROOT, "external", "oss-fuzz", "build", "out", PROJECT_NAME)
DEFAULT_CORPUS_ROOT = os.path.join(PROJECT_ROOT, "external", "oss-fuzz", "build", "corpus", PROJECT_NAME)
DEFAULT_ARTIFACT_PREFIX = "/tmp/llm-fuzzgen-gdb-artifacts/"

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

def normalize_gdb_symbol(symbol: str) -> str:
    if not symbol:
        return ""
    normalized = symbol.strip()
    if normalized.endswith(" ()"):
        normalized = normalized[:-3]
    return normalized


def get_short_function_name(symbol: str) -> str:
    normalized = normalize_gdb_symbol(symbol)
    if not normalized:
        return ""
    before_args = normalized.split("(", 1)[0]
    return before_args.split("::")[-1].strip()

def resolve_fuzzer_paths(target_name: str,
                         out_dir: str = DEFAULT_OUT_DIR,
                         corpus_root: str = DEFAULT_CORPUS_ROOT) -> dict:
    fuzzer_bin = os.path.join(out_dir, target_name)
    corpus_dir = os.path.join(corpus_root, target_name)

    return {
        "fuzzer_bin": fuzzer_bin,
        "corpus_dir": corpus_dir,
        "fuzzer_exists": os.path.isfile(fuzzer_bin),
        "corpus_exists": os.path.isdir(corpus_dir)
    }


def list_corpus_inputs(corpus_dir: str, limit: Optional[int] = None) -> List[str]:
    if not os.path.isdir(corpus_dir):
        return []

    corpus_inputs = []
    for entry in sorted(os.listdir(corpus_dir)):
        full_path = os.path.join(corpus_dir, entry)
        if os.path.isfile(full_path):
            corpus_inputs.append(full_path)

    if limit is not None:
        return corpus_inputs[:limit]
    return corpus_inputs


def parse_gdb_backtrace(gdb_output: str) -> List[dict]:
    frames = []
    for line in gdb_output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue

        match = re.match(r"^#(\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(.+?)(?:\s+at\s+(.+?):(\d+)|\s+from\s+(.+))?$", stripped)
        if not match:
            frames.append({"raw": stripped})
            continue

        frame_no, symbol, src_file, src_line, shared_obj = match.groups()
        frames.append({
            "frame": int(frame_no),
            "symbol": symbol,
            "file": src_file,
            "line": int(src_line) if src_line else None,
            "shared_object": shared_obj,
            "raw": stripped
        })

    return frames


def extract_last_running_input(gdb_output: str) -> str:
    last_running_input = ""
    for line in gdb_output.splitlines():
        if line.startswith("Running: "):
            last_running_input = line.split("Running: ", 1)[1].strip()
    return last_running_input


def format_gdb_call_chain(frames: List[dict]) -> str:
    if not frames:
        return "Empty runtime call chain."

    lines = ["Runtime call chain from GDB (Top frame -> Root):"]
    for frame in frames:
        if "symbol" not in frame:
            lines.append(f"  {frame['raw']}")
            continue

        location = ""
        if frame.get("file") and frame.get("line") is not None:
            location = f" at {frame['file']}:{frame['line']}"
        elif frame.get("shared_object"):
            location = f" from {frame['shared_object']}"

        lines.append(f"  #{frame['frame']} {frame['symbol']}{location}")

    return "\n".join(lines)


def run_gdb(fuzzer_bin: str,
            run_target: str,
            breakpoint: str,
            runs_arg: str,
            artifact_prefix: str = DEFAULT_ARTIFACT_PREFIX) -> dict:
    os.makedirs(artifact_prefix, exist_ok=True)
    cmd = [
        "gdb", "-batch",
        "-ex", "set pagination off",
        "-ex", "set print frame-arguments all",
        "-ex", f"break {breakpoint}",
        "-ex", f"run {runs_arg} -artifact_prefix={artifact_prefix} {run_target}",
        "-ex", "echo \\n\\n================ ACTUAL CALL CHAIN ================\\n\\n",
        "-ex", "bt 64",
        "--args", fuzzer_bin
    ]

    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )
    output = completed.stdout + completed.stderr

    return {
        "command": cmd,
        "returncode": completed.returncode,
        "output": output,
        "breakpoint_hit": "Breakpoint " in output and "#0 " in output,
        "frames": parse_gdb_backtrace(output),
        "triggering_input": extract_last_running_input(output)
    }


def find_runtime_call_chain_with_gdb(target_name: str,
                                     breakpoint: str,
                                     out_dir: str = DEFAULT_OUT_DIR,
                                     corpus_root: str = DEFAULT_CORPUS_ROOT,
                                     max_inputs: int = 50) -> dict:
    paths = resolve_fuzzer_paths(target_name, out_dir=out_dir, corpus_root=corpus_root)
    if not paths["fuzzer_exists"]:
        return {"error": f"Fuzzer binary not found: {paths['fuzzer_bin']}"}
    if not paths["corpus_exists"]:
        return {"error": f"Corpus directory not found: {paths['corpus_dir']}"}

    corpus_inputs = list_corpus_inputs(paths["corpus_dir"], limit=max_inputs)
    if not corpus_inputs:
        return {"error": f"No corpus inputs found under: {paths['corpus_dir']}"}

    for input_path in corpus_inputs:
        gdb_result = run_gdb(
            paths["fuzzer_bin"],
            input_path,
            breakpoint,
            "-runs=1 -rss_limit_mb=0 -timeout=0"
        )
        if gdb_result["breakpoint_hit"]:
            return {
                "target": target_name,
                "breakpoint": breakpoint,
                "triggering_input": gdb_result["triggering_input"] or input_path,
                "runtime_chain_structure": format_gdb_call_chain(gdb_result["frames"]),
                "gdb_frames": gdb_result["frames"],
                "raw_gdb_output": gdb_result["output"]
            }

    return {
        "error": f"GDB did not hit breakpoint '{breakpoint}' in the first {len(corpus_inputs)} corpus inputs.",
        "target": target_name,
        "breakpoint": breakpoint,
        "checked_inputs": len(corpus_inputs)
    }


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
        demangled_name = node.dst_function_name
        if INTROSPECTOR_AVAILABLE and utils is not None:
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


def extract_function_via_api(introspector: Introspector, project_name: str, file_path: str, start_line: int) -> str:
    """Fallback method: 透過 Introspector API 取得完整檔案後，暴力取出函數原始碼"""
    try:
        source_code = introspector.get_project_source_code(project_name, file_path, 1, 999999)
        if not source_code:
            return f"// [Fallback Failed] File not found via Introspector API: {file_path}"
            
        lines = source_code.splitlines()

        if start_line > len(lines) or start_line <= 0:
            return "// [Fallback Failed] Invalid line number"

        first_brace_line = -1
        for i in range(start_line - 1, len(lines)):
            if '{' in lines[i]:
                first_brace_line = i
                break
        
        if first_brace_line == -1:
            return "// [Fallback Failed] Could not find function start '{'"

        func_lines = []
        for i in range(max(0, first_brace_line - 5), first_brace_line):
           func_lines.append(lines[i].rstrip())
           
        brace_count = 0
        for i in range(first_brace_line, len(lines)):
            line = lines[i]
            func_lines.append(line.rstrip())
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            if brace_count == 0:
                break
                
        return "\n".join(func_lines)
    except Exception as e:
        return f"// [Fallback Failed] Exception: {str(e)}"


def get_runtime_function_source_codes(
    runtime_functions: List[dict],
    introspector: Introspector,
    project_name: str,
) -> str:
    if not runtime_functions:
        return ""

    collected_sources = []
    for frame in runtime_functions:
        symbol = frame.get("symbol", "")
        if not symbol:
            continue

        raw_name = get_mangled_function_name(introspector, project_name, symbol)
        if not raw_name:
            short_name = get_short_function_name(symbol)
            for func in introspector.get_all_functions(project_name):
                if get_short_function_name(func.get("function_name", "")) == short_name:
                    raw_name = func.get("raw_function_name", "")
                    break
                    
        # 1. 嘗試使用 Introspector / CFG (Primary)
        source_code = ""
        if raw_name:
            source_code = get_node_source_code(introspector, project_name, raw_name)
            
        location = ""
        if frame.get("file") and frame.get("line") is not None:
            location = f"{frame['file']}:{frame['line']}"
        elif frame.get("file"):
            location = frame["file"]
        else:
            location = "unknown location"

        # 2. 若 CFG 失敗，啟動 Fallback 透過 API 讀檔機制
        if not source_code and frame.get("file") and frame.get("line"):
            source_code = extract_function_via_api(introspector, project_name, frame["file"], frame["line"])
            if not source_code.startswith("// [Fallback Failed]"):
                source_code = "// [Source retrieved via API fallback]\n" + source_code

        # 3. 還是找不到就塞個提示給 LLM
        if not source_code:
            source_code = "// [Warning] Could not retrieve source code for this function."

        collected_sources.append(
            f"// Function: {symbol}\n"
            f"// Runtime location: {location}\n"
            f"{source_code}"
        )

    return "\n\n".join(collected_sources)


def extract_blocker_callchain_info(blocker: dict,
                                   yaml_file: str,
                                   project_name: str,
                                   use_gdb: bool = True,
                                   max_gdb_inputs: int = 50) -> dict:
    if not INTROSPECTOR_AVAILABLE:
        return {
            "target": blocker.get('best_target'),
            "breakpoint": blocker['function_name'],
            "cfg_error": f"Introspector dependencies unavailable: {INTROSPECTOR_IMPORT_ERROR}"
        }

    # 提前宣告
    introspector = Introspector()

    target = blocker.get('best_target')
    cfg_file_path = get_data_file_for_target(yaml_file, target)
    breakpoint = blocker['function_name']
    result = {
        "target": target,
        "breakpoint": breakpoint
    }

    if use_gdb:
        gdb_result = find_runtime_call_chain_with_gdb(
            target,
            breakpoint,
            max_inputs=max_gdb_inputs
        )
        if "gdb_frames" in gdb_result:
            # 這裡我們呼叫剛剛加回去的函數來拿 Source Code
            runtime_segment_sources = get_runtime_function_source_codes(
                gdb_result["gdb_frames"],
                introspector,
                project_name
            )
            gdb_result["runtime_segment_source_codes"] = runtime_segment_sources
        result["gdb_result"] = gdb_result


    if not cfg_file_path or not os.path.exists(cfg_file_path):
        result["cfg_error"] = f"Data file not found for target {target}: {cfg_file_path}"
        return result
    
    with open(cfg_file_path, "r", encoding="utf-8", errors="ignore") as f:
        cfg_content = f.read()

    root_node = cfg_load.data_file_read_calltree(cfg_content)
    if not root_node:
        result["cfg_error"] = "Failed to parse calltree root."
        return result

    all_nodes = cfg_load.extract_all_callsites(root_node)

    raw_blocker_name = get_mangled_function_name(introspector, project_name, blocker['function_name']) 
    branch_line_number = int(blocker['branch_line_number'])

    target_node = find_closest_callsite_to_blocker(all_nodes, raw_blocker_name, branch_line_number)
    
    if not target_node:
        result["cfg_error"] = f"CFG search failed for '{raw_blocker_name}'."
        return result

    call_chain = build_call_chain(target_node)

    result["cfg_result"] = {
        "chain_structure": get_call_chain_structure(call_chain),
        "unique_source_codes": get_unique_source_codes(call_chain, introspector, project_name)
    }
    return result


def main():
    json_path = "./process_blocker/branch-blockers.json"
    project_name = "tinyxml2"
    yaml_file = "/home/kyliechien/LLM-FuzzGen/external/oss-fuzz/build/out/tinyxml2/inspector/exe_to_fuzz_introspector_logs.yaml"

    global_blockers = aggregate_and_score_blockers(json_path, top_k=12)
    # global_blockers = {
    #     	"blocked_side": "0",
	# 		"blocked_unique_not_covered_complexity": 20,
	# 		"blocked_unique_reachable_complexity": 20,
	# 		"blocked_unique_functions": [
	# 			"tinyxml2::StrPair::CollapseWhitespace()"
	# 		],
	# 		"blocked_not_covered_complexity": 20,
	# 		"blocked_reachable_complexity": 20,
	# 		"sides_hitcount_diff": 280,
	# 		"source_file": "/src/tinyxml2/tinyxml2.cpp",
	# 		"branch_line_number": "372",
	# 		"blocked_side_line_numder": "373",
	# 		"function_name": "tinyxml2::StrPair::GetStr()"
    # }
    if not global_blockers:
        print("[Error] No global blockers found or file missing.")
        return
        
    for blocker in global_blockers[:1]:  # 若之後想處理多個，改這裡即可 (例如 global_blockers[:3])
        print(f"\n[Info] Processing Blocker in function: {blocker['function_name']}")
        
        result = extract_blocker_callchain_info(blocker, yaml_file, project_name)

        print(f"\n=== Target: {result['target']} ===")
        print(f"=== Breakpoint: {result['breakpoint']} ===")

        gdb_result = result.get("gdb_result", {})
        if gdb_result:
            if "error" in gdb_result:
                print(f"[Warn] {gdb_result['error']}")
            else:
                print("\n=== Information 1: Runtime Call Chain From GDB ===")
                print(gdb_result["runtime_chain_structure"])
                
                # ---> 重點：把我們剛剛辛苦拿到的 Runtime Source Code 印出來！<---
                print("\n=== Information 1.5: Runtime Source Codes (API/Fallback) ===")
                print(gdb_result.get("runtime_segment_source_codes", "No runtime source codes captured."))
                
                print(f"\n=== Triggering Input ===\n{gdb_result['triggering_input']}")

        cfg_result = result.get("cfg_result")
        if not cfg_result:
            print(f"[Warn] {result.get('cfg_error', 'CFG result unavailable.')}")
            # ---> 重點：把這裡的 continue 拿掉，不要因為 CFG 失敗就結束，還是可以看 GDB 結果 <---
        else:
            print("\n=== Information 2: CFG Call Chain Structure ===")
            print(cfg_result["chain_structure"])
            print("\n=== Information 3: CFG Unique Source Codes ===")
            print(cfg_result["unique_source_codes"])

if __name__ == "__main__":
    main()
