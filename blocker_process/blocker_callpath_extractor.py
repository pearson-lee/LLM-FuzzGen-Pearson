import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, List, Optional

import yaml

from global_blocker_selector import aggregate_and_score_blockers

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "external", "fuzz-introspector", "src"))

try:
    from external.introspector import Introspector
    from fuzz_introspector import cfg_load, utils

    INTROSPECTOR_AVAILABLE = True
    INTROSPECTOR_IMPORT_ERROR = ""
except Exception as exc:
    Introspector = Any  # type: ignore
    cfg_load = None  # type: ignore
    utils = None  # type: ignore
    INTROSPECTOR_AVAILABLE = False
    INTROSPECTOR_IMPORT_ERROR = str(exc)

try:
    from blocker_classifier_tool.blocker_classifier import classify_blocker

    CLASSIFIER_AVAILABLE = True
    CLASSIFIER_IMPORT_ERROR = ""
except Exception as first_exc:
    try:
        from blocker_process.blocker_classifier import classify_blocker

        CLASSIFIER_AVAILABLE = True
        CLASSIFIER_IMPORT_ERROR = ""
    except Exception:
        try:
            from blocker_classifier import classify_blocker

            CLASSIFIER_AVAILABLE = True
            CLASSIFIER_IMPORT_ERROR = ""
        except Exception as final_exc:
            classify_blocker = None  # type: ignore
            CLASSIFIER_AVAILABLE = False
            CLASSIFIER_IMPORT_ERROR = f"{first_exc}; fallback failed: {final_exc}"

if TYPE_CHECKING:
    from external.introspector import Introspector as IntrospectorType
else:
    IntrospectorType = Any


PROJECT_NAME = "tinyxml2"
DEFAULT_OUT_DIR = os.path.join(PROJECT_ROOT, "external", "oss-fuzz", "build", "out", PROJECT_NAME)
DEFAULT_CORPUS_ROOT = os.path.join(PROJECT_ROOT, "external", "oss-fuzz", "build", "corpus", PROJECT_NAME)
DEFAULT_ARTIFACT_PREFIX = "/tmp/llm-fuzzgen-gdb-artifacts/"


def get_project_out_dir(project_name: str) -> str:
    return os.path.join(PROJECT_ROOT, "external", "oss-fuzz", "build", "out", project_name)


def get_project_corpus_root(project_name: str) -> str:
    return os.path.join(PROJECT_ROOT, "external", "oss-fuzz", "build", "corpus", project_name)


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
            if os.path.basename(executable_path) != target_name:
                continue

            log_file = pair.get("fuzzer_log_file")
            file_name = f"{log_file}.data" if not log_file.endswith(".data") else log_file
            return os.path.join(os.path.dirname(yaml_path), file_name)
    except Exception as exc:
        print(f"[Error] Failed to parse YAML {yaml_path}: {exc}")

    return None


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
    return normalized.split("(", 1)[0].split("::")[-1].strip()


def symbols_match(lhs: str, rhs: str) -> bool:
    left = normalize_gdb_symbol(lhs)
    right = normalize_gdb_symbol(rhs)
    if not left or not right:
        return False
    return left == right or get_short_function_name(left) == get_short_function_name(right)


def get_mangled_function_name(introspector: IntrospectorType, project_name: str, func_name: str) -> str:
    query_name_normalized = func_name.replace(" ", "")
    for func in introspector.get_all_functions(project_name):
        target_name_normalized = func.get("function_name", "").replace(" ", "")
        if target_name_normalized == query_name_normalized:
            return func.get("raw_function_name", "")

    if func_name != "LLVMFuzzerTestOneInput":
        print(f"[Warning] Could not find mangled name for '{func_name}' in project '{project_name}'")
    return ""


def resolve_fuzzer_paths(
    target_name: str,
    out_dir: str = DEFAULT_OUT_DIR,
    corpus_root: str = DEFAULT_CORPUS_ROOT,
) -> dict:
    return {
        "fuzzer_bin": os.path.join(out_dir, target_name),
        "corpus_dir": os.path.join(corpus_root, target_name),
        "fuzzer_exists": os.path.isfile(os.path.join(out_dir, target_name)),
        "corpus_exists": os.path.isdir(os.path.join(corpus_root, target_name)),
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

        match = re.match(
            r"^#(\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(.+?)(?:\s+at\s+(.+?):(\d+)|\s+from\s+(.+))?$",
            stripped,
        )
        if not match:
            frames.append({"raw": stripped})
            continue

        frame_no, symbol, src_file, src_line, shared_obj = match.groups()
        frames.append(
            {
                "frame": int(frame_no),
                "symbol": symbol,
                "file": src_file,
                "line": int(src_line) if src_line else None,
                "shared_object": shared_obj,
                "raw": stripped,
            }
        )

    return frames


def extract_last_running_input(gdb_output: str) -> str:
    last_running_input = ""
    for line in gdb_output.splitlines():
        if line.startswith("Running: "):
            last_running_input = line.split("Running: ", 1)[1].strip()
    return last_running_input


def extract_unique_runtime_functions(frames: List[dict]) -> List[dict]:
    unique_frames = []
    seen_symbols = set()

    for frame in frames:
        symbol = normalize_gdb_symbol(frame.get("symbol", ""))
        if not symbol or symbol in seen_symbols:
            continue

        seen_symbols.add(symbol)
        unique_frames.append(
            {
                "symbol": symbol,
                "file": frame.get("file"),
                "line": frame.get("line"),
                "shared_object": frame.get("shared_object"),
            }
        )

    return unique_frames


def extract_runtime_segment_between_functions(
    frames: List[dict],
    entry_function: str,
    target_function: str,
) -> List[dict]:
    unique_frames = extract_unique_runtime_functions(frames)
    reversed_frames = list(reversed(unique_frames))
    start_idx = None
    end_idx = None

    for idx, frame in enumerate(reversed_frames):
        symbol = frame.get("symbol", "")
        if start_idx is None and symbols_match(symbol, entry_function):
            start_idx = idx
        if symbols_match(symbol, target_function):
            end_idx = idx
            if start_idx is not None:
                break

    if start_idx is None or end_idx is None or start_idx > end_idx:
        return []

    return reversed_frames[start_idx : end_idx + 1]


def format_runtime_segment(segment_frames: List[dict], entry_function: str, target_function: str) -> str:
    if not segment_frames:
        return f"Could not isolate the runtime segment between {entry_function} and {target_function}."

    lines = ["Runtime functions from entry to blocker (Root -> Target, deduplicated):"]
    for idx, frame in enumerate(segment_frames):
        location = ""
        if frame.get("file") and frame.get("line") is not None:
            location = f" at {frame['file']}:{frame['line']}"
        elif frame.get("shared_object"):
            location = f" from {frame['shared_object']}"
        lines.append(f"  #{idx} {frame['symbol']}{location}")

    return "\n".join(lines)


def run_gdb(
    fuzzer_bin: str,
    run_target: str,
    breakpoint: str,
    runs_arg: str,
    artifact_prefix: str = DEFAULT_ARTIFACT_PREFIX,
) -> dict:
    os.makedirs(artifact_prefix, exist_ok=True)
    cmd = [
        "gdb",
        "-batch",
        "-ex",
        "set pagination off",
        "-ex",
        "set print frame-arguments all",
        "-ex",
        f"break {breakpoint}",
        "-ex",
        f"run {runs_arg} -artifact_prefix={artifact_prefix} {run_target}",
        "-ex",
        "echo \\n\\n================ ACTUAL CALL CHAIN ================\\n\\n",
        "-ex",
        "bt 64",
        "--args",
        fuzzer_bin,
    ]

    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    output = completed.stdout + completed.stderr

    return {
        "command": cmd,
        "returncode": completed.returncode,
        "output": output,
        "breakpoint_hit": "Breakpoint " in output and "#0 " in output,
        "gdb_frames": parse_gdb_backtrace(output),
        "triggering_input": extract_last_running_input(output),
    }


def find_runtime_call_chain_with_gdb(
    target_name: str,
    breakpoint: str,
    out_dir: str = DEFAULT_OUT_DIR,
    corpus_root: str = DEFAULT_CORPUS_ROOT,
    max_inputs: int = 50,
) -> dict:
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
            "-runs=0 -rss_limit_mb=0 -timeout=0",
        )
        if gdb_result["breakpoint_hit"]:
            return {
                "target": target_name,
                "breakpoint": breakpoint,
                "triggering_input": gdb_result["triggering_input"] or input_path,
                "gdb_frames": gdb_result["gdb_frames"],
                "raw_gdb_output": gdb_result["output"],
            }

    return {
        "error": f"GDB did not hit breakpoint '{breakpoint}' in the first {len(corpus_inputs)} corpus inputs.",
        "target": target_name,
        "breakpoint": breakpoint,
        "checked_inputs": len(corpus_inputs),
    }


def find_closest_callsite_to_blocker(all_nodes: List[Any], target_raw_name: str, branch_line_number: int) -> Optional[Any]:
    if not target_raw_name:
        return None

    for idx, node in enumerate(all_nodes):
        if node.dst_function_name != target_raw_name:
            continue

        target_inner_depth = node.depth + 1
        closest_node = node

        for next_node in all_nodes[idx + 1 :]:
            if target_inner_depth > next_node.depth:
                break
            if target_inner_depth == next_node.depth and branch_line_number >= next_node.src_linenumber:
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


def get_node_source_code(introspector: IntrospectorType, project_name: str, raw_name: str) -> str:
    if not raw_name:
        return ""

    target_signature = ""
    for func in introspector.get_all_functions(project_name):
        if func.get("raw_function_name", "") == raw_name:
            target_signature = func.get("function_signature", "")
            break

    if target_signature:
        return introspector.function_source_code(project_name, target_signature)
    return ""


def extract_function_via_api(introspector: IntrospectorType, project_name: str, file_path: str, start_line: int) -> str:
    """Fallback: fetch the full file through the Introspector API and slice out the function body."""
    try:
        source_code = introspector.get_project_source_code(project_name, file_path, 1, 999999)
        if not source_code:
            return f"// [Fallback Failed] File not found via Introspector API: {file_path}"

        lines = source_code.splitlines()
        if start_line > len(lines) or start_line <= 0:
            return "// [Fallback Failed] Invalid line number"

        first_brace_line = -1
        for i in range(start_line - 1, len(lines)):
            if "{" in lines[i]:
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
            brace_count += line.count("{")
            brace_count -= line.count("}")
            if brace_count == 0:
                break

        return "\n".join(func_lines)
    except Exception as exc:
        return f"// [Fallback Failed] Exception: {str(exc)}"


def get_runtime_function_source_codes(
    runtime_functions: List[dict],
    introspector: IntrospectorType,
    project_name: str,
) -> str:
    if not runtime_functions:
        return ""

    collected_sources = []
    all_functions = introspector.get_all_functions(project_name)

    for frame in runtime_functions:
        symbol = frame.get("symbol", "")
        if not symbol:
            continue
        if symbol == "LLVMFuzzerTestOneInput":
            continue

        raw_name = get_mangled_function_name(introspector, project_name, symbol)
        if not raw_name:
            short_name = get_short_function_name(symbol)
            for func in all_functions:
                if get_short_function_name(func.get("function_name", "")) == short_name:
                    raw_name = func.get("raw_function_name", "")
                    break

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

        if not source_code and frame.get("file") and frame.get("line"):
            source_code = extract_function_via_api(introspector, project_name, frame["file"], frame["line"])
            if not source_code.startswith("// [Fallback Failed]"):
                source_code = "// [Source retrieved via API fallback]\n" + source_code

        if not source_code:
            source_code = "// [Warning] Could not retrieve source code for this function."

        collected_sources.append(
            f"// Function: {symbol}\n"
            f"// Runtime location: {location}\n"
            f"{source_code}"
        )

    return "\n\n".join(collected_sources)


def get_unique_source_codes(chain: List[Any], introspector: IntrospectorType, project_name: str) -> str:
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


def extract_blocker_callchain_info(
    blocker: dict,
    yaml_file: str,
    project_name: str,
    use_gdb: bool = True,
    max_gdb_inputs: int = 50,
) -> dict:
    if not INTROSPECTOR_AVAILABLE:
        return {
            "target": blocker.get("best_target"),
            "breakpoint": blocker["function_name"],
            "cfg_error": f"Introspector dependencies unavailable: {INTROSPECTOR_IMPORT_ERROR}",
        }

    introspector = Introspector()
    target = blocker.get("best_target")
    cfg_file_path = get_data_file_for_target(yaml_file, target)
    breakpoint = blocker["function_name"]
    result = {"target": target, "breakpoint": breakpoint}
    project_out_dir = get_project_out_dir(project_name)
    project_corpus_root = get_project_corpus_root(project_name)

    if use_gdb:
        gdb_result = find_runtime_call_chain_with_gdb(
            target,
            breakpoint,
            out_dir=project_out_dir,
            corpus_root=project_corpus_root,
            max_inputs=max_gdb_inputs,
        )
        if "gdb_frames" in gdb_result:
            runtime_segment = extract_runtime_segment_between_functions(
                gdb_result["gdb_frames"],
                "LLVMFuzzerTestOneInput",
                blocker["function_name"],
            )
            gdb_result["runtime_blocker_segment"] = runtime_segment
            gdb_result["runtime_blocker_segment_structure"] = format_runtime_segment(
                runtime_segment,
                "LLVMFuzzerTestOneInput",
                blocker["function_name"],
            )
            gdb_result["runtime_segment_source_codes"] = get_runtime_function_source_codes(
                runtime_segment,
                introspector,
                project_name,
            )
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
    raw_blocker_name = get_mangled_function_name(introspector, project_name, blocker["function_name"])
    branch_line_number = int(blocker["branch_line_number"])
    target_node = find_closest_callsite_to_blocker(all_nodes, raw_blocker_name, branch_line_number)

    if not target_node:
        result["cfg_error"] = f"CFG search failed for '{raw_blocker_name}'."
        return result

    call_chain = build_call_chain(target_node)
    result["cfg_result"] = {
        "chain_structure": get_call_chain_structure(call_chain),
        "unique_source_codes": get_unique_source_codes(call_chain, introspector, project_name),
    }
    return result


def to_prompt_source_path(source_file: str, project_name: str) -> str:
    normalized = source_file.replace("\\", "/")
    if normalized.startswith("/src/"):
        return str(Path(get_project_out_dir(project_name)) / normalized.lstrip("/"))
    return source_file


def format_runtime_collection_status(gdb_result: dict) -> tuple[str, str]:
    if not gdb_result:
        return "not_requested", ""
    if "error" in gdb_result:
        return "failed", gdb_result["error"]
    return "success", ""


def format_cfg_collection_status(cfg_result: dict, cfg_error: str) -> tuple[str, str]:
    if cfg_result:
        return "success", ""
    if cfg_error:
        return "failed", cfg_error
    return "not_requested", ""


def build_classifier_args_from_result(
    blocker: dict,
    extraction_result: dict,
    project_name: str,
    fuzz_file: str,
    header_file: Optional[str],
    backend: str,
    model: Optional[str],
) -> SimpleNamespace:
    gdb_result = extraction_result.get("gdb_result", {})
    cfg_result = extraction_result.get("cfg_result", {})
    runtime_status, runtime_error = format_runtime_collection_status(gdb_result)
    cfg_status, cfg_error = format_cfg_collection_status(cfg_result, extraction_result.get("cfg_error", ""))

    return SimpleNamespace(
        backend=backend,
        model=model,
        project_name=project_name,
        function_name=blocker["function_name"],
        branch_line_number=str(blocker["branch_line_number"]),
        blocked_side_line_number=str(blocker["blocked_side_line_numder"]),
        source_file=to_prompt_source_path(blocker["source_file"], project_name),
        fuzz_file=fuzz_file,
        header_file=header_file,
        runtime_blocker_segment=gdb_result.get("runtime_blocker_segment_structure", "N/A"),
        runtime_blocker_segment_source_codes=gdb_result.get("runtime_segment_source_codes", "N/A"),
        cfg_call_chain=cfg_result.get("chain_structure", "N/A"),
        cfg_source_codes=cfg_result.get("unique_source_codes", "N/A"),
        runtime_collection_status=runtime_status,
        runtime_collection_error=runtime_error,
        cfg_collection_status=cfg_status,
        cfg_collection_error=cfg_error,
        triggering_input=gdb_result.get("triggering_input", ""),
        source_code=None,
        fuzz_target_code=None,
        header_code=None,
    )


def classify_from_extraction_result(
    blocker: dict,
    extraction_result: dict,
    project_name: str,
    fuzz_file: str,
    header_file: Optional[str],
    backend: str,
    model: Optional[str],
    execute_pipeline: bool,
) -> dict:
    if classify_blocker is None:
        raise RuntimeError(f"Classifier import unavailable: {CLASSIFIER_IMPORT_ERROR}")

    classifier_args = build_classifier_args_from_result(
        blocker=blocker,
        extraction_result=extraction_result,
        project_name=project_name,
        fuzz_file=fuzz_file,
        header_file=header_file,
        backend=backend,
        model=model,
    )
    return classify_blocker(classifier_args, execute_pipeline=execute_pipeline)


def main():
    parser = argparse.ArgumentParser(description="Extract blocker runtime/static context and optionally classify it.")
    parser.add_argument("--json-path", default="./process_blocker/branch-blockers.json")
    parser.add_argument("--project-name", default="tinyxml2")
    parser.add_argument("--yaml-file", default=None)
    parser.add_argument("--top-k", type=int, default=12)
    parser.add_argument("--index", type=int, default=0, help="Which ranked blocker to process")
    parser.add_argument("--max-gdb-inputs", type=int, default=50)
    parser.add_argument("--classify", action="store_true", help="Run blocker classification after extraction")
    parser.add_argument("--backend", default="gemini", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--fuzz-file", default=None, help="Override fuzz target source file path")
    parser.add_argument("--header-file", default=None, help="Optional related header file path")
    parser.add_argument(
        "--execute-pipeline",
        action="store_true",
        help="If set with --classify, continue into the downstream dependent/independent pipeline.",
    )
    parser.add_argument("--manual-function", default=None, help="Manually set function name to bypass JSON")
    parser.add_argument("--manual-branch-line", type=int, default=None)
    parser.add_argument("--manual-blocked-side-line", type=int, default=None)
    parser.add_argument("--manual-source-file", default=None)
    parser.add_argument("--manual-target", default=None, help="The fuzzer binary name (e.g. llm_fuzzgen0916173855)")
    
    args = parser.parse_args()

    if not args.yaml_file:
        args.yaml_file = os.path.join(
            get_project_out_dir(args.project_name),
            "inspector",
            "exe_to_fuzz_introspector_logs.yaml",
        )

    if args.manual_function:
        blocker = {
            "function_name": args.manual_function,
            "branch_line_number": args.manual_branch_line,
            "blocked_side_line_numder": args.manual_blocked_side_line, # 注意這裡沿用舊的 key 拼字以防其他地方報錯
            "source_file": args.manual_source_file,
            "best_target": args.manual_target
        }
        print(f"\n[Info] Processing Manual Blocker in function: {blocker['function_name']}")
    else:
        # --- 原本透過 JSON 和 Selector 抓取的邏輯 ---
        global_blockers = aggregate_and_score_blockers(args.json_path, top_k=args.top_k)
        if not global_blockers:
            print("[Error] No global blockers found or file missing.")
            return

        if args.index < 0 or args.index >= len(global_blockers):
            print(f"[Error] Blocker index {args.index} is out of range.")
            return

        blocker = global_blockers[args.index]
        print(f"\n[Info] Processing Blocker in function: {blocker['function_name']}")
    result = extract_blocker_callchain_info(
        blocker,
        args.yaml_file,
        args.project_name,
        max_gdb_inputs=args.max_gdb_inputs,
    )

    print(f"\n=== Target: {result['target']} ===")
    print(f"=== Breakpoint: {result['breakpoint']} ===")

    gdb_result = result.get("gdb_result", {})
    if gdb_result:
        if "error" in gdb_result:
            print(f"[Warn] {gdb_result['error']}")
        else:
            print("\n=== Information 1: Runtime Blocker Segment ===")
            print(gdb_result.get("runtime_blocker_segment_structure", "Unavailable"))
            print("\n=== Information 2: Runtime Blocker Segment Source Codes ===")
            print(gdb_result.get("runtime_segment_source_codes", "No runtime source codes captured."))
            print(f"\n=== Triggering Input ===\n{gdb_result['triggering_input']}")

    cfg_result = result.get("cfg_result")
    if not cfg_result:
        print(f"[Warn] {result.get('cfg_error', 'CFG result unavailable.')}")
    else:
        print("\n=== Information 3: CFG Call Chain Structure ===")
        print(cfg_result["chain_structure"])
        print("\n=== Information 4: CFG Unique Source Codes ===")
        print(cfg_result["unique_source_codes"])

    if not args.classify:
        return

    fuzz_file = args.fuzz_file or str(
        Path(PROJECT_ROOT) / "external" / "oss-fuzz" / "projects" / args.project_name / f"{result['target']}.cc"
    )
    try:
        classification_result = classify_from_extraction_result(
            blocker=blocker,
            extraction_result=result,
            project_name=args.project_name,
            fuzz_file=fuzz_file,
            header_file=args.header_file,
            backend=args.backend,
            model=args.model,
            execute_pipeline=args.execute_pipeline,
        )
    except Exception as exc:
        print(f"[Error] Classification failed: {exc}")
        return

    print("\n=== Classification Result ===")
    print(classification_result.get("dependency_result", "Unknown"))
    reason = classification_result.get("reason", "")
    if reason:
        print(f"Reason: {reason}")


if __name__ == "__main__":
    main()
