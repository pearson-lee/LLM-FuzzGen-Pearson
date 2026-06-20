import argparse
from functools import lru_cache
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, List, Optional

import yaml

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "external", "fuzz-introspector", "src"))

try:
    from blocker_process.global_blocker_selector import aggregate_and_score_blockers
except Exception:
    from global_blocker_selector import aggregate_and_score_blockers
try:
    from blocker_process.find_blocker_seeds_by_coverage import find_matching_seeds
except Exception:
    from find_blocker_seeds_by_coverage import find_matching_seeds

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
    profile_output = os.path.join(artifact_prefix, "gdb_run.profraw")
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
        "info breakpoints",
        "-ex",
        f"run {runs_arg} -artifact_prefix={artifact_prefix} {run_target}",
        "-ex",
        "echo \\n\\n================ ACTUAL CALL CHAIN ================\\n\\n",
        "-ex",
        "bt 64",
        "--args",
        fuzzer_bin,
    ]
    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = profile_output

    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    try:
        os.remove(profile_output)
    except FileNotFoundError:
        pass
    output = completed.stdout + completed.stderr
    lines = output.splitlines()
    breakpoint_info_lines = [
        line for line in lines if line.strip().startswith("Breakpoint ") or line.strip().startswith("Num ")
    ]
    breakpoint_set = any("Breakpoint " in line for line in lines)
    breakpoint_resolved = any(" in " in line and "Breakpoint " in line for line in lines)
    breakpoint_warning_lines = [
        line for line in lines if "Function" in line or "Make breakpoint pending" in line or "not defined" in line
    ]

    return {
        "command": cmd,
        "returncode": completed.returncode,
        "output": output,
        "breakpoint_set": breakpoint_set,
        "breakpoint_resolved": breakpoint_resolved,
        "breakpoint_info": "\n".join(breakpoint_info_lines).strip(),
        "breakpoint_warnings": "\n".join(breakpoint_warning_lines).strip(),
        "breakpoint_hit": "Breakpoint " in output and "#0 " in output,
        "gdb_frames": parse_gdb_backtrace(output),
        "triggering_input": extract_last_running_input(output),
    }


def find_runtime_call_chain_with_gdb(
    target_name: str,
    breakpoint: str,
    seed_path: str,
    out_dir: str = DEFAULT_OUT_DIR,
    fallback_breakpoint: str | None = None,
) -> dict:
    paths = resolve_fuzzer_paths(target_name, out_dir=out_dir, corpus_root=DEFAULT_CORPUS_ROOT)
    if not paths["fuzzer_exists"]:
        return {"error": f"Fuzzer binary not found: {paths['fuzzer_bin']}"}
    input_path = str(Path(seed_path).resolve())
    attempted_breakpoints = [breakpoint]
    if fallback_breakpoint and fallback_breakpoint != breakpoint:
        attempted_breakpoints.append(fallback_breakpoint)

    last_result: dict | None = None
    for breakpoint_spec in attempted_breakpoints:
        gdb_result = run_gdb(
            paths["fuzzer_bin"],
            input_path,
            breakpoint_spec,
            "-runs=0 -rss_limit_mb=0 -timeout=0",
        )
        last_result = gdb_result
        if gdb_result["breakpoint_hit"]:
            return {
                "target": target_name,
                "breakpoint": breakpoint_spec,
                "triggering_input": gdb_result["triggering_input"] or input_path,
                "gdb_frames": gdb_result["gdb_frames"],
                "raw_gdb_output": gdb_result["output"],
                "seed": input_path,
                "breakpoint_strategy": "line" if breakpoint_spec == breakpoint else "function",
                "breakpoint_info": gdb_result.get("breakpoint_info", ""),
                "breakpoint_warnings": gdb_result.get("breakpoint_warnings", ""),
            }
    return {
        "error": f"GDB did not hit breakpoints {attempted_breakpoints} with seed {input_path}.",
        "target": target_name,
        "breakpoint": breakpoint,
        "seed": input_path,
        "selected_seed": input_path,
        "attempted_breakpoints": attempted_breakpoints,
        "breakpoint_info": (last_result or {}).get("breakpoint_info", ""),
        "breakpoint_warnings": (last_result or {}).get("breakpoint_warnings", ""),
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


# ---------------------------------------------------------------------------
# Blocker call-site enumeration (generic C/C++)
#
# Surface ALL candidate direct call sites of the blocker function, each with a
# local source-context window, so the seed generator can pick a call site whose
# guard is COMPATIBLE with the required predicate value -- instead of relying on
# the single (possibly incompatible) call site captured by the calltree.
#
# The code only collects/labels evidence (provenance + local context); it does
# NOT judge guard compatibility (left to the LLM). Textual collection is
# best-effort and runs without Introspector/CFG; calltree only enriches it.
# ---------------------------------------------------------------------------

CALL_SITE_MAX_ENTRIES = 30
CALL_SITE_CTX_BEFORE = 10
CALL_SITE_CTX_AFTER = 2
CALL_SITE_MAX_FILES = 400
CALL_SITE_MAX_CONFIG_HEADERS = 100
_CALL_SITE_NOISE_DIRS = (
    "/test/", "/tests/", "/testprogs/", "/example/", "/examples/",
    "/docs/", "/doc/", "/.git/", "/third_party/", "/vendor/",
)
_C_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".hh", ".hxx")


def _macro_fact_source_roots(project_name: str, source_root: Optional[str] = None) -> List[str]:
    out = get_project_out_dir(project_name)
    roots = [os.path.join(out, "src"), os.path.join(out, "source_code")]
    if source_root:
        roots.insert(0, source_root)
    return roots


@lru_cache(maxsize=64)
def _load_build_macro_facts(project_name: str, source_root: Optional[str] = None) -> dict:
    """Collect conservative macro facts from generated build configuration headers.

    Absence is not treated as undefined because a compiler command line may still
    define the macro. Conflicting facts remain unknown.
    """
    observations: dict[str, List[dict]] = {}
    config_files: List[str] = []
    for root in _macro_fact_source_roots(project_name, source_root):
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {"usr", ".git", "third_party", "vendor"}]
            for name in names:
                lower = name.lower()
                if lower.endswith((".h", ".hpp")) and (
                    lower == "config.h"
                    or lower == "config.hpp"
                    or "autoconfig" in lower
                    or lower.endswith("_config.h")
                    or lower.endswith("-config.h")
                ):
                    config_files.append(os.path.join(dirpath, name))
                    if len(config_files) >= CALL_SITE_MAX_CONFIG_HEADERS:
                        break
            if len(config_files) >= CALL_SITE_MAX_CONFIG_HEADERS:
                break
        if len(config_files) >= CALL_SITE_MAX_CONFIG_HEADERS:
            break

    define_re = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)(?:\s+(.*?))?\s*$")
    undef_re = re.compile(r"^\s*#\s*undef\s+([A-Za-z_]\w*)\s*$")
    commented_undef_re = re.compile(r"^\s*/\*\s*#\s*undef\s+([A-Za-z_]\w*)\s*\*/\s*$")
    for path in sorted(set(config_files)):
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, 1):
            match = define_re.match(line)
            state = "defined"
            value = "1"
            if match:
                name = match.group(1)
                value = (match.group(2) or "1").strip()
            else:
                match = undef_re.match(line) or commented_undef_re.match(line)
                if not match:
                    continue
                name = match.group(1)
                state = "undefined"
                value = ""
            observations.setdefault(name, []).append(
                {
                    "state": state,
                    "value": value,
                    "file": os.path.relpath(path, get_project_out_dir(project_name)),
                    "line": line_number,
                    "text": line.strip(),
                }
            )

    facts = {}
    for name, evidence in observations.items():
        states = {item["state"] for item in evidence}
        facts[name] = {
            "state": next(iter(states)) if len(states) == 1 else "conflict",
            "evidence": evidence,
        }
    return facts


def _macro_defined_state(macro_facts: dict, name: str) -> Optional[bool]:
    state = (macro_facts.get(name) or {}).get("state")
    if state == "defined":
        return True
    if state == "undefined":
        return False
    return None


def _evaluate_simple_preprocessor_condition(directive: str, expression: str, macro_facts: dict) -> Optional[bool]:
    expression = expression.strip()
    if directive == "ifdef":
        return _macro_defined_state(macro_facts, expression)
    if directive == "ifndef":
        value = _macro_defined_state(macro_facts, expression)
        return None if value is None else not value
    if directive not in {"if", "elif"}:
        return None
    if expression in {"0", "1"}:
        return expression == "1"
    match = re.fullmatch(r"defined\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|\s+([A-Za-z_]\w*))", expression)
    if match:
        return _macro_defined_state(macro_facts, match.group(1) or match.group(2))
    match = re.fullmatch(r"!\s*defined\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|\s+([A-Za-z_]\w*))", expression)
    if match:
        value = _macro_defined_state(macro_facts, match.group(1) or match.group(2))
        return None if value is None else not value
    return None


def _combine_parent_condition(parent: Optional[bool], child: Optional[bool]) -> Optional[bool]:
    if parent is False or child is False:
        return False
    if parent is True and child is True:
        return True
    return None


def _preprocessor_context_by_line(lines: List[str], macro_facts: dict) -> List[dict]:
    """Return enclosing preprocessor conditions and their conservative state per line."""
    contexts: List[dict] = []
    stack: List[dict] = []
    directive_re = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")

    for line in lines:
        conditions = [frame["display"] for frame in stack]
        states = [frame["effective"] for frame in stack]
        if any(state is False for state in states):
            status = "inactive"
        elif states and all(state is True for state in states):
            status = "active"
        elif states:
            status = "unknown"
        else:
            status = "active"
        contexts.append({"conditions": conditions, "status": status, "frames": [dict(frame) for frame in stack]})

        match = directive_re.match(line)
        if not match:
            continue
        directive, expression = match.group(1), match.group(2).strip()
        if directive in {"if", "ifdef", "ifndef"}:
            parent = stack[-1]["effective"] if stack else True
            branch = _evaluate_simple_preprocessor_condition(directive, expression, macro_facts)
            stack.append(
                {
                    "display": f"#{directive} {expression}".rstrip(),
                    "parent": parent,
                    "branch_results": [branch],
                    "effective": _combine_parent_condition(parent, branch),
                }
            )
        elif directive == "elif" and stack:
            frame = stack[-1]
            previous = frame["branch_results"]
            branch = _evaluate_simple_preprocessor_condition(directive, expression, macro_facts)
            if any(value is True for value in previous):
                selected = False
            elif all(value is False for value in previous):
                selected = branch
            else:
                selected = False if branch is False else None
            frame["branch_results"].append(branch)
            frame["display"] = f"#elif {expression}"
            frame["effective"] = _combine_parent_condition(frame["parent"], selected)
        elif directive == "else" and stack:
            frame = stack[-1]
            previous = frame["branch_results"]
            if any(value is True for value in previous):
                selected = False
            elif all(value is False for value in previous):
                selected = True
            else:
                selected = None
            frame["display"] = "#else"
            frame["effective"] = _combine_parent_condition(frame["parent"], selected)
        elif directive == "endif" and stack:
            stack.pop()
    return contexts


def _macro_names_in_conditions(conditions: List[str]) -> List[str]:
    names = []
    keywords = {"if", "ifdef", "ifndef", "elif", "else", "defined"}
    for condition in conditions:
        for name in re.findall(r"\b[A-Za-z_]\w*\b", condition):
            if name not in keywords and not name.isdigit() and name not in names:
                names.append(name)
    return names


def _build_evidence_for_conditions(conditions: List[str], macro_facts: dict) -> List[dict]:
    evidence = []
    for name in _macro_names_in_conditions(conditions):
        fact = macro_facts.get(name)
        if not fact:
            continue
        for item in fact.get("evidence", []):
            evidence.append({"macro": name, **item})
    return evidence


def project_source_roots(project_name: str, source_root: Optional[str] = None) -> List[str]:
    out = get_project_out_dir(project_name)
    roots = [
        os.path.join(out, "source_code"),
        os.path.join(out, "src", project_name),
        os.path.join(out, "src"),
    ]
    if source_root:
        roots.insert(0, source_root)
    return roots


def _call_site_source_roots(project_name: str, source_root: Optional[str] = None) -> List[str]:
    return project_source_roots(project_name, source_root)


def resolve_project_source_file(
    project_name: str,
    source_file: Optional[str],
    source_root: Optional[str] = None,
) -> Optional[str]:
    """Best-effort resolve a (possibly /src/...) path to an on-disk mirror file."""
    if not source_file:
        return None
    if os.path.isfile(source_file):
        return source_file
    norm = str(source_file).replace("\\", "/")
    base = os.path.basename(norm)
    rel = norm.split("/src/", 1)[1] if "/src/" in norm else base
    roots = project_source_roots(project_name, source_root)
    for root in roots:
        project_relative = rel
        if project_name and rel.startswith(project_name + "/"):
            project_relative = rel[len(project_name) + 1 :]
        for cand in (
            os.path.join(root, rel),
            os.path.join(root, project_relative),
            os.path.join(root, base),
        ):
            if os.path.isfile(cand):
                return cand
    if source_root and os.path.isdir(source_root):
        for dirpath, _dirs, files in os.walk(source_root):
            if base in files:
                return os.path.join(dirpath, base)
    sc = os.path.join(get_project_out_dir(project_name), "source_code")
    if os.path.isdir(sc):
        for dirpath, _dirs, files in os.walk(sc):
            if base in files:
                return os.path.join(dirpath, base)
    return None


def _resolve_in_mirror(
    project_name: str,
    source_file: Optional[str],
    source_root: Optional[str] = None,
) -> Optional[str]:
    return resolve_project_source_file(project_name, source_file, source_root)


def display_project_source_path(path: str, project_name: str) -> str:
    norm = str(path).replace("\\", "/")
    marker = f"/out/{project_name}/source_code/"
    if marker in norm:
        return norm.split(marker, 1)[1]
    return os.path.basename(norm)


def _display_path(path: str, project_name: str) -> str:
    return display_project_source_path(path, project_name)


def _first_paren_content(s: str) -> Optional[str]:
    """Given a string starting at the '(' of a call, return the balanced inner text."""
    start = s.find("(")
    if start < 0:
        return None
    depth = 0
    for idx in range(start, len(s)):
        ch = s[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return s[start + 1 : idx]
    return s[start + 1 :]  # unbalanced (multi-line) -> best effort


def _looks_like_declaration(args_str: Optional[str]) -> bool:
    """True if the first argument looks like a TYPED parameter (definition/prototype),
    e.g. 'compiler_state_t *cstate', as opposed to a call argument like 'cstate'."""
    if args_str is None:
        return False
    first = args_str.split(",", 1)[0].strip()
    if not first or first == "void":
        return False
    # '<type> name' or '<type> *name' (two identifiers, or a '*' between identifiers).
    if re.match(
        r"^(?:const\s+|struct\s+|enum\s+|union\s+|unsigned\s+|signed\s+)*"
        r"[A-Za-z_]\w*\s+\*?\s*[A-Za-z_]\w*\s*$",
        first,
    ):
        return True
    if re.match(r"^[A-Za-z_][\w\s]*\*\s*[A-Za-z_]\w*$", first):
        return True
    return False


def _definition_is_static(lines: List[str], function_name: str) -> bool:
    pat = re.compile(r"\b" + re.escape(function_name) + r"\s*\(")
    for i, line in enumerate(lines):
        m = pat.search(line)
        if not m:
            continue
        args = _first_paren_content(line[m.end() - 1 :])
        if not _looks_like_declaration(args):
            continue
        if line.rstrip().endswith(";"):
            continue  # prototype, not the definition
        region = " ".join(lines[max(0, i - 2) : i + 1])
        return bool(re.search(r"\bstatic\b", region))
    return False


def _enclosing_function_name(lines: List[str], idx: int) -> Optional[str]:
    """Best-effort nearest preceding function header name above line idx."""
    for j in range(idx, max(-1, idx - 400), -1):
        ln = lines[j]
        m = re.match(r"^([A-Za-z_]\w*)\s*\(", ln)  # name( at column 0 (e.g. libpcap style)
        if m and not ln.rstrip().endswith(";"):
            return m.group(1)
    return None


def render_source_window(lines: List[str], idx: int, *, before: int, after: int) -> str:
    begin = max(0, idx - before)
    end = min(len(lines), idx + after + 1)
    out = []
    for k in range(begin, end):
        marker = ">>" if k == idx else "  "
        out.append(f"{marker} {k + 1:6d}: {lines[k]}")
    return "\n".join(out)


def _render_call_site_window(lines: List[str], idx: int) -> str:
    return render_source_window(
        lines,
        idx,
        before=CALL_SITE_CTX_BEFORE,
        after=CALL_SITE_CTX_AFTER,
    )


def collect_project_source_files(
    project_name: str,
    source_root: Optional[str] = None,
) -> tuple[List[str], List[str]]:
    errors: List[str] = []
    files: List[str] = []
    roots = [r for r in project_source_roots(project_name, source_root) if os.path.isdir(r)]
    if not roots:
        errors.append("no source mirror directory found")
        return files, errors
    root = roots[0]
    for dirpath, _dirs, names in os.walk(root):
        low = (dirpath + "/").replace("\\", "/").lower()
        if any(marker in low for marker in _CALL_SITE_NOISE_DIRS):
            continue
        for name in names:
            if name.lower().endswith(_C_SOURCE_SUFFIXES):
                files.append(os.path.join(dirpath, name))
                if len(files) >= CALL_SITE_MAX_FILES:
                    errors.append(f"file scan capped at {CALL_SITE_MAX_FILES}")
                    return files, errors
    return files, errors


def _collect_mirror_sources(
    project_name: str,
    source_file: Optional[str],
    source_root: Optional[str] = None,
) -> tuple[List[str], List[str]]:
    del source_file
    return collect_project_source_files(project_name, source_root)


def load_build_macro_facts(project_name: str, source_root: Optional[str] = None) -> dict:
    return _load_build_macro_facts(project_name, source_root)


def preprocessor_context_by_line(lines: List[str], macro_facts: dict) -> List[dict]:
    return _preprocessor_context_by_line(lines, macro_facts)


def build_evidence_for_conditions(conditions: List[str], macro_facts: dict) -> List[dict]:
    return _build_evidence_for_conditions(conditions, macro_facts)


def enumerate_textual_call_sites(
    project_name: str,
    function_name: str,
    source_file: Optional[str],
    source_root: Optional[str] = None,
) -> dict:
    """Find candidate DIRECT call sites of function_name from source text.

    Returns a structured object. Best-effort: missing mirror -> empty entries +
    collection_errors (never a guarantee). Does not resolve overloads / function
    pointers / macro-expanded / virtual calls (documented limitation).
    """
    result = {
        "entries": [],
        "total_candidates": 0,
        "included_candidates": 0,
        "truncated": False,
        "collection_errors": [],
    }
    if not function_name:
        result["collection_errors"].append("missing function_name")
        return result

    # Narrow scope by linkage: a `static` (internal-linkage) function can only be
    # called within its defining translation unit -> search that file only.
    defn_file = _resolve_in_mirror(project_name, source_file, source_root)
    is_static = False
    if defn_file:
        try:
            defn_lines = Path(defn_file).read_text(encoding="utf-8", errors="ignore").splitlines()
            is_static = _definition_is_static(defn_lines, function_name)
        except OSError as exc:
            result["collection_errors"].append(f"read defn file failed: {exc}")

    if is_static and defn_file:
        search_files = [defn_file]
    else:
        search_files, errs = _collect_mirror_sources(project_name, source_file, source_root)
        result["collection_errors"].extend(errs)

    if not search_files:
        result["collection_errors"].append("no source files to search (mirror missing?)")
        return result

    pat = re.compile(r"\b" + re.escape(function_name) + r"\s*\(")
    macro_facts = _load_build_macro_facts(project_name, source_root)
    entries: List[dict] = []
    for f in search_files:
        try:
            lines = Path(f).read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            result["collection_errors"].append(f"read {os.path.basename(f)} failed: {exc}")
            continue
        preprocessor_contexts = _preprocessor_context_by_line(lines, macro_facts)
        for i, line in enumerate(lines):
            m = pat.search(line)
            if not m:
                continue
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*")):  # comment line (best-effort)
                continue
            args = _first_paren_content(line[m.end() - 1 :])
            if _looks_like_declaration(args):
                continue  # definition or prototype (typed parameter) -> not a call
            preprocessor = preprocessor_contexts[i]
            preprocessor_status = preprocessor["status"]
            conditions = preprocessor["conditions"]
            build_evidence = _build_evidence_for_conditions(conditions, macro_facts)
            if preprocessor_status == "inactive":
                build_status = "inactive"
                build_reason = "An enclosing preprocessor branch is false under the collected build configuration."
            elif conditions and preprocessor_status == "unknown":
                build_status = "unknown"
                build_reason = "Enclosing preprocessor conditions could not be fully resolved from build artifacts."
            else:
                build_status = "unknown"
                build_reason = "No positive target-build evidence confirms this textual call site is compiled."
            entries.append(
                {
                    "candidate_id": f"{os.path.basename(f)}:{i + 1}",
                    "file": _display_path(f, project_name),
                    "line": i + 1,
                    "caller_function": _enclosing_function_name(lines, i),
                    "callsite_path_status": "textual_only",
                    "candidate_kind": "call",
                    "context_may_be_incomplete": True,
                    "build_status": build_status,
                    "build_reason": build_reason,
                    "preprocessor_status": preprocessor_status,
                    "preprocessor_conditions": conditions,
                    "build_evidence": build_evidence,
                    "local_context": _render_call_site_window(lines, i),
                }
            )

    entries.sort(key=lambda e: (e["file"], e["line"]))
    result["total_candidates"] = len(entries)
    capped = entries[:CALL_SITE_MAX_ENTRIES]
    result["entries"] = capped
    result["included_candidates"] = len(capped)
    result["truncated"] = len(capped) < len(entries)
    return result


def enrich_call_sites_with_calltree(call_sites: dict, all_nodes: List[Any], raw_blocker_name: str) -> dict:
    """Upgrade textual entries that also appear in the target calltree, and mark the
    discovery provenance. Best-effort line/file matching; never breaks textual data."""
    if not call_sites or not all_nodes or not raw_blocker_name:
        return call_sites
    by_key = {}
    for e in call_sites.get("entries", []):
        by_key[(os.path.basename(str(e.get("file"))), int(e.get("line") or 0))] = e
    for node in all_nodes:
        if getattr(node, "dst_function_name", None) != raw_blocker_name:
            continue
        srcf = os.path.basename(str(getattr(node, "dst_function_source_file", "") or ""))
        line = int(getattr(node, "src_linenumber", 0) or 0)
        parent = getattr(node, "parent_calltree_callsite", None)
        caller = getattr(parent, "dst_function_name", None) if parent else None
        entry = by_key.get((srcf, line))
        if entry is not None:
            entry["callsite_path_status"] = "present_in_target_calltree"
            if entry.get("build_status") == "inactive":
                entry["build_status"] = "unknown"
                entry["build_reason"] = (
                    "Conflicting evidence: collected preprocessor configuration marks this call site inactive, "
                    "but the target calltree contains it."
                )
            else:
                entry["build_status"] = "active"
                entry["build_reason"] = "The call site is present in the target-specific Introspector calltree."
            if caller and not entry.get("caller_function"):
                entry["caller_function"] = caller
    return call_sites


def render_call_sites_for_prompt(call_sites: Optional[dict]) -> str:
    if not call_sites or not call_sites.get("entries"):
        errs = "; ".join(call_sites.get("collection_errors", [])) if call_sites else "not collected"
        return f"N/A: no candidate call sites collected ({errs})."
    selectable = [e for e in call_sites["entries"] if e.get("build_status") != "inactive"]
    selectable.sort(
        key=lambda e: (
            0 if e.get("build_status") == "active" else 1,
            str(e.get("file", "")),
            int(e.get("line") or 0),
        )
    )
    inactive = [e for e in call_sites["entries"] if e.get("build_status") == "inactive"]
    active_count = sum(e.get("build_status") == "active" for e in selectable)
    unknown_count = sum(e.get("build_status") == "unknown" for e in selectable)
    head = [
        f"Discovered {call_sites['included_candidates']} of {call_sites['total_candidates']} "
        f"textual direct call site(s) of the blocker function"
        + (" (list truncated)" if call_sites.get("truncated") else "")
        + ".",
        f"Selectable candidates: {len(selectable)} (active={active_count}, unknown={unknown_count}). "
        f"Filtered inactive candidates: {len(inactive)}.",
        "path_status = how the call site was discovered (runtime_observed | "
        "present_in_target_calltree | textual_only); it does NOT imply the blocked side is "
        "reachable from it. build_status=active has positive target-build evidence; "
        "build_status=unknown has not been proven present or absent. Never assume unknown means active. "
        "local_context may be INCOMPLETE (an enclosing guard could be "
        "farther up). Pick a call site whose guard is compatible with the required predicate "
        "value; if a call site's guard is the negation of the predicate it cannot reach the "
        "blocked side. If the local context is insufficient to decide, say unknown.",
        "",
    ]
    for e in selectable:
        head.append(
            f"### {e['candidate_id']}  [{e['callsite_path_status']}]  "
            f"caller={e.get('caller_function') or 'unknown'}  build_status={e.get('build_status', 'unknown')}"
        )
        head.append(f"Build reason: {e.get('build_reason', 'N/A')}")
        if e.get("preprocessor_conditions"):
            head.append("Enclosing preprocessor conditions: " + " -> ".join(e["preprocessor_conditions"]))
        if e.get("build_evidence"):
            evidence_text = "; ".join(
                f"{item['file']}:{item['line']}: {item['text']}"
                for item in e["build_evidence"][:8]
            )
            head.append("Build evidence: " + evidence_text)
        head.append(e["local_context"])
        head.append("")
    if inactive:
        head.extend(
            [
                "## Filtered inactive call sites (not selectable)",
                "These entries are retained only as audit evidence. Do not select them.",
                "",
            ]
        )
        for e in inactive:
            head.append(f"- {e['candidate_id']}: {e.get('build_reason', 'inactive')}")
            if e.get("preprocessor_conditions"):
                head.append("  Conditions: " + " -> ".join(e["preprocessor_conditions"]))
            if e.get("build_evidence"):
                evidence_text = "; ".join(
                    f"{item['file']}:{item['line']}: {item['text']}"
                    for item in e["build_evidence"][:8]
                )
                head.append("  Evidence: " + evidence_text)
    return "\n".join(head)


def extract_blocker_callchain_info(
    blocker: dict,
    yaml_file: str,
    project_name: str,
    use_gdb: bool = True,
    max_gdb_inputs: int = 0,
    source_root: Optional[str] = None,
) -> dict:
    # Textual call-site enumeration is independent of Introspector/CFG and must run
    # on every return path below, or it would never execute when no calltree .data
    # exists (the current situation). calltree only enriches it.
    call_sites = enumerate_textual_call_sites(
        project_name,
        blocker.get("function_name", ""),
        blocker.get("source_file"),
        source_root,
    )

    if not INTROSPECTOR_AVAILABLE:
        return {
            "target": blocker.get("best_target"),
            "breakpoint": blocker["function_name"],
            "call_sites": call_sites,
            "cfg_error": f"Introspector dependencies unavailable: {INTROSPECTOR_IMPORT_ERROR}",
        }

    introspector = Introspector()
    target = blocker.get("best_target")
    cfg_file_path = get_data_file_for_target(yaml_file, target)
    breakpoint = blocker["function_name"]
    result = {"target": target, "breakpoint": breakpoint, "call_sites": call_sites}
    project_out_dir = get_project_out_dir(project_name)
    project_corpus_root = get_project_corpus_root(project_name)

    if use_gdb:
        source_file = blocker.get("source_file", "")
        seed_limit = max_gdb_inputs if max_gdb_inputs and max_gdb_inputs > 0 else None
        try:
            matching_seeds, resolved_source_file = find_matching_seeds(
                project=project_name,
                target=target,
                function_name=breakpoint,
                branch_line=int(blocker["branch_line_number"]),
                blocked_side_line=int(
                    blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder", 0)) or 0
                ),
                corpus_dir=Path(project_corpus_root) / target,
                limit=seed_limit,
                source_file=source_file,
                skip_build=True,
                stop_after_first=True,
            )
        except Exception as exc:
            matching_seeds = []
            resolved_source_file = source_file
            result["gdb_error"] = f"Seed discovery failed: {exc}"

        result["matching_seeds"] = matching_seeds
        if matching_seeds:
            selected_seed = matching_seeds[0]["seed"]
            line_breakpoint = f"{source_file}:{blocker['branch_line_number']}"
            gdb_result = find_runtime_call_chain_with_gdb(
                target,
                line_breakpoint,
                selected_seed,
                out_dir=project_out_dir,
                fallback_breakpoint=breakpoint,
            )
            gdb_result["seed_source"] = "find_blocker_seeds_by_coverage"
            gdb_result["selected_seed"] = selected_seed
            gdb_result["resolved_source_file"] = resolved_source_file
        else:
            gdb_result = {
                "error": f"No branch-reaching seed found for breakpoint '{breakpoint}'.",
                "target": target,
                "breakpoint": breakpoint,
                "seed_source": "find_blocker_seeds_by_coverage",
            }
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
    enrich_call_sites_with_calltree(call_sites, all_nodes, raw_blocker_name)
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
    blocked_side_line_number = blocker.get("blocked_side_line_number", blocker.get("blocked_side_line_numder"))

    return SimpleNamespace(
        backend=backend,
        model=model,
        project_name=project_name,
        function_name=blocker["function_name"],
        branch_line_number=str(blocker["branch_line_number"]),
        blocked_side_line_number=str(blocked_side_line_number),
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
    parser.add_argument(
        "--max-gdb-inputs",
        type=int,
        default=0,
        help="Max corpus inputs to try for GDB runtime call path collection. Use 0 to scan the full corpus.",
    )
    parser.add_argument("--classify", action="store_true", help="Run blocker classification after extraction")
    parser.add_argument("--backend", default="vertexai", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default="gemini-2.5-flash")
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
            "blocked_side_line_number": args.manual_blocked_side_line,
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
            if gdb_result.get("selected_seed"):
                print(f"[Info] Seed used for GDB: {gdb_result['selected_seed']}")
            if gdb_result.get("breakpoint_info"):
                print("\n=== GDB Breakpoint Info ===")
                print(gdb_result["breakpoint_info"])
            if gdb_result.get("breakpoint_warnings"):
                print("\n=== GDB Breakpoint Warnings ===")
                print(gdb_result["breakpoint_warnings"])
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
