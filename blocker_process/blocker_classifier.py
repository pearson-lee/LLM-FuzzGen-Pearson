#!/usr/bin/env python3
import argparse
import contextlib
import datetime
import json
import logging
import posixpath
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from external.introspector import Introspector
from external.oss_fuzz import OSSFuzz
from blocker_process.coverage_utils import get_line_execution_count
from blocker_process.blocker_triage import run_triage_for_classifier
import config.config as config

try:
    from json_repair import repair_json
except Exception:
    repair_json = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
TEMPLATE_PATH = REPO_ROOT / "prompts" / "templates" / "blocker_classify_template"
AUTO_CONTEXT_DIR = REPO_ROOT / "logs" / "auto_context"
_SHARED_INTROSPECTOR: Introspector | None = None
_INTROSPECTOR_AVAILABLE: bool | None = None
_SESSION_FILE_HANDLER_FLAG = "_llm_fuzzgen_session_file_handler"


def get_introspector() -> Introspector:
    global _SHARED_INTROSPECTOR
    if _SHARED_INTROSPECTOR is None:
        _SHARED_INTROSPECTOR = Introspector()
    return _SHARED_INTROSPECTOR


def introspector_available() -> bool:
    global _INTROSPECTOR_AVAILABLE
    if _INTROSPECTOR_AVAILABLE is not None:
        return _INTROSPECTOR_AVAILABLE
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        _INTROSPECTOR_AVAILABLE = sock.connect_ex(("127.0.0.1", 8080)) == 0
    except Exception:
        _INTROSPECTOR_AVAILABLE = False
    finally:
        sock.close()
    return _INTROSPECTOR_AVAILABLE

def load_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""

def read_optional_file(path_str: str | None) -> str:
    if not path_str:
        return "N/A"
    p = Path(path_str)
    return load_text(p) if p.exists() else "N/A"


def resolve_text(file_path: str | None, inline_text: str | None, default: str = "N/A") -> str:
    if file_path:
        text = read_optional_file(file_path)
        if text != "N/A":
            return text
    if inline_text:
        return inline_text
    return default


def sanitize_filename(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return sanitized or "unknown"


def write_auto_context_file(project_name: str, category: str, filename_hint: str, content: str) -> str | None:
    if not content:
        return None
    AUTO_CONTEXT_DIR.mkdir(parents=True, exist_ok=True)
    target_dir = AUTO_CONTEXT_DIR / sanitize_filename(project_name) / sanitize_filename(category)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / sanitize_filename(filename_hint)
    target_path.write_text(content, encoding="utf-8")
    return str(target_path)


def track_auto_context_path(args: argparse.Namespace, path_str: str | None) -> None:
    if not path_str:
        return
    tracked = getattr(args, "_auto_context_paths", None)
    if tracked is None:
        tracked = []
        args._auto_context_paths = tracked
    if path_str not in tracked:
        tracked.append(path_str)


def cleanup_auto_context_paths(args: argparse.Namespace) -> None:
    if getattr(args, "keep_auto_context", False):
        return

    tracked_paths = getattr(args, "_auto_context_paths", [])
    for path_str in tracked_paths:
        path = Path(path_str)
        try:
            if path.exists() and AUTO_CONTEXT_DIR in path.parents:
                path.unlink()
        except Exception as exc:
            logging.warning("Failed to remove auto context file %s: %s", path, exc)

    project_dir = AUTO_CONTEXT_DIR / sanitize_filename(getattr(args, "project_name", ""))
    for directory in [project_dir / "headers", project_dir / "library_sources", project_dir / "fuzz_targets", project_dir]:
        try:
            if directory.exists() and not any(directory.iterdir()):
                directory.rmdir()
        except Exception:
            pass

    try:
        if AUTO_CONTEXT_DIR.exists() and not any(AUTO_CONTEXT_DIR.iterdir()):
            AUTO_CONTEXT_DIR.rmdir()
    except Exception:
        pass


def first_present(mapping: dict, keys: list[str], default=None):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return default


def normalize_blocker_payload(payload: dict) -> dict:
    return {
        "function_name": first_present(payload, ["function_name"]),
        "branch_line_number": str(first_present(payload, ["branch_line_number"], "")),
        "blocked_side_line_number": str(
            first_present(payload, ["blocked_side_line_number", "blocked_side_line_numder"], "")
        ),
        "source_file": first_present(payload, ["source_file"]),
        "source_api_file": first_present(payload, ["source_api_file", "source_file"]),
        "target_name": first_present(payload, ["target_name", "best_target"]),
        "seeds": first_present(payload, ["seeds", "seed_paths"], []),
    }

def format_prompt(template: str, args: argparse.Namespace) -> str:
    mapping = {
        "language": args.language or "N/A",
        "project_name": args.project_name or "N/A",
        "function_name": args.function_name or "N/A",
        "branch_line_number": getattr(args, "branch_line_number", "N/A"),
        "blocked_side_line_number": getattr(args, "blocked_side_line_number", "N/A"),
        "blocker_line_code": getattr(args, "blocker_line_code", "N/A") or "N/A",
        "blocked_side_line_code": getattr(args, "blocked_side_line_code", "N/A") or "N/A",
        "fuzz_target_code": resolve_text(getattr(args, "fuzz_file", None), getattr(args, "fuzz_target_code", None)),
        "header_code": resolve_text(getattr(args, "header_file", None), getattr(args, "header_code", None)),
        "branch_hit_count": getattr(args, "branch_hit_count", "N/A") or "N/A",
        "runtime_blocker_segment": resolve_text(
            getattr(args, "runtime_blocker_segment_file", None),
            getattr(args, "runtime_blocker_segment", None),
        ),
        "runtime_blocker_segment_source_codes": resolve_text(
            getattr(args, "runtime_blocker_segment_source_codes_file", None),
            getattr(args, "runtime_blocker_segment_source_codes", None),
        ),
        "cfg_call_chain": resolve_text(
            getattr(args, "cfg_call_chain_file", None),
            getattr(args, "cfg_call_chain", None),
        ),
        "cfg_source_codes": resolve_text(
            getattr(args, "cfg_source_codes_file", None),
            getattr(args, "cfg_source_codes", None),
        ),
    }

    def repl(m: re.Match) -> str:
        key = m.group(1)
        return mapping.get(key, m.group(0))

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, template)

def to_api_filepath(path_str: str) -> str:
    if not path_str:
        return ""
    p = path_str.replace("\\", "/")
    marker = "/inspector/source-code"
    if marker in p:
        # e.g. .../inspector/source-code/src/tinyxml2/tinyxml2.cpp -> /src/tinyxml2/tinyxml2.cpp
        return p.split(marker, 1)[1]
    build_out_src_marker = "/build/out/"
    if build_out_src_marker in p and "/src/" in p:
        return p[p.index("/src/") :]
    return p

def fetch_line_code(project_name: str, filepath: str, line_no: int) -> str:
    if not project_name or not filepath or line_no <= 0:
        return ""
    local_path = Path(filepath)
    if local_path.is_file():
        try:
            lines = local_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if 1 <= line_no <= len(lines):
                return lines[line_no - 1].strip()
        except Exception:
            pass
    if not introspector_available():
        return ""
    ins = get_introspector()
    return ins.get_project_source_code(
        project_name=project_name,
        filepath=filepath,
        begin_line=line_no,
        end_line=line_no,
    ).strip()


def resolve_function_metadata(project_name: str, function_name: str) -> dict:
    if not introspector_available():
        return {}
    introspector = get_introspector()
    normalized_query = function_name.replace(" ", "")
    for func in introspector.get_all_functions(project_name):
        if func.get("function_name", "").replace(" ", "") == normalized_query:
            return func
    return {}


def apply_blocker_payload(args: argparse.Namespace) -> argparse.Namespace:
    payload = None
    if getattr(args, "blocker_json_file", None):
        payload = json.loads(Path(args.blocker_json_file).read_text(encoding="utf-8"))
    elif getattr(args, "blocker_json", None):
        payload = json.loads(args.blocker_json)

    if not isinstance(payload, dict):
        return args

    normalized = normalize_blocker_payload(payload)
    if not getattr(args, "function_name", None):
        args.function_name = normalized["function_name"]
    if not getattr(args, "branch_line_number", None):
        args.branch_line_number = normalized["branch_line_number"]
    if not getattr(args, "blocked_side_line_number", None):
        args.blocked_side_line_number = normalized["blocked_side_line_number"]
    if not getattr(args, "source_file", None):
        args.source_file = normalized["source_file"]
    if not getattr(args, "source_api_file", None):
        args.source_api_file = normalized["source_api_file"]
    if not getattr(args, "target_name", None):
        args.target_name = normalized["target_name"]
    if not getattr(args, "seed", None):
        seeds = normalized.get("seeds", [])
        if isinstance(seeds, list):
            args.seed = [str(item) for item in seeds if item]
    return args


def resolve_fuzz_target_path(project_name: str, requested_target: str | None) -> str | None:
    project_dir = REPO_ROOT / "external" / "oss-fuzz" / "projects" / project_name
    if requested_target:
        for suffix in (".cpp", ".cc", ".cxx", ".c"):
            candidate = project_dir / f"{requested_target}{suffix}"
            if candidate.is_file():
                return str(candidate.resolve())

    if not introspector_available():
        return None
    introspector = get_introspector()
    pairs = introspector._query_api("harness-source-and-executable", {"project": project_name}).get("pairs", [])
    if not pairs:
        return None

    selected_pair = None
    if requested_target:
        for pair in pairs:
            executable = pair.get("executable", "")
            candidate_name = Path(executable).stem if executable else ""
            if candidate_name == requested_target:
                selected_pair = pair
                break
    if selected_pair is None:
        selected_pair = pairs[0]

    source_path = selected_pair.get("source", "")
    executable = selected_pair.get("executable", "")
    target_name = Path(executable).stem if executable else requested_target or "fuzz_target"
    if not source_path:
        return None

    code = introspector.get_project_source_code(project_name, source_path, 0, 999)
    if not code:
        return None
    suffix = Path(source_path).suffix or ".cc"
    return write_auto_context_file(project_name, "fuzz_targets", f"{target_name}{suffix}", code)


def resolve_source_file_path(project_name: str, function_name: str) -> str | None:
    if not introspector_available():
        return None
    function_meta = resolve_function_metadata(project_name, function_name)
    source_path = function_meta.get("function_filename", "")
    if not source_path:
        return None

    source_code = get_introspector().get_project_source_code(project_name, source_path, 1, 999999)
    if not source_code:
        return None

    source_name = Path(source_path).name or f"{sanitize_filename(function_name)}.c"
    return write_auto_context_file(project_name, "library_sources", source_name, source_code)


def resolve_source_api_file(project_name: str, function_name: str) -> str:
    if not introspector_available():
        return ""
    function_meta = resolve_function_metadata(project_name, function_name)
    return function_meta.get("function_filename", "")


def infer_header_api_candidates(source_api_file: str, source_code: str) -> list[str]:
    if not source_api_file or not source_code:
        return []

    source_dir = posixpath.dirname(source_api_file)
    candidates: list[str] = []
    seen: set[str] = set()

    for match in re.finditer(r'^\s*#\s*include\s*"([^"]+\.(?:h|hh|hpp|hxx))"', source_code, re.MULTILINE):
        include_path = match.group(1).strip()
        if include_path.startswith("/src/"):
            candidate = posixpath.normpath(include_path)
        else:
            candidate = posixpath.normpath(posixpath.join(source_dir, include_path))
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)

    return candidates


def resolve_header_file_path(
    project_name: str,
    function_name: str,
    source_api_file: str | None = None,
) -> str | None:
    if not introspector_available():
        return None
    introspector = get_introspector()
    _, headers = introspector.get_function_signature_and_headers(project_name, function_name)
    for header_path in headers:
        header_code = introspector.get_project_source_code(project_name, header_path, 1, 999999)
        if not header_code:
            continue
        header_name = Path(header_path).name or f"{sanitize_filename(function_name)}.h"
        return write_auto_context_file(project_name, "headers", header_name, header_code)

    api_source = source_api_file or resolve_source_api_file(project_name, function_name)
    if api_source:
        source_code = introspector.get_project_source_code(project_name, api_source, 1, 999999)
        for candidate in infer_header_api_candidates(api_source, source_code):
            header_code = introspector.get_project_source_code(project_name, candidate, 1, 999999)
            if not header_code:
                continue
            header_name = Path(candidate).name or f"{sanitize_filename(function_name)}.h"
            logging.info("Resolved header via source include fallback: %s", candidate)
            return write_auto_context_file(project_name, "headers", header_name, header_code)
    return None


def infer_introspector_yaml_path(project_name: str) -> str:
    return str(
        REPO_ROOT
        / "external"
        / "oss-fuzz"
        / "build"
        / "out"
        / project_name
        / "inspector"
        / "exe_to_fuzz_introspector_logs.yaml"
    )


def should_collect_callpath_context(args: argparse.Namespace) -> bool:
    return not all(
        [
            getattr(args, "runtime_blocker_segment", None) or getattr(args, "runtime_blocker_segment_file", None),
            getattr(args, "runtime_blocker_segment_source_codes", None)
            or getattr(args, "runtime_blocker_segment_source_codes_file", None),
            getattr(args, "cfg_call_chain", None) or getattr(args, "cfg_call_chain_file", None),
            getattr(args, "cfg_source_codes", None) or getattr(args, "cfg_source_codes_file", None),
        ]
    )


def auto_collect_callpath_context(args: argparse.Namespace) -> argparse.Namespace:
    if not should_collect_callpath_context(args):
        return args

    if not getattr(args, "target_name", None):
        logging.info("Skipping auto call-path collection because target name is unavailable.")
        return args

    yaml_file = getattr(args, "yaml_file", None) or infer_introspector_yaml_path(args.project_name)
    if not Path(yaml_file).exists():
        logging.info("Skipping auto call-path collection because YAML is missing: %s", yaml_file)
        return args

    blocker = {
        "function_name": args.function_name,
        "branch_line_number": str(args.branch_line_number),
        "blocked_side_line_number": str(args.blocked_side_line_number),
        "source_file": getattr(args, "source_api_file", None) or args.source_file or "",
        "best_target": args.target_name,
    }

    try:
        from blocker_process.blocker_callpath_extractor import (
            extract_blocker_callchain_info,
            format_cfg_collection_status,
            format_runtime_collection_status,
        )
    except Exception as exc:
        logging.warning("Failed to import blocker_callpath_extractor for auto context collection: %s", exc)
        return args

    extraction_result = extract_blocker_callchain_info(
        blocker=blocker,
        yaml_file=yaml_file,
        project_name=args.project_name,
        max_gdb_inputs=getattr(args, "max_gdb_inputs", 0),
    )

    gdb_result = extraction_result.get("gdb_result", {})
    cfg_result = extraction_result.get("cfg_result", {})

    runtime_status, runtime_error = format_runtime_collection_status(gdb_result)
    cfg_status, cfg_error = format_cfg_collection_status(cfg_result, extraction_result.get("cfg_error", ""))

    if not getattr(args, "runtime_blocker_segment", None):
        args.runtime_blocker_segment = gdb_result.get("runtime_blocker_segment_structure")
    if not getattr(args, "runtime_blocker_segment_source_codes", None):
        args.runtime_blocker_segment_source_codes = gdb_result.get("runtime_segment_source_codes")
    if not getattr(args, "cfg_call_chain", None):
        args.cfg_call_chain = cfg_result.get("chain_structure")
    if not getattr(args, "cfg_source_codes", None):
        args.cfg_source_codes = cfg_result.get("unique_source_codes")
    if not getattr(args, "triggering_input", None):
        args.triggering_input = gdb_result.get("triggering_input", "")

    args.runtime_collection_status = runtime_status
    args.runtime_collection_error = runtime_error
    args.cfg_collection_status = cfg_status
    args.cfg_collection_error = cfg_error
    args.yaml_file = yaml_file
    logging.info(
        "Auto-collected call-path context: runtime=%s cfg=%s target=%s",
        runtime_status,
        cfg_status,
        args.target_name,
    )
    return args


def auto_resolve_context_files(args: argparse.Namespace) -> argparse.Namespace:
    if not getattr(args, "source_api_file", None):
        current_source = getattr(args, "source_file", None)
        if current_source:
            args.source_api_file = to_api_filepath(current_source)

    if not getattr(args, "source_api_file", None):
        args.source_api_file = resolve_source_api_file(args.project_name, args.function_name)

    current_source = getattr(args, "source_file", None)
    if not current_source or not Path(current_source).exists():
        args.source_file = resolve_source_file_path(args.project_name, args.function_name)
        if args.source_file:
            track_auto_context_path(args, args.source_file)
            logging.info("Auto-resolved source file: %s", args.source_file)

    current_fuzz = getattr(args, "fuzz_file", None)
    if not current_fuzz or not Path(current_fuzz).exists():
        args.fuzz_file = resolve_fuzz_target_path(args.project_name, getattr(args, "target_name", None))
        if args.fuzz_file:
            track_auto_context_path(args, args.fuzz_file)
            logging.info("Auto-resolved fuzz target file: %s", args.fuzz_file)

    current_header = getattr(args, "header_file", None)
    if not current_header or not Path(current_header).exists():
        args.header_file = resolve_header_file_path(
            args.project_name,
            args.function_name,
            getattr(args, "source_api_file", None),
        )
        if args.header_file:
            track_auto_context_path(args, args.header_file)
            logging.info("Auto-resolved header file: %s", args.header_file)

    if not args.source_file:
        raise RuntimeError(
            f"Could not auto-resolve source file for function '{args.function_name}'. "
            "Pass --source-file explicitly or ensure Introspector data is available."
        )
    if not args.fuzz_file:
        raise RuntimeError(
            "Could not auto-resolve fuzz target source. "
            "Pass --fuzz-file explicitly or provide --target-name with available harness metadata."
        )
    return args

def extract_json(text: str) -> dict:
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, count=1)
        cleaned = re.sub(r"\s*```$", "", cleaned, count=1)
    if cleaned and not cleaned.lstrip().startswith("{"):
        first_brace = cleaned.find("{")
        if first_brace >= 0:
            cleaned = cleaned[first_brace:]
        elif re.match(r'^\s*"', cleaned):
            cleaned = "{\n" + cleaned
    if cleaned.count("{") > cleaned.count("}"):
        cleaned = cleaned + ("\n" + ("}" * (cleaned.count("{") - cleaned.count("}"))))

    if repair_json is not None:
        parsed = repair_json(cleaned, return_objects=True)
        if not isinstance(parsed, dict):
            raise ValueError("Failed to parse JSON into dictionary.")
        return normalize_classification_result(parsed)

    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("Failed to parse JSON into dictionary.")
    return normalize_classification_result(parsed)


def normalize_classification_result(parsed: dict) -> dict:
    if "classification" in parsed and isinstance(parsed["classification"], dict):
        return parsed
    if "dependency" in parsed:
        return {
            "analysis_trace": parsed.get("analysis_trace", []),
            "classification": {"dependency": parsed.get("dependency", "")},
            "reason": parsed.get("reason", ""),
        }
    raise ValueError("Parsed JSON does not contain the expected classification fields.")


def build_json_retry_prompt(original_prompt: str, response_text: str, error_message: str) -> str:
    return (
        f"{original_prompt}\n\n"
        "Your previous response was not parseable as a single JSON object.\n"
        "Return only one valid JSON object.\n"
        "Do not use markdown fences.\n"
        "Do not add explanation before or after the JSON.\n"
        f"Parser error: {error_message}\n"
        "Previous invalid response:\n"
        f"{response_text}"
    )

def _parse_program_json_output(stdout: str) -> dict | None:
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def run_program(script: Path, extra_args: list[str] = None) -> dict:
    cmd = [sys.executable, str(script)]
    if extra_args:
        cmd.extend(extra_args)
    logging.info("Dispatching: %s", " ".join(cmd))
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    parsed_output = _parse_program_json_output(p.stdout)
    if p.stdout:
        logging.info("Pipeline stdout:\n%s", p.stdout)
    if p.stderr:
        logging.info("Pipeline stderr:\n%s", p.stderr)
    return {
        "returncode": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
        "parsed_output": parsed_output,
    }


def _infer_pipeline_methods(dependency_result: str, pipeline_output: dict | None) -> list[str]:
    parsed_output = pipeline_output.get("parsed_output") if pipeline_output else None
    if isinstance(parsed_output, dict):
        reported_methods = parsed_output.get("pipeline_methods")
        if isinstance(reported_methods, list):
            normalized = [str(method) for method in reported_methods if str(method).strip()]
            if normalized:
                return normalized

    if dependency_result == "Input Dependent":
        methods = ["llm_seed_generator"]
        if isinstance(parsed_output, dict):
            # Keep space for future richer dependent pipeline integrations.
            if parsed_output.get("used_symcc"):
                methods.append("symcc")
        return methods

    if dependency_result == "Input Independent":
        methods: list[str] = []
        if isinstance(parsed_output, dict):
            iterations = parsed_output.get("iterations", []) or []
            fallback_iterations = parsed_output.get("fallback_iterations", []) or []
            strategies = {
                item.get("strategy")
                for item in [*iterations, *fallback_iterations]
                if isinstance(item, dict) and item.get("strategy")
            }
            if "reference_guided" in strategies:
                methods.append("reference_guided_generation")
            if "dedicated_generation" in strategies:
                methods.append("dedicated_generation")
            if not methods:
                if "refine_existing" in strategies:
                    methods.append("reference_guided_generation")
                if "generate_dedicated" in strategies:
                    methods.append("dedicated_generation")
        return methods or ["input_independent_target_generation"]

    return []


def infer_attempt_result(
    dependency_result: str,
    pipeline_returncode: int | None,
    pipeline_output: dict | None,
) -> str:
    parsed_output = pipeline_output.get("parsed_output") if isinstance(pipeline_output, dict) else None
    if isinstance(parsed_output, dict):
        explicit = str(parsed_output.get("attempt_result", "")).strip()
        if explicit in {"success", "failed", "llm_error"}:
            return explicit
        if parsed_output.get("success") is True:
            return "success"

    if dependency_result in {"Input Dependent", "Input Independent"}:
        return "success" if pipeline_returncode == 0 else "failed"
    return "failed"


def build_seed_generation_args(args: argparse.Namespace) -> list[str]:
    forwarded = [
        "--backend",
        args.backend,
        "--project-name",
        args.project_name,
        "--function-name",
        args.function_name,
        "--branch-line-number",
        str(args.branch_line_number),
        "--blocked-side-line-number",
        str(args.blocked_side_line_number),
        "--source-file",
        args.source_file,
        "--fuzz-file",
        args.fuzz_file,
    ]

    if getattr(args, "source_api_file", None):
        forwarded.extend(["--source-api-file", args.source_api_file])

    if getattr(args, "target_name", None):
        forwarded.extend(["--target-name", args.target_name])
    for seed in getattr(args, "seed", []) or []:
        forwarded.extend(["--seed", seed])

    if args.model:
        forwarded.extend(["--model", args.model])
    if getattr(args, "header_file", None):
        forwarded.extend(["--header-file", args.header_file])
    if getattr(args, "language", None):
        forwarded.extend(["--language", args.language])
    if getattr(args, "runtime_blocker_segment_file", None):
        forwarded.extend(["--runtime-blocker-segment-file", args.runtime_blocker_segment_file])
    if getattr(args, "runtime_blocker_segment_source_codes_file", None):
        forwarded.extend(
            ["--runtime-blocker-segment-source-codes-file", args.runtime_blocker_segment_source_codes_file]
        )
    if getattr(args, "cfg_call_chain_file", None):
        forwarded.extend(["--cfg-call-chain-file", args.cfg_call_chain_file])
    if getattr(args, "cfg_source_codes_file", None):
        forwarded.extend(["--cfg-source-codes-file", args.cfg_source_codes_file])
    if getattr(args, "runtime_blocker_segment", None):
        forwarded.extend(["--runtime-blocker-segment", args.runtime_blocker_segment])
    if getattr(args, "runtime_blocker_segment_source_codes", None):
        forwarded.extend(["--runtime-blocker-segment-source-codes", args.runtime_blocker_segment_source_codes])
    if getattr(args, "cfg_call_chain", None):
        forwarded.extend(["--cfg-call-chain", args.cfg_call_chain])
    if getattr(args, "cfg_source_codes", None):
        forwarded.extend(["--cfg-source-codes", args.cfg_source_codes])
    if getattr(args, "triggering_input", None):
        forwarded.extend(["--triggering-input", args.triggering_input])
    if getattr(args, "max_iterations", None) is not None:
        forwarded.extend(["--max-iterations", str(args.max_iterations)])
    if getattr(args, "fuzz_seconds", None) is not None:
        forwarded.extend(["--fuzz-seconds", str(args.fuzz_seconds)])
    if getattr(args, "reset_corpus_per_iteration", False):
        forwarded.append("--reset-corpus-per-iteration")

    return forwarded


def build_input_independent_solver_args(args: argparse.Namespace) -> list[str]:
    forwarded = build_seed_generation_args(args)
    if getattr(args, "blocker_line_code", None):
        forwarded.extend(["--blocker-line-code", args.blocker_line_code])
    if getattr(args, "blocked_side_line_code", None):
        forwarded.extend(["--blocked-side-line-code", args.blocked_side_line_code])
    return forwarded

def check_function_coverage(project_name: str, fuzzer_name: str, func_name: str) -> str:
    """
    Retrieves the line coverage report for a specific function within a given fuzz target.
    It automatically translates the demangled function name to its mangled regex.
    """
    oss_fuzz = OSSFuzz()
    report_file = oss_fuzz.build_out_dir / project_name / "textcov_reports" / f"{fuzzer_name}.linecovreport"
    if report_file.exists():
        try:
            report = report_file.read_text(encoding="utf-8")
        except OSError as exc:
            logging.warning("Failed to read cached line coverage report %s: %s", report_file, exc)
        else:
            if report.strip():
                logging.info("Using cached line coverage report: %s", report_file)
                return report
            logging.info("Cached line coverage report is empty: %s", report_file)

    if not introspector_available():
        logging.info("Skipping function coverage lookup because Introspector is unavailable.")
        return ""
    introspector = get_introspector()
    
    # 1. Look up the mangled function name (raw_function_name)
    func_name_list = introspector.get_all_functions(project_name)
    function_regex = ""
    for func in func_name_list:
        # Remove spaces to ensure robust string matching
        target_name = func.get('function_name', '').replace(' ', '')
        query_name = func_name.replace(' ', '')
        
        if target_name == query_name:
            function_regex = func.get('raw_function_name', '')
            break  # Found the matching function

    if not function_regex:
        logging.warning(f"Could not find heavily mangled name for '{func_name}' in project '{project_name}'")
        return ""

    logging.info(f"Matched '{func_name}' to regex: '{function_regex}'. Checking coverage...")
    
    # 2. Extract the coverage report
    report = oss_fuzz.linecov_reports(
        proj_name=project_name, 
        fuzzer_name=fuzzer_name, 
        fun_name_regex=function_regex
    )
    
    return report

@contextlib.contextmanager
def scoped_file_logging(func_name: str):
    safe_func_name = func_name.replace("::", "_").replace(" ", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{timestamp}_{safe_func_name}.log"

    log_dir = REPO_ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    log_filepath = log_dir / log_filename

    root_logger = logging.getLogger()
    file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    setattr(file_handler, _SESSION_FILE_HANDLER_FLAG, True)
    root_logger.addHandler(file_handler)
    try:
        logging.info(f"Log file create: {log_filepath}")
        yield log_filepath
    finally:
        root_logger.removeHandler(file_handler)
        file_handler.close()


def log_collection_status(args: argparse.Namespace) -> None:
    logging.info("=============== Collection Status ===============")
    logging.info("Runtime/GDB acquisition status: %s", getattr(args, "runtime_collection_status", "unknown"))
    logging.info("Static/CFG acquisition status: %s", getattr(args, "cfg_collection_status", "unknown"))

    runtime_error = getattr(args, "runtime_collection_error", "")
    cfg_error = getattr(args, "cfg_collection_error", "")
    triggering_input = getattr(args, "triggering_input", "")

    if runtime_error:
        logging.info("Runtime/GDB error: %s", runtime_error)
    if cfg_error:
        logging.info("Static/CFG error: %s", cfg_error)
    if triggering_input:
        logging.info("Triggering input: %s", triggering_input)


def enrich_classification_args(args: argparse.Namespace) -> argparse.Namespace:
    oss_fuzz = OSSFuzz()
    api_filepath = getattr(args, "source_api_file", None) or to_api_filepath(args.source_file or "")
    branch_line = int(args.branch_line_number)
    blocked_side_line = int(args.blocked_side_line_number)

    args.language = oss_fuzz.proj_lang(args.project_name)
    args.blocker_line_code = fetch_line_code(args.project_name, api_filepath, branch_line) or "N/A"
    args.blocked_side_line_code = fetch_line_code(args.project_name, api_filepath, blocked_side_line) or "N/A"

    if getattr(args, "fuzz_file", None):
        fuzzer_name = Path(args.fuzz_file).stem
        try:
            cov_report = check_function_coverage(args.project_name, fuzzer_name, args.function_name)
            args.branch_hit_count = get_line_execution_count(
                cov_report,
                branch_line,
                function_name=args.function_name,
            )
        except Exception as exc:
            logging.warning("Failed to get branch hit count: %s", exc)
            args.branch_hit_count = "N/A"
    else:
        args.branch_hit_count = "N/A"

    return args


def classify_blocker(args: argparse.Namespace, execute_pipeline: bool = True) -> dict:
    from llm_interface.llm_client import LLMClient

    try:
        args = apply_blocker_payload(args)
        with scoped_file_logging(args.function_name):
            args = auto_resolve_context_files(args)
            args = auto_collect_callpath_context(args)
            log_collection_status(args)
            args = enrich_classification_args(args)

            if not TEMPLATE_PATH.exists():
                raise FileNotFoundError(f"Template missing: {TEMPLATE_PATH}")

            template = load_text(TEMPLATE_PATH)
            prompt = format_prompt(template, args)
            logging.info("================ Generated Prompt ================\n%s\n", prompt)

            llm = LLMClient(
                backend=args.backend,
                model_name=args.model,
                temperature=config.BLOCKER_CLASSIFIER_TEMPERATURE,
            )
            parse_retry_attempts = max(1, int(getattr(config, "BLOCKER_CLASSIFIER_PARSE_RETRY_ATTEMPTS", 3)))
            parse_retry_delay_sec = float(getattr(config, "BLOCKER_CLASSIFIER_PARSE_RETRY_DELAY_SEC", 2.0))
            response_text = ""
            result = None
            current_prompt = prompt
            last_exc: Exception | None = None

            for attempt in range(1, parse_retry_attempts + 1):
                response_text = llm.generate(current_prompt) or ""
                if not response_text:
                    last_exc = RuntimeError("Empty LLM response.")
                else:
                    try:
                        result = extract_json(response_text)
                        break
                    except Exception as exc:
                        last_exc = exc
                        logging.error(
                            "JSON parsing failed on blocker classification attempt %d/%d: %s",
                            attempt,
                            parse_retry_attempts,
                            exc,
                        )
                        print(response_text)
                        current_prompt = build_json_retry_prompt(prompt, response_text, str(exc))

                if attempt < parse_retry_attempts:
                    logging.info(
                        "Retrying blocker classification due to unparsable LLM output (attempt %d/%d).",
                        attempt + 1,
                        parse_retry_attempts,
                    )
                    time.sleep(parse_retry_delay_sec)

            if result is None:
                raise last_exc or ValueError("Failed to parse blocker classification JSON.")

            analysis_trace = result.get("analysis_trace", [])
            classification = result.get("classification", {})
            dependency_result = classification.get("dependency", "")
            reason = result.get("reason", "")

            if isinstance(analysis_trace, list):
                formatted_trace = "\n\n".join(analysis_trace)
            else:
                formatted_trace = str(analysis_trace)

            logging.info(
                "Analysis trace:\n\n%s\n\n------------------------\nDependency: %s\nReason: %s\n",
                formatted_trace,
                dependency_result,
                reason,
            )

            output = {
                "prompt": prompt,
                "response_text": response_text,
                "parsed_result": result,
                "dependency_result": dependency_result,
                "reason": reason,
            }

            if not execute_pipeline:
                return output

            pipeline_mode = getattr(args, "blocker_pipeline_mode", None)
            skip_dependent_pipeline = bool(getattr(args, "skip_input_dependent_pipeline", False))
            skip_independent_pipeline = bool(getattr(args, "skip_input_independent_pipeline", False))
            if pipeline_mode == "dependent":
                skip_dependent_pipeline = False
                skip_independent_pipeline = True
            elif pipeline_mode == "independent":
                skip_dependent_pipeline = True
                skip_independent_pipeline = False

            triage_enabled = bool(getattr(args, "enable_triage", False)) and not bool(
                getattr(args, "skip_triage", False)
            )
            if triage_enabled:
                logging.info("--> Running blocker triage before solver dispatch")
                triage_result = run_triage_for_classifier(args, result, dependency_result, reason)
                output["triage_result"] = triage_result
                triage_action = triage_result.get("solver_action")
                triage_decision = triage_result.get("first_layer_decision")
                triage_status = triage_result.get("triage_status", "completed")
                if triage_status == "triage_error":
                    logging.warning(
                        "--> Triage failed after %s LLM attempt(s); failing open to the %s solver: %s",
                        triage_result.get("llm_attempt_count"),
                        dependency_result,
                        triage_result.get("triage_error_reason"),
                    )
                elif triage_action != "run_solver":
                    logging.info(
                        "--> Solver skipped by triage: decision=%s action=%s label=%s",
                        triage_decision,
                        triage_action,
                        triage_result.get("refined_triage_label"),
                    )
                    attempt_result = "triage_skipped" if triage_action == "skip_solver" else "triage_manual_review"
                    output["success"] = False
                    output["pipeline_skipped"] = True
                    output["pipeline_skip_reason"] = "triage_" + str(triage_action or "manual_review")
                    output["pipeline_returncode"] = 0
                    output["pipeline_methods"] = []
                    output["attempt_result"] = attempt_result
                    output["pipeline_output"] = {
                        "returncode": 0,
                        "stdout": "",
                        "stderr": "",
                        "parsed_output": {
                            "success": False,
                            "attempt_result": attempt_result,
                            "failure_stage": "triage",
                            "output_dir": triage_result.get("triage_output_dir"),
                            "summary_path": triage_result.get("triage_parsed_path"),
                            "triage_decision": triage_decision,
                            "triage_label": triage_result.get("refined_triage_label"),
                            "solver_action": triage_action,
                        },
                    }
                    return output

            if dependency_result == "Input Dependent":
                if skip_dependent_pipeline:
                    logging.info("--> Input Dependent pipeline skipped by configuration.")
                    output["pipeline_skipped"] = True
                    output["pipeline_skip_reason"] = "input_dependent_pipeline_disabled"
                    output["pipeline_returncode"] = 0
                    output["pipeline_methods"] = []
                    output["attempt_result"] = "failed"
                    return output
                logging.info("--> Routing to Input Dependent Solver (Seed Gen -> Symbolic Execution)")
                _dep_args = build_seed_generation_args(args)
                if getattr(args, "output_root", None):
                    _dep_args.extend(["--output-root", args.output_root])
                pipeline_output = run_program(
                    MODULE_ROOT / "dependent" / "input_dependent_solver.py",
                    _dep_args,
                )
                output["pipeline_returncode"] = pipeline_output["returncode"]
                output["pipeline_output"] = pipeline_output
                output["pipeline_methods"] = _infer_pipeline_methods(dependency_result, pipeline_output)
                output["attempt_result"] = infer_attempt_result(
                    dependency_result,
                    output["pipeline_returncode"],
                    pipeline_output,
                )
                return output

            if dependency_result == "Input Independent":
                if skip_independent_pipeline:
                    logging.info("--> Input Independent pipeline skipped by configuration.")
                    output["pipeline_skipped"] = True
                    output["pipeline_skip_reason"] = "input_independent_pipeline_disabled"
                    output["pipeline_returncode"] = 0
                    output["pipeline_methods"] = []
                    output["attempt_result"] = "failed"
                    return output
                logging.info("--> Routing to Input Independent Solver (Fuzz Target Refine -> New Target -> Drop)")
                _indep_args = build_input_independent_solver_args(args)
                if getattr(args, "output_root", None):
                    _indep_args.extend(["--output-root", str(Path(args.output_root) / "independent_target")])
                pipeline_output = run_program(
                    MODULE_ROOT / "independent" / "input_independent_solver.py",
                    _indep_args,
                )
                output["pipeline_returncode"] = pipeline_output["returncode"]
                output["pipeline_output"] = pipeline_output
                output["pipeline_methods"] = _infer_pipeline_methods(dependency_result, pipeline_output)
                output["attempt_result"] = infer_attempt_result(
                    dependency_result,
                    output["pipeline_returncode"],
                    pipeline_output,
                )
                return output

            raise RuntimeError(f"Unknown dependency classification: {dependency_result}")
    finally:
        cleanup_auto_context_paths(args)


def main():
    parser = argparse.ArgumentParser(description="Classify blocker via template and dispatch to appropriate program.")
    parser.add_argument("--backend", default="vertexai", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default="gemini-2.5-flash")

    parser.add_argument("--project-name", required=True)
    parser.add_argument("--function-name", default=None)
    parser.add_argument("--branch-line-number", default=None)
    parser.add_argument("--blocked-side-line-number", default=None)
    parser.add_argument("--blocker-json", default=None, help="Inline blocker JSON containing function/line/target metadata")
    parser.add_argument("--blocker-json-file", default=None, help="Path to blocker JSON file containing function/line/target metadata")
    parser.add_argument("--source-file", default=None, help="Path to source code file for blocker line lookup and optional extra context")
    parser.add_argument("--source-api-file", default=None, help="Project-relative API source path such as /src/tinyxml2/tinyxml2.cpp")
    parser.add_argument("--fuzz-file", default=None, help="Path to fuzz target code to embed")
    parser.add_argument("--header-file", default=None, help="Path to related header file to embed")
    parser.add_argument("--target-name", default=None, help="Optional fuzz target executable name used for auto-resolving fuzz target source")
    parser.add_argument("--yaml-file", default=None, help="Optional introspector exe_to_fuzz_introspector_logs.yaml path for auto call-path collection")
    parser.add_argument(
        "--skip-input-dependent-pipeline",
        action="store_true",
        default=False,
        help="Classify input-dependent blockers but do not run the input-dependent solver pipeline.",
    )
    parser.add_argument(
        "--skip-input-independent-pipeline",
        action="store_true",
        default=False,
        help="Classify input-independent blockers but do not run the input-independent solver pipeline.",
    )
    parser.add_argument(
        "--enable-triage",
        action="store_true",
        default=False,
        help="Run C/C++ blocker solvability triage as a hard gate before solver dispatch.",
    )
    parser.add_argument(
        "--skip-triage",
        action="store_true",
        default=False,
        help="Disable blocker triage even if a wrapper enabled it.",
    )
    parser.add_argument(
        "--triage-emit-prompts-only",
        action="store_true",
        default=False,
        help="Write triage prompt artifacts but do not call the LLM; triage is Inconclusive and does not gate the solver.",
    )
    parser.add_argument(
        "--triage-source-context-lines",
        type=int,
        default=25,
        help="Number of source lines around the branch and blocked side for triage evidence.",
    )
    parser.add_argument(
        "--blocker-pipeline-mode",
        choices=["dependent", "independent"],
        default=None,
        help="When set, only run the selected blocker pipeline after classification.",
    )
    parser.add_argument(
        "--max-gdb-inputs",
        type=int,
        default=0,
        help="Max corpus inputs to try when auto-collecting runtime call path. Use 0 to scan the full corpus.",
    )
    parser.add_argument("--runtime-blocker-segment-file", default=None, help="Path to the runtime blocker segment text")
    parser.add_argument("--runtime-blocker-segment-source-codes-file", default=None, help="Path to runtime blocker segment source codes")
    parser.add_argument("--cfg-call-chain-file", default=None, help="Path to CFG call chain text")
    parser.add_argument("--cfg-source-codes-file", default=None, help="Path to CFG source codes text")
    parser.add_argument("--runtime-blocker-segment", default=None, help="Inline runtime blocker segment text")
    parser.add_argument("--runtime-blocker-segment-source-codes", default=None, help="Inline runtime blocker segment source code text")
    parser.add_argument("--cfg-call-chain", default=None, help="Inline CFG call chain text")
    parser.add_argument("--cfg-source-codes", default=None, help="Inline CFG source code text")
    parser.add_argument("--runtime-collection-status", default="unknown")
    parser.add_argument("--runtime-collection-error", default="")
    parser.add_argument("--cfg-collection-status", default="unknown")
    parser.add_argument("--cfg-collection-error", default="")
    parser.add_argument("--triggering-input", default="")
    parser.add_argument("--seed", action="append", default=[])
    parser.add_argument("--max-iterations", type=int, default=3)
    parser.add_argument("--fuzz-seconds", type=int, default=15)
    parser.add_argument("--reset-corpus-per-iteration", action="store_true")
    parser.add_argument(
        "--keep-auto-context",
        action="store_true",
        help="Keep auto-resolved files under logs/auto_context instead of deleting them after the run",
    )
    parser.add_argument(
        "--classify-only",
        action="store_true",
        help="Only classify the blocker and skip downstream seed-generation / blocker-iteration pipelines",
    )
    parser.add_argument(
        "--output-root",
        default=None,
        help="Root directory for all pipeline outputs (sub-scripts write under symbolic_run/, "
             "generator/, harness/). Auto-generated under experiments/ when not specified.",
    )
    args = parser.parse_args()
    args = apply_blocker_payload(args)
    missing = [
        name
        for name, value in [
            ("function-name", args.function_name),
            ("branch-line-number", args.branch_line_number),
            ("blocked-side-line-number", args.blocked_side_line_number),
        ]
        if not value
    ]
    if missing:
        parser.error("Missing required blocker fields: " + ", ".join(missing))
    if not args.output_root and not args.classify_only:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = (args.function_name or "unknown").replace("/", "_")
        branch = args.branch_line_number or "0"
        args.output_root = str(
            Path("experiments") / f"{ts}_{args.project_name}_{fn}_{branch}"
        )
        logging.info("Auto-generated output root: %s", args.output_root)
    try:
        result = classify_blocker(args, execute_pipeline=not args.classify_only)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        sys.exit(1)
    except RuntimeError as exc:
        logging.error("%s", exc)
        sys.exit(2)
    except Exception as exc:
        logging.error("Classification failed: %s", exc)
        sys.exit(3)

    pipeline_returncode = result.get("pipeline_returncode")
    if pipeline_returncode is not None:
        sys.exit(pipeline_returncode)
    sys.exit(0)

if __name__ == "__main__":
    main()
