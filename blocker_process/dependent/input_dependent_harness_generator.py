#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from blocker_process.dependent.build_context import reconstruct_build_context
from external.oss_fuzz import OSSFuzz
import config.config as config

try:
    from json_repair import repair_json
except Exception:
    repair_json = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

OUTPUT_ROOT = MODULE_ROOT / "generated_harnesses"
TEMPLATE_BY_MODE = {
    "symcc": REPO_ROOT / "prompts" / "templates" / "symcc_harness_generator_template",
}


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def read_optional_file(path_str: str | None) -> str:
    if not path_str:
        return "N/A"
    path = Path(path_str)
    if not path.exists() or not path.is_file():
        return "N/A"
    text = load_text(path)
    return text if text else "N/A"


def clip_text(text: str, max_chars: int = 12000) -> str:
    if not text or text == "N/A":
        return "N/A"
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}\n\n... [truncated {omitted} characters] ..."


def resolve_text(file_path: str | None, inline_text: str | None, default: str = "N/A") -> str:
    if file_path:
        text = read_optional_file(file_path)
        if text != "N/A":
            return text
    if inline_text:
        return inline_text
    return default


def sanitize_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-") or "unknown"


def extract_line_range_from_file(path_str: str | None, start_line: int, end_line: int) -> str:
    if not path_str or start_line <= 0 or end_line < start_line:
        return "N/A"

    path = Path(path_str)
    if not path.exists():
        return "N/A"

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return "N/A"

    start = max(1, start_line)
    end = min(len(lines), end_line)
    rendered = [f"{line_no}: {lines[line_no - 1]}" for line_no in range(start, end + 1)]
    return "\n".join(rendered) if rendered else "N/A"


def extract_source_window_from_file(path_str: str | None, center_line: int, radius: int = 8) -> str:
    if not path_str or center_line <= 0:
        return "N/A"
    return extract_line_range_from_file(path_str, center_line - radius, center_line + radius)


def resolve_triggering_input(triggering_input: str) -> tuple[str, str]:
    if not triggering_input:
        return "N/A", "N/A"

    path = Path(triggering_input)
    if path.exists() and path.is_file():
        try:
            raw = path.read_bytes()
            preview = raw[:512].decode("utf-8", errors="replace")
            return str(path), preview
        except Exception:
            return str(path), "N/A"

    return "inline", triggering_input


def format_prompt(template: str, mapping: dict[str, str]) -> str:
    def repl(match: re.Match) -> str:
        key = match.group(1)
        return mapping.get(key, match.group(0))

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, template)


def extract_json(text: str) -> dict:
    if repair_json is not None:
        parsed = repair_json(text, return_objects=True)
        if isinstance(parsed, dict):
            return parsed

    candidates: list[str] = []
    if match := re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL):
        candidates.append(match.group(1))
    if match := re.search(r"(\{.*\})", text, re.DOTALL):
        candidates.append(match.group(1))
    candidates.append(text)

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    raise ValueError("Failed to parse response JSON.")


def strip_markdown_code_fence(text: str) -> str:
    stripped = text.strip()
    match = re.match(r"^```[a-zA-Z0-9_+-]*\n(?P<body>.*)\n```$", stripped, re.DOTALL)
    if match:
        return match.group("body").strip() + "\n"
    return text


def _make_repair_hint(failure_details: str, language: str | None) -> str:
    """Return an extra hint line when the error matches a known fixable pattern."""
    lang = (language or "").strip().lower()
    if lang in _C_LANGUAGE_VARIANTS and "expected identifier" in failure_details and 'extern' in failure_details:
        return (
            '\n**Hint**: The error "expected identifier or \'(\'" is caused by `extern "C"` '
            "which is C++ syntax and is **not valid in a C file**. "
            "Remove `extern \"C\"` from the function signature entirely — write "
            "`int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` with no prefix. "
            "Also replace any C++ headers (`<cstddef>`, `<cstdint>`, etc.) with their C "
            "equivalents (`<stddef.h>`, `<stdint.h>`, etc.)."
        )
    return ""


def build_harness_repair_prompt(
    base_prompt: str,
    failure_kind: str,
    failure_details: str,
    previous_harness_code: str,
    language: str | None = None,
) -> str:
    details = clip_text(failure_details or "N/A", max_chars=8000)
    previous_code = clip_text(previous_harness_code or "N/A", max_chars=16000)
    hint = _make_repair_hint(failure_details, language)
    return (
        f"{base_prompt}\n\n"
        "## Repair Task\n"
        "The previous harness attempt failed validation.\n"
        f"- Failure kind: {failure_kind}\n"
        f"- Failure details:\n{details}{hint}\n\n"
        "Revise the harness so it preserves the blocker path requirements and passes the reported failure.\n"
        "Keep the same JSON output schema as before.\n\n"
        "## Previous Harness Code\n"
        "```cpp\n"
        f"{previous_code}\n"
        "```"
    )


def sanitize_generated_harness_code(code: str) -> str:
    lines: list[str] = []
    include_re = re.compile(r'^\s*#\s*include\s+"(?P<path>/(?:src|repo)/[^"]+)"')
    for line in code.splitlines():
        match = include_re.match(line)
        if not match:
            lines.append(line)
            continue

        raw_path = match.group("path")
        normalized = raw_path.replace("\\", "/")
        rewritten = None
        if normalized.startswith("/src/"):
            rewritten = normalized[len("/src/") :]
        elif normalized.startswith("/repo/"):
            repo_relative = normalized[len("/repo/") :]
            src_marker = "/src/"
            if src_marker in repo_relative:
                rewritten = repo_relative.split(src_marker, 1)[1]
            else:
                rewritten = repo_relative.split("/")[-1]
        else:
            rewritten = normalized.split("/")[-1]

        lines.append(f'#include "{rewritten}"')
    return "\n".join(lines) + ("\n" if code.endswith("\n") else "")


def extract_prefixed_calls(code: str, prefixes: tuple[str, ...]) -> list[str]:
    calls: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
        name = match.group(1)
        if not name.startswith(prefixes):
            continue
        if name in seen:
            continue
        seen.add(name)
        calls.append(name)
    return calls


COMMON_NON_PROJECT_CALLS = {
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memmove", "memset", "memcmp",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy",
    "strchr", "strrchr", "strstr",
    "snprintf", "vsnprintf", "printf", "fprintf", "perror",
    "fopen", "fclose", "fread", "fwrite",
    "abort", "exit", "assert",
}


def extract_called_functions(code: str) -> list[str]:
    calls: list[str] = []
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
        name = match.group(1)
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        calls.append(name)
    return calls


def extract_defined_functions(code: str) -> set[str]:
    defined: set[str] = set()
    pattern = re.compile(
        r"^\s*(?:[A-Za-z_][A-Za-z0-9_*\s]*\s+)*\**\s*([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{",
        re.MULTILINE,
    )
    for match in pattern.finditer(code):
        name = match.group(1)
        if name in {"if", "for", "while", "switch"}:
            continue
        defined.add(name)
    return defined


def infer_project_prefix(name: str) -> str:
    stripped = name.lstrip("_")
    if "_" in stripped:
        return stripped.split("_", 1)[0]
    match = re.match(r"[a-z]+", stripped)
    return match.group(0) if match else stripped


def is_zero_arg_standalone_call(code: str, name: str) -> bool:
    pattern = re.compile(rf"^\s*{re.escape(name)}\s*\(\s*\)\s*;\s*$", re.MULTILINE)
    return bool(pattern.search(code))


def infer_blocker_relevant_project_calls(code: str) -> list[str]:
    defined = extract_defined_functions(code)
    called = extract_called_functions(code)

    prefix_counts: Counter[str] = Counter()
    for name in called:
        if name in defined or name in COMMON_NON_PROJECT_CALLS or name == "LLVMFuzzerTestOneInput":
            continue
        prefix = infer_project_prefix(name)
        if prefix:
            prefix_counts[prefix] += 1

    dominant_prefixes = {prefix for prefix, count in prefix_counts.items() if count >= 2}
    relevant: list[str] = []
    seen: set[str] = set()
    for name in called:
        if name in seen:
            continue
        seen.add(name)
        if name in defined or name in COMMON_NON_PROJECT_CALLS or name == "LLVMFuzzerTestOneInput":
            continue
        if infer_project_prefix(name) not in dominant_prefixes:
            continue
        if re.search(r"(Free|Delete|Destroy|Close|Release)", name):
            continue
        if is_zero_arg_standalone_call(code, name):
            continue
        relevant.append(name)
    return relevant


def summarize_fidelity_requirements(fuzz_target_code: str) -> str:
    requirements = [
        "- Keep the blocker-relevant control flow and state-building sequence close to the original fuzz target.",
        "- Remove symbolic noise only when it does not change object construction, nullability, formats, flags, or the API calls that produce the blocker state.",
        "- Do not clamp, sanitize, normalize, or replace blocker-relevant input fields unless the original fuzz target already does so.",
        "- If the original fuzz target already uses raw byte consumption instead of FuzzedDataProvider or STL wrappers, preserve that structure instead of inventing a shorter model.",
        "- Preserve format constants and execution-trigger steps that materially affect the blocker path, such as follow-up transform/evaluate calls after object creation.",
    ]

    ordered_calls = extract_prefixed_calls(fuzz_target_code, ("cms", "_cms"))
    if ordered_calls:
        rendered_calls = ", ".join(ordered_calls[:20])
        requirements.append(f"- Prefer preserving this original project API order when those calls are blocker-relevant: {rendered_calls}.")

    return "\n".join(requirements)


def extract_project_function_names(code: str) -> set[str]:
    return set(re.findall(r"(?m)^[A-Za-z_][A-Za-z0-9_*\s]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{", code))


def extract_segment_entry_api(runtime_blocker_segment: str, project_functions: set[str]) -> str | None:
    if not runtime_blocker_segment or runtime_blocker_segment == "N/A":
        return None

    for line in runtime_blocker_segment.splitlines():
        match = re.search(r"#\d+\s+([A-Za-z_][A-Za-z0-9_]*)\s+at\s+", line)
        if not match:
            continue
        function_name = match.group(1)
        if function_name == "LLVMFuzzerTestOneInput":
            continue
        if function_name in project_functions:
            return function_name
    return None


def validate_harness_semantics(
    original_code: str,
    generated_code: str,
    runtime_blocker_segment: str | None = None,
) -> list[str]:
    errors: list[str] = []

    if "LLVMFuzzerTestOneInput" not in generated_code:
        errors.append("Generated harness is missing LLVMFuzzerTestOneInput.")

    original_type_constants = sorted(set(re.findall(r"\bTYPE_[A-Za-z0-9_]+\b", original_code)))
    generated_type_constants = set(re.findall(r"\bTYPE_[A-Za-z0-9_]+\b", generated_code))
    missing_types = [item for item in original_type_constants if item not in generated_type_constants]
    if missing_types:
        errors.append(
            "Generated harness changed blocker-relevant format constants from the original fuzz target: "
            + ", ".join(missing_types)
        )

    original_has_raw_byte_flow = "FuzzedDataProvider" not in original_code and "std::" not in original_code
    generated_clamps_inputs = bool(
        re.search(r"if\s*\([^)]*(<=|>=|<|>)\s*0[^)]*\)\s*[A-Za-z_][A-Za-z0-9_]*\s*=", generated_code)
    )
    if original_has_raw_byte_flow and generated_clamps_inputs:
        errors.append(
            "Generated harness adds new input clamping/normalization that does not exist in the original fuzz target."
        )

    project_functions = extract_project_function_names(original_code)
    segment_entry_api = extract_segment_entry_api(runtime_blocker_segment or "", project_functions)
    generated_project_calls = set(infer_blocker_relevant_project_calls(generated_code))
    if segment_entry_api and segment_entry_api not in generated_project_calls:
        errors.append(
            "Generated harness dropped the runtime blocker-segment entry API required to reach the blocker: "
            + segment_entry_api
        )

    return errors


def _infer_harness_extension(language: str | None) -> str:
    lowered = str(language or "").strip().lower()
    if lowered in {"c", "c89", "c99", "c11", "c17"}:
        return ".c"
    return ".cpp"


_C_LANGUAGE_VARIANTS = {"c", "c89", "c99", "c11", "c17"}

_EXTERN_C_RE = re.compile(r'\bextern\s+"C"\s+')
_CPP_HEADER_MAP = {
    "#include <cstddef>": "#include <stddef.h>",
    "#include <cstdint>": "#include <stdint.h>",
    "#include <cstdlib>": "#include <stdlib.h>",
    "#include <cstring>": "#include <string.h>",
    "#include <cstdio>": "#include <stdio.h>",
}


def _fix_cpp_in_c_harness(code: str) -> str:
    """Remove C++-only syntax from a harness that must compile as C.

    LLMs tend to copy `extern "C"` and C++ headers from the .cpp template even
    when the project language is C.  This strips the most common offenders so
    the OSS-Fuzz native build (which uses $CC, not $CXX) does not fail with
    "expected identifier or '(' extern".
    """
    code = _EXTERN_C_RE.sub("", code)
    for cpp_hdr, c_hdr in _CPP_HEADER_MAP.items():
        code = code.replace(cpp_hdr, c_hdr)
    return code


def extract_includes_from_file(source_path: str | None) -> str:
    """Return the #include lines from the given source file as a formatted block."""
    if not source_path:
        return ""
    try:
        code = Path(source_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    includes = re.findall(r'^\s*#\s*include\s+[<"][^>"]+[>"]', code, re.MULTILINE)
    return "\n".join(includes)


def _select_compiler(language: str | None, harness_path: Path) -> str:
    suffix = harness_path.suffix.lower()
    lowered = str(language or "").strip().lower()
    if suffix in {".cc", ".cpp", ".cxx", ".c++"} or lowered in {"c++", "cpp"}:
        return "clang++"
    return "clang"


def _link_probe_source(language: str) -> str:
    if language == "c++":
        return (
            '#include <cstddef>\n'
            '#include <cstdint>\n'
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);\n'
            "int main() {\n"
            "  static const uint8_t data[1] = {0};\n"
            "  return LLVMFuzzerTestOneInput(data, sizeof(data));\n"
            "}\n"
        )
    return (
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);\n"
        "int main(void) {\n"
        "  static const uint8_t data[1] = {0};\n"
        "  return LLVMFuzzerTestOneInput(data, sizeof(data));\n"
        "}\n"
    )


def run_harness_native_build_gate(
    harness_code: str,
    args: argparse.Namespace,
    output_dir: Path,
) -> tuple[str | None, str, dict]:
    output_dir.mkdir(parents=True, exist_ok=True)
    oss_fuzz = OSSFuzz()
    native_target = oss_fuzz.save_named_target(
        args.project_name,
        harness_code,
        stem_prefix=f"llm_fuzzgen_symcc_{sanitize_name(args.function_name)}",
    )
    build_result = oss_fuzz.ensure_target_binary(args.project_name, native_target.stem, sanitizer="address")
    native_log = output_dir / "native_build_check.txt"
    native_log.write_text(
        "\n".join(
            [
                f"target_path={native_target}",
                f"target_name={native_target.stem}",
                f"success={build_result.success}",
                f"error={build_result.error}",
            ]
        ),
        encoding="utf-8",
    )
    if not build_result.success:
        oss_fuzz.remove_target(args.project_name, native_target.stem)
        return "native_build_invalid", build_result.error or "OSS-Fuzz native build failed.", {}

    binary_path = oss_fuzz.built_target_binary(args.project_name, native_target.stem)
    metadata = {
        "native_target_name": native_target.stem,
        "native_target_path": str(native_target),
        "native_address_binary": str(binary_path) if binary_path is not None else None,
    }

    sanity_seeds = [Path(path) for path in (getattr(args, "runtime_sanity_seed", None) or [])]
    if not sanity_seeds:
        metadata["runtime_sanity"] = {
            "status": "skipped",
            "reason": "No runtime sanity seeds were provided.",
        }
        return None, "", metadata

    corpus_dir = oss_fuzz.build_corpus_dir / args.project_name / native_target.stem
    if corpus_dir.exists():
        shutil.rmtree(corpus_dir)
    corpus_dir.mkdir(parents=True, exist_ok=True)

    copied_seeds: list[str] = []
    missing_seeds: list[str] = []
    for index, seed_path in enumerate(sanity_seeds):
        if not seed_path.is_file():
            missing_seeds.append(str(seed_path))
            continue
        suffix = seed_path.suffix if seed_path.suffix else ".seed"
        destination = corpus_dir / f"sanity_{index:03d}{suffix}"
        shutil.copy2(seed_path, destination)
        copied_seeds.append(str(destination))

    if not copied_seeds:
        details = "Runtime sanity check has no readable seed files."
        metadata["runtime_sanity"] = {
            "status": "failed",
            "error": details,
            "missing_seeds": missing_seeds,
        }
        (output_dir / "runtime_sanity.json").write_text(
            json.dumps(metadata["runtime_sanity"], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        oss_fuzz.remove_target(args.project_name, native_target.stem)
        return "runtime_sanity_invalid", details, {}

    sanity_seconds = max(1, int(config.BLOCKER_TARGET_RUNTIME_SANITY_SECONDS))
    started_at = time.perf_counter()
    sanity_result = oss_fuzz.run_fuzzer(
        proj_name=args.project_name,
        fuzzer_name=native_target.stem,
        seconds=sanity_seconds,
        build_fuzzer=False,
    )
    elapsed_seconds = time.perf_counter() - started_at
    sanity_error = (sanity_result.error or "").strip()
    sanity_metadata = {
        "status": "passed" if sanity_result.success else "failed",
        "success": bool(sanity_result.success),
        "sanitizer": "address",
        "seconds": sanity_seconds,
        "elapsed_seconds": elapsed_seconds,
        "seed_count": len(copied_seeds),
        "seed_paths": copied_seeds,
        "missing_seeds": missing_seeds,
        "error": sanity_error,
    }
    (output_dir / "runtime_sanity.json").write_text(
        json.dumps(sanity_metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if sanity_error:
        (output_dir / "runtime_sanity_error.txt").write_text(sanity_error, encoding="utf-8")
    if not sanity_result.success:
        oss_fuzz.remove_target(args.project_name, native_target.stem)
        details = sanity_error or "Generated harness failed the ASan runtime sanity check."
        return "runtime_sanity_invalid", details, {}

    metadata["runtime_sanity"] = sanity_metadata
    return None, "", metadata


def _try_fix_missing_include_subdirs(harness_code: str, original_code: str, error_msg: str) -> str | None:
    """
    When validation fails with 'Y.h file not found', check if original_code has '#include "X/Y.h"'
    and replace '<Y.h>' with '<X/Y.h>' in harness_code. Returns patched code or None if no fix applies.

    This handles the common LLM mistake of stripping subdirectory prefixes from includes
    (e.g. 'vpx/vpx_decoder.h' -> 'vpx_decoder.h') when the project name and subdirectory share a name.
    """
    missing_headers = re.findall(r"'([^'/]+\.h[^']*?)' file not found", error_msg)
    if not missing_headers:
        return None

    # Build basename -> full relative path from original includes ("X/Y.h" patterns only)
    subdir_map: dict[str, str] = {}
    for inc in re.findall(r'#\s*include\s+"([^"]+)"', original_code):
        if "/" in inc:
            basename = inc.rsplit("/", 1)[-1]
            subdir_map.setdefault(basename, inc)

    if not subdir_map:
        return None

    patched = harness_code
    applied = False
    for missing in missing_headers:
        basename = missing.rsplit("/", 1)[-1]
        if basename in subdir_map:
            full_path = subdir_map[basename]
            old_tok = f"<{missing}>"
            new_tok = f"<{full_path}>"
            if old_tok in patched and old_tok != new_tok:
                patched = patched.replace(old_tok, new_tok)
                applied = True

    return patched if applied else None


def _run_local_syntax_check(
    harness_path: Path,
    build_context,
    output_dir: Path,
    language: str | None,
) -> tuple[str | None, str]:
    """Run local clang syntax/compile check and return (failure_kind, details) or (None, '')."""
    compiler = _select_compiler(build_context.language or language, harness_path)
    include_dirs = [Path(path) for path in build_context.include_dirs]
    common_flags = ["-std=c++17"] if compiler == "clang++" else ["-std=c11"]
    include_flags = [flag for path in include_dirs for flag in ("-I", str(path))]

    syntax_cmd = [compiler, *common_flags, *include_flags, "-fsyntax-only", str(harness_path)]
    syntax_result = subprocess.run(
        syntax_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    syntax_log = output_dir / "syntax_check.txt"
    syntax_log.write_text(
        "COMMAND:\n" + " ".join(syntax_cmd) + "\n\nSTDOUT:\n" + syntax_result.stdout + "\nSTDERR:\n" + syntax_result.stderr,
        encoding="utf-8",
    )
    if syntax_result.returncode != 0:
        return "syntax_invalid", syntax_result.stderr.strip() or syntax_result.stdout.strip() or "Syntax check failed."
    return None, ""


def run_harness_frontend_gate(
    harness_path: Path,
    args: argparse.Namespace,
    output_dir: Path,
) -> tuple[str | None, str, dict]:
    # Always reconstruct build context so downstream SymCC can use build_context.json.
    build_context = reconstruct_build_context(
        project_name=args.project_name,
        mode="generated_harness",
        target_source=args.fuzz_file,
        branch_source=args.source_file,
        harness_source=str(harness_path),
        header_file=args.header_file,
    )
    build_context.write_json(output_dir / "build_context.json")

    # For C projects: strip C++-only syntax (extern "C", C++ headers) that LLMs
    # sometimes copy from the .cpp template, which breaks compilation with $CC.
    if (args.language or "").strip().lower() in _C_LANGUAGE_VARIANTS:
        original_code = harness_path.read_text(encoding="utf-8")
        fixed_code = _fix_cpp_in_c_harness(original_code)
        if fixed_code != original_code:
            harness_path.write_text(fixed_code, encoding="utf-8")

    # Primary gate: OSS-Fuzz native build, which uses the project's own build.sh and
    # has the correct sysroot / include paths. Avoids false failures from locally
    # missing system headers (e.g. BSD types needed by libpcap headers).
    native_failure, native_details, native_metadata = run_harness_native_build_gate(
        harness_code=harness_path.read_text(encoding="utf-8"),
        args=args,
        output_dir=output_dir,
    )
    if native_failure is None:
        return None, "", native_metadata

    # Native build failed. Run local syntax check as a supplementary diagnostic so
    # the LLM repair prompt gets a more specific clang error message.
    local_failure, local_details = _run_local_syntax_check(
        harness_path, build_context, output_dir, args.language
    )
    if local_failure is not None:
        # Prefer local clang error (more precise) combined with native build context.
        combined = f"{local_details}\n[OSS-Fuzz native build also failed: {native_details}]"
        return local_failure, combined.strip(), {}

    # Native build failed but local syntax passes — return native build error.
    return native_failure, native_details, {}


def build_prompt(args: argparse.Namespace) -> str:
    template_path = TEMPLATE_BY_MODE[args.mode]
    if not template_path.exists():
        raise FileNotFoundError(f"Template missing: {template_path}")

    fuzz_target_code = clip_text(read_optional_file(args.fuzz_file), max_chars=16000)
    header_code = clip_text(read_optional_file(args.header_file), max_chars=12000)
    source_code = clip_text(read_optional_file(args.source_file), max_chars=18000)
    branch_window = extract_source_window_from_file(args.source_file, int(args.branch_line_number))
    blocked_window = extract_source_window_from_file(args.source_file, int(args.blocked_side_line_number))
    triggering_input_path, triggering_input_preview = resolve_triggering_input(args.triggering_input)

    mapping = {
        "mode": args.mode,
        "project_name": args.project_name,
        "language": args.language or "unknown",
        "function_name": args.function_name,
        "branch_line_number": str(args.branch_line_number),
        "blocked_side_line_number": str(args.blocked_side_line_number),
        "source_file": args.source_file or "N/A",
        "fuzz_file": args.fuzz_file or "N/A",
        "fuzz_target_name": Path(args.fuzz_file).stem if args.fuzz_file else "unknown",
        "fuzz_target_code": fuzz_target_code,
        "fidelity_requirements": summarize_fidelity_requirements(fuzz_target_code),
        "header_code": header_code,
        "source_code": source_code,
        "source_api_file": args.source_api_file or "N/A",
        "branch_window": clip_text(branch_window, max_chars=5000),
        "blocked_window": clip_text(blocked_window, max_chars=5000),
        "runtime_blocker_segment": clip_text(
            resolve_text(args.runtime_blocker_segment_file, args.runtime_blocker_segment),
            max_chars=7000,
        ),
        "runtime_blocker_segment_source_codes": clip_text(
            resolve_text(
                args.runtime_blocker_segment_source_codes_file,
                args.runtime_blocker_segment_source_codes,
            ),
            max_chars=9000,
        ),
        "cfg_call_chain": clip_text(resolve_text(args.cfg_call_chain_file, args.cfg_call_chain), max_chars=7000),
        "cfg_source_codes": clip_text(resolve_text(args.cfg_source_codes_file, args.cfg_source_codes), max_chars=9000),
        "blocker_call_sites": clip_text(
            resolve_text(args.blocker_call_sites_file, args.blocker_call_sites),
            max_chars=9000,
        ),
        "triggering_input_path": triggering_input_path,
        "triggering_input_preview": triggering_input_preview,
        "template_path": str(MODULE_ROOT / "symex_harness_template.cpp"),
        "template_code": clip_text(load_text(MODULE_ROOT / "symex_harness_template.cpp"), max_chars=12000),
        "reference_target_includes": extract_includes_from_file(args.fuzz_file),
    }
    prompt = format_prompt(load_text(template_path), mapping)
    fidelity_feedback = str(getattr(args, "fidelity_repair_feedback", "") or "").strip()
    if fidelity_feedback:
        previous_harness = clip_text(
            read_optional_file(getattr(args, "previous_harness_file", None)),
            max_chars=16000,
        )
        prompt += (
            "\n\n# Previous Generated-Harness Fidelity Failure\n\n"
            "A previous simplified harness compiled and passed ASan runtime sanity, but a seed that "
            "reached the blocker branch in the original target did not reach that branch in the simplified harness. "
            "Revise the byte parsing, state construction, and API sequence so the original input contract is preserved.\n\n"
            f"Failure evidence:\n```text\n{clip_text(fidelity_feedback, max_chars=8000)}\n```\n\n"
            f"Previous harness:\n```cpp\n{previous_harness}\n```\n"
        )
    return prompt


def write_harness(output_dir: Path, harness_code: str, suggested_name: str) -> Path:
    filename = sanitize_name(suggested_name or "generated_harness.cpp")
    if "." not in filename:
        filename += ".cpp"
    target = output_dir / filename
    target.write_text(harness_code, encoding="utf-8")
    return target


def build_output_dir(args: argparse.Namespace) -> Path:
    safe_project = sanitize_name(args.project_name)
    safe_function = sanitize_name(args.function_name)
    prefix = f"{safe_project}_{safe_function}_{args.mode}_"
    candidates = sorted(path for path in OUTPUT_ROOT.glob(prefix + "*") if path.is_dir())
    return candidates[-1] if candidates else (OUTPUT_ROOT / f"{prefix}unknown")


def run_generation(args: argparse.Namespace) -> dict:
    from llm_interface.llm_client import LLMClient, new_thread_id

    prompt = build_prompt(args)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_project = sanitize_name(args.project_name)
    safe_function = sanitize_name(args.function_name)
    _output_root = Path(args.output_root) if getattr(args, "output_root", None) else OUTPUT_ROOT
    output_dir = _output_root / f"{safe_project}_{safe_function}_{args.mode}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    llm = LLMClient(backend=args.backend, model_name=args.model, temperature=args.temperature)
    llm_thread_id = new_thread_id(
        "input_dependent_harness_generator",
        args.project_name,
        args.function_name,
        args.branch_line_number,
        args.blocked_side_line_number,
        args.mode,
        output_dir,
    )
    logging.info("Harness generator LLM thread_id=%s", llm_thread_id)
    original_code = read_optional_file(args.fuzz_file)
    runtime_segment = resolve_text(args.runtime_blocker_segment_file, args.runtime_blocker_segment)
    default_filename = f"{args.mode}_harness{_infer_harness_extension(args.language)}"

    current_prompt = prompt
    response_text = ""
    parsed: dict = {}
    harness_code = ""
    harness_filename = default_filename
    validation_kind = ""
    validation_details = ""
    final_response_name = "response.txt"
    final_parsed_name = "parsed.json"
    native_build_metadata: dict = {}

    for attempt_index in range(2):
        response_text = llm.generate(current_prompt, thread_id=llm_thread_id)
        if not response_text:
            raise RuntimeError("Empty LLM response.")

        parsed = extract_json(response_text)
        harness_code = strip_markdown_code_fence(parsed.get("harness_code", ""))
        harness_code = sanitize_generated_harness_code(harness_code)
        harness_filename = parsed.get("harness_filename", default_filename)
        if "." not in harness_filename:
            harness_filename += _infer_harness_extension(args.language)
        if not harness_code:
            raise RuntimeError("LLM response did not include harness_code.")

        response_name = "response.txt" if attempt_index == 0 else f"repair_response_{attempt_index:02d}.txt"
        parsed_name = "parsed.json" if attempt_index == 0 else f"repair_parsed_{attempt_index:02d}.json"
        (output_dir / response_name).write_text(response_text, encoding="utf-8")
        (output_dir / parsed_name).write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
        final_response_name = response_name
        final_parsed_name = parsed_name

        harness_path = write_harness(
            output_dir,
            harness_code,
            harness_filename if attempt_index == 0 else f"repair_{attempt_index:02d}_{harness_filename}",
        )

        validation_kind, validation_details, native_build_metadata = run_harness_frontend_gate(
            harness_path,
            args,
            output_dir,
        )
        if validation_kind is None:
            # Static check: catch absolute Docker paths and parent-traversal paths that survived
            # sanitize_generated_harness_code() but would still fail local SymCC compilation.
            # Only flag #include "/absolute/..." and #include "../parent"; relative "sub/dir.h"
            # paths with no leading slash are allowed (may be valid project-relative includes).
            _abs_include_re = re.compile(r'^\s*#\s*include\s+"(/[^"]+|[^"]*\.\./[^"]*)"', re.MULTILINE)
            bad_includes = _abs_include_re.findall(harness_code)
            if bad_includes:
                validation_kind = "absolute_include_paths"
                validation_details = (
                    "Harness contains absolute or parent-traversal #include paths that will fail "
                    "local SymCC compilation (SymCC uses -I flags, not Docker /src/ paths). "
                    "Replace ALL such includes with angle-bracket system includes, e.g. <pcap.h>. "
                    "Offending: " + ", ".join(f'"{p}"' for p in bad_includes[:5])
                )

        if validation_kind is None:
            semantic_errors = validate_harness_semantics(
                original_code=original_code,
                generated_code=harness_code,
                runtime_blocker_segment=runtime_segment,
            )
            if semantic_errors:
                validation_kind = "semantic_invalid"
                validation_details = " | ".join(semantic_errors)

        if validation_kind is None:
            break

        # Auto-fix: if error is 'Y.h file not found', try restoring subdirectory prefix from
        # original fuzz target includes (e.g. '<vpx_decoder.h>' → '<vpx/vpx_decoder.h>')
        if attempt_index == 0 and validation_kind == "syntax_invalid" and original_code:
            patched = _try_fix_missing_include_subdirs(harness_code, original_code, validation_details)
            if patched is not None:
                patched_filename = f"autofix_{harness_filename}"
                patched_path = write_harness(output_dir, patched, patched_filename)
                fixed_kind, fixed_details, _ = run_harness_frontend_gate(patched_path, args, output_dir)
                if fixed_kind is None:
                    harness_code = patched
                    harness_filename = patched_filename
                    harness_path = patched_path
                    validation_kind = None
                    break
                # Fix didn't fully resolve; fall through to LLM repair with updated error context
                validation_details = fixed_details or validation_details

        if attempt_index >= 1:
            raise RuntimeError(f"Generated harness failed {validation_kind}: {validation_details}")

        repair_prompt = build_harness_repair_prompt(
            base_prompt=prompt,
            failure_kind=validation_kind,
            failure_details=validation_details,
            previous_harness_code=harness_code,
            language=args.language,
        )
        (output_dir / "repair_prompt_01.txt").write_text(repair_prompt, encoding="utf-8")
        current_prompt = repair_prompt

    harness_path = write_harness(output_dir, harness_code, harness_filename)

    result = {
        "success": True,
        "mode": args.mode,
        "output_dir": str(output_dir),
        "prompt_path": str(output_dir / "prompt.txt"),
        "response_path": str(output_dir / final_response_name),
        "parsed_path": str(output_dir / final_parsed_name),
        "harness_path": str(harness_path),
        "harness_filename": harness_path.name,
        "analysis_summary": parsed.get("analysis_summary", []),
        "harness_design_rationale": parsed.get("harness_design_rationale", ""),
        "validation_status": "passed",
        "native_build_target_name": native_build_metadata.get("native_target_name"),
        "native_build_target_path": native_build_metadata.get("native_target_path"),
        "native_build_address_binary": native_build_metadata.get("native_address_binary"),
        "runtime_sanity": native_build_metadata.get("runtime_sanity"),
    }
    return result


def build_failure_result(args: argparse.Namespace, attempt_result: str, error: str, validation_status: str) -> dict:
    return {
        "success": False,
        "attempt_result": attempt_result,
        "mode": args.mode,
        "output_dir": str(build_output_dir(args)),
        "validation_status": validation_status,
        "error": error,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a SymCC-friendly harness for an input-dependent blocker.")
    parser.add_argument("--mode", required=True, choices=["symcc"])
    parser.add_argument("--backend", default="vertexai", choices=["gemini", "vertexai", "openrouter", "ollama"])
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument("--branch-line-number", required=True)
    parser.add_argument("--blocked-side-line-number", required=True)
    parser.add_argument("--source-file", required=True)
    parser.add_argument("--source-api-file", default=None)
    parser.add_argument("--fuzz-file", required=True)
    parser.add_argument("--header-file", default=None)
    parser.add_argument("--language", default=None)
    parser.add_argument("--runtime-blocker-segment-file", default=None)
    parser.add_argument("--runtime-blocker-segment-source-codes-file", default=None)
    parser.add_argument("--cfg-call-chain-file", default=None)
    parser.add_argument("--cfg-source-codes-file", default=None)
    parser.add_argument("--runtime-blocker-segment", default=None)
    parser.add_argument("--runtime-blocker-segment-source-codes", default=None)
    parser.add_argument("--cfg-call-chain", default=None)
    parser.add_argument("--cfg-source-codes", default=None)
    parser.add_argument("--blocker-call-sites", default=None)
    parser.add_argument("--blocker-call-sites-file", default=None)
    parser.add_argument("--triggering-input", default="")
    parser.add_argument("--fidelity-repair-feedback", default="")
    parser.add_argument("--previous-harness-file", default=None)
    parser.add_argument(
        "--runtime-sanity-seed",
        action="append",
        default=[],
        help="Seed file to replay against the generated native harness under ASan; repeatable.",
    )
    parser.add_argument("--output-root", default=None,
                        help="Root directory under which harness output dirs are created. "
                             "Defaults to generated_harnesses/.")
    args = parser.parse_args()

    try:
        result = run_generation(args)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        print(
            json.dumps(
                build_failure_result(args, "failed", str(exc), "file_not_found"),
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(1)
    except RuntimeError as exc:
        logging.error("%s", exc)
        error_text = str(exc)
        attempt_result = "failed" if error_text.startswith("Generated harness failed ") else "llm_error"
        validation_status = "validation_failed" if attempt_result == "failed" else "llm_error"
        print(
            json.dumps(
                build_failure_result(args, attempt_result, error_text, validation_status),
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(2)
    except Exception as exc:
        logging.error("Harness generation failed: %s", exc, exc_info=True)
        print(
            json.dumps(
                build_failure_result(args, "failed", f"Harness generation failed: {exc}", "unexpected_error"),
                ensure_ascii=False,
                indent=2,
            )
        )
        sys.exit(3)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
