# LLM-FuzzGen

A Large Language Model-based Fuzzing Target Generator.

## System Requirements
- ubuntu 22.04
- python 3.11.11 
- docker

## Installation

### 1. Clone the repository:
```bash
git clone https://github.com/pei-lun-chien/LLM_FuzzGen_Seed.git
cd LLM-FuzzGen
```

### 2. Set up Python environment:
```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

### 3. Run the installation script:
```bash
chmod +x setup.sh
./setup.sh
```

### 4. Set up environment variables (`GOOGLE_API_KEY` and optional LangSmith)
```bash
# ptrace for GDB trace code
sudo sysctl kernel.yama.ptrace_scope=0
# API KEY
export GOOGLE_API_KEY="YOUR_API_KEY"
# Optional: For LangSmith tracing
# export LANGSMITH_TRACING=true
# export LANGSMITH_API_KEY="<your-langsmith-api-key>"
```

Replace `"YOUR_API_KEY"` with your actual Google API key.
### 5. Modify config.yaml

### 6. Run main.py
```bash
python ./main.py tinyxml2
```

## SymCC Environment

This project may use SymCC in the blocker-solving pipeline.

There are two supported setup modes:

1. Regular SymCC
   - For normal C/C++ symbolic execution without STL-internal tracing.
2. SymCC with instrumented libc++
   - Required when symbolic tracing must continue through STL operations such as `std::string`, `std::vector`, `std::map`, and `std::unordered_map`.

Documentation:

- `docs/setup_symcc.md`
- `docs/setup_symcc_stl.md`
- `docs/integration_blocker_system.md`

Quick notes:

- The STL-instrumented flow is currently tracked against `llvmorg-14.0.6`.
- Do not commit LLVM source trees, SymCC build directories, or instrumented libc++ install artifacts into Git.

## Analyze Saved Crash Seeds

Analyze `crash_seeds` saved under one or more experiment directories with the
repository CrashAnalyzer. By default only `artifact_kind=crash` is analyzed;
`slow-unit`, timeout, and OOM artifacts are not mixed into TP/FP counts.

```bash
export VERTEXAI_PROJECT_ID="YOUR_GCP_PROJECT_ID"
export VERTEXAI_LOCATION="us-central1"

.venv/bin/python tools/analyze_experiment_crashes.py \
  experiments/20260720_replay_current_corpus \
  experiments/20260724_025850_cjson \
  experiments/20260726_231453_libvpx \
  --llm vertexai \
  --model gemini-2.5-pro \
  --build
```

Use `--dry-run` first to list valid inputs without Docker or LLM calls. Results
are written to `experiments/<timestamp>_crash_analysis/`: `summary.md`,
`summary.json`, and `results.csv` contain per-experiment TP/FP/TBD totals,
while `artifacts/` contains each full analysis report and reproduced stack
trace.
