# llm-as-judge FP cases

This directory stores local FP cases selected from `experiments/20260702_224826_run_all_fuzzer` for crash analyzer LLM-as-judge calibration.

Layout:

- `primary/`: high-confidence FP cases recommended for the main calibration pass.
- `optional_candidates/`: usable but lower-confidence or lower-representativeness FP candidates.
- `validation_cases.json`: compact index of all cases.

- `judge_inputs.json`: label-free index intended for judge prompts.
- Per-case `judge_input.json`: label-free case evidence pointer file.

Each case directory contains:

- `metadata.json`: human labels, provenance, crash summary, corpus recovery details.
- `judge_input.json`: label-free evidence pointers for judge prompts.
- `target.c`: generated fuzz target source used for the crash.
- `crash.log`: ANSI-stripped full run_fuzzer log.
- `full_run_fuzzer.log`: original run_fuzzer log, copied verbatim.
- `run_log_excerpt.log`: excerpt from the experiment-level `run.log`.
- `runtime_sanity.json`: runtime sanity artifact from blocker generation.
- `target_quality_report.json`: blocker target quality report.
- `prompt_attempt_02.txt`: prompt artifact that preserves context and crash excerpt.
- `corpus/`: reconstructed crash testcase decoded from the `Base64:` line in `full_run_fuzzer.log`.

Important: `metadata.json` contains human labels (`label`, `label_reason`, `confidence`, `usage`). Do not pass those fields to the judge prompt. They are for evaluation and audit only.
