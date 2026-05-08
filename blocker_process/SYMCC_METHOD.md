# SymCC Blocker-Solving Method

## Goal

For a blocker that is `input-dependent` relative to a current fuzz target, use
one or more seeds that already reach the blocker branch line and ask SymCC to
produce a new seed that flips the blocked side.

This method treats blocker solving as a project-level coverage task. The output
may be:

- a new seed for the original fuzz target, or
- a new `symex-compatible` harness that can itself be treated as a project fuzz
  target.

## When To Use SymCC

Use SymCC when all of the following hold:

- the blocker has already been classified as `input-dependent` for the current
  fuzz target;
- there is at least one seed that reaches the blocker branch line;
- LLM seed generation did not solve the blocker.

Do not start from SymCC if there is no seed that reaches the blocker branch.

## Input Model

The recommended SymCC input model is always:

1. read a concrete seed from file;
2. replay the seed through a harness that exposes
   `LLVMFuzzerTestOneInput(const uint8_t*, size_t)`;
3. let SymCC run concolically from that seed.

## Two Execution Modes

### Mode A: Original fuzz target

Use this mode only if the current fuzz target is a clean replay target:

- raw bytes go directly into the library API;
- no heavy `std::string` / STL wrapping around the input;
- no `FuzzedDataProvider`;
- no multi-stage input unpacking.

This is the lowest-cost option.

### Mode B: Symex-compatible harness

Use this mode when the original fuzz target is not a good SymCC entry because
of STL, `FuzzedDataProvider`, or complex pre-processing.

Requirements for the harness:

- no STL container or `std::string` in the input path if avoidable;
- no `FuzzedDataProvider`;
- copy input bytes with `memcpy`;
- call a short, reasonable API path that can still reach the blocker;
- keep the input format compatible with the intended project-level target.

This harness is still a fuzz target. If it is reasonable and reaches the
project blocker, the blocker can be treated as solved at the project level.

## Validation Rule

SymCC output is not accepted just because a seed was generated. A generated seed
must be replayed with coverage instrumentation and must hit:

- the blocker branch line, and
- the blocked-side line.

If coverage does not improve, the run is classified as one of:

- `stalled`
- `bad_harness`
- `not_symcc_suitable`

## Existing Tooling In This Repo

Use [symcc_blocker_solver.py](/home/kyliechien/LLM-FuzzGen/blocker_process/symcc_blocker_solver.py:1)
as the main SymCC driver. It already does the following:

- builds a replay driver around a fuzz target source file;
- builds a SymCC binary and a coverage binary;
- replays initial seeds through SymCC;
- collects generated seeds from `SYMCC_OUTPUT_DIR`;
- replays the full corpus with coverage and checks whether the blocked side was
  reached.

## Recommended Operational Flow

1. Find a blocker in project coverage.
2. Pick a current fuzz target that reaches the blocker branch line.
3. Collect one or more seeds that hit the branch line but not the blocked side.
4. Ask the classifier whether the blocker is `input-dependent` for this target.
5. Try LLM seed generation first.
6. If it fails, choose:
   - Mode A if the current fuzz target is SymCC-friendly;
   - Mode B if the current fuzz target has STL / FDP / complex unpacking.
7. Run `symcc_blocker_solver.py`.
8. Accept the result only if coverage confirms the blocked side was reached.

## Minimal Command Shape

```bash
python3 blocker_process/symcc_blocker_solver.py \
  --fuzz-target /path/to/fuzz_target_or_symex_harness.cpp \
  --source /path/to/project_source.cpp \
  --include-dir /path/to/include \
  --branch-source /path/to/project_source.cpp \
  --branch-line 426 \
  --blocked-side-line 429 \
  --seed /path/to/seed.bin
```

## TinyXML2 Example

```bash
python3 blocker_process/symcc_blocker_solver.py \
  --fuzz-target /home/kyliechien/LLM-FuzzGen/blocker_process/xmltest.cpp \
  --source /home/kyliechien/LLM-FuzzGen/blocker_process/tinyxml2.cpp \
  --include-dir /home/kyliechien/LLM-FuzzGen/blocker_process \
  --branch-source /home/kyliechien/LLM-FuzzGen/blocker_process/tinyxml2.cpp \
  --branch-line 426 \
  --blocked-side-line 429 \
  --seed /home/kyliechien/LLM-FuzzGen/blocker_process/seed_reach426.xml
```
