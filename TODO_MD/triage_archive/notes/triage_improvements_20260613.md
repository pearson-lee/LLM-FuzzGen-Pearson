# Triage Module Improvements — 2026-06-13

> 後續 review 已將 1c 的「矛盾修正」改成 deterministic label routing：LLM 只選
> `refined_triage_label`，程式固定推導 `first_layer_decision` 與 `solver_action`。
> `Inconclusive` 與 `triage_error` 採 fail-open，不再因證據不足或 LLM 格式錯誤跳過 solver。

## Background

`TODO_MD/triage_decisions_all.jsonl` (generated with an earlier template) showed first-layer
accuracy of 5/9 (56%) on the libpcap retrospective dataset.  Four false positives
(Generation-solvable when ground truth is Non-generation-solvable) were analysed and three
targeted fixes were made.  Final accuracy after fixes: **7/9 (78%)**.

---

## Changes Made

### 1. `blocker_process/blocker_triage.py`

#### 1a. Remove Flex-specific token exception in `extract_source_identifiers()`

**Before**
```python
if len(token) < 4 and not token.startswith("yy"):
    continue
```

**After**
```python
if len(token) < 4:
    continue
```

**Why**: The `yy` exception was a Flex-specific optimisation that had no benefit in practice
(all meaningful Flex variables such as `yy_fill_buffer`, `yyerrstatus` are ≥ 4 chars and
would have been kept anyway).  Removing it makes the function fully C/C++-generic.

---

#### 1b. Graceful fallback when LLM returns unparseable JSON in `run_triage_prompt()`

**Before**
```python
parsed = normalize_triage_result(extract_json_object(response_text), response_text=response_text)
```

**After**
```python
try:
    parsed = normalize_triage_result(extract_json_object(response_text), response_text=response_text)
except Exception as exc:
    logging.warning("Triage JSON parse failed: %s", exc)
    parsed = default_inconclusive(f"JSON parse error: {exc}")
    parsed["response_text"] = response_text
```

**Why**: Without the try/except, an LLM response with unparseable JSON would raise an
unhandled exception and crash the classifier pipeline.  With the fallback, the blocker is
marked `Inconclusive / manual_review` and the pipeline continues to the next blocker.

---

#### 1c. Label → first_layer consistency constraint in `normalize_triage_result()`

**Added** (after the existing Non-gen + run_solver guard):
```python
NON_GEN_LABELS = {
    "Resource-Exhaustion Guard",
    "Environmental Failure",
    "Internal Invariant Guard",
    "Generated Parser State",
    "Structurally Unreachable API Path",
    "Infeasible Counter Overflow",
    "Crash-Revealing Path",
}
if label in NON_GEN_LABELS and first_layer == "Generation-solvable":
    first_layer = "Non-generation-solvable"
```

**Why**: The LLM occasionally outputs a semantically contradictory pair such as
`Generation-solvable + Resource-Exhaustion Guard`.  Resource-Exhaustion Guard, Environmental
Failure, Internal Invariant Guard, etc., are by definition non-solvable by input/target
generation.  This guard corrects the contradiction without discarding the label chosen by
the LLM.

**Effect on newchunk_642**: LLM correctly labelled `Resource-Exhaustion Guard` but set
`first_layer = Generation-solvable`.  The guard corrects this to `Non-generation-solvable /
skip_solver` — matching the manual label.

---

### 2. `prompts/templates/blocker_triage_template`

#### 2a. Generalise Rule 7 (remove Bison/Flex hardcoding)

**Before**
```
7. For generated Bison/Flex parser/scanner states, do not infer solvability from
   generic parser behavior alone. Choose `Generated Parser State` or
   `Structurally Unreachable API Path` unless the provided source shows a visible
   legal public transition that sets the required state and survives to the
   blocked-side read.
```

**After**
```
7. For internal parser or scanner state variables managed by generated code or
   opaque internal transitions, do not infer solvability from generic parser
   theory alone. Choose `Generated Parser State` or `Structurally Unreachable
   API Path` unless the provided source shows a visible legal public transition
   that sets the required state and persists to the blocked-side read.
```

**Why**: The original wording named Bison/Flex explicitly, violating the C/C++-generic
requirement.  The new wording describes the general category (generated or opaque internal
transitions) without referencing specific tools.

---

#### 2b. Rewrite Rule 5 (control nesting → execution reachability)

**Before**
```
5. Always verify control nesting before accepting a proposed path. If the
   classifier claims an earlier value such as zero can reach a branch, but the
   branch is nested inside a guard that excludes that value, source evidence must
   override the classifier.
```

**After**
```
5. Before accepting any proposed path to the blocked side, verify that execution
   actually reaches blocked-side line {blocked_side_line_number}. When an
   enclosing `if`, `for`, or `while` condition evaluates to false, ALL lines
   inside that block's `{}` are skipped — including any nested `if` branches
   within it. A condition being satisfiable (e.g., `!ptr == true`) does not
   prove the line is reachable if that line is inside a block whose own guard
   is not entered. Use the step "[1b. Enclosing-block reachability]" to make
   this check explicit before proceeding.
```

**Why**: The old rule told the LLM to "verify nesting" but did not explain the execution
semantics — the LLM still made the error of saying "slen=0 → offset stays NULL → line 2715
reachable," not realising that when `if (slen)` is false the entire block including line
2715 is skipped.  The new rule makes the skip-semantics explicit.

---

#### 2c. Add mandatory step 1b to analysis_trace schema

**Before** (Output Strict JSON section):
```json
"analysis_trace": [
  "[1. Source-first blocker interpretation]: ...",
  "[2. Required blocked-side condition]: ...",
  "[3. Solvability evidence]: ...",
  "[4. Classifier conflict check]: ...",
  "[5. Triage decision]: ..."
],
```

**After**:
```json
"analysis_trace": [
  "[1. Source-first blocker interpretation]: ...",
  "[1b. Enclosing-block reachability]: List every if/for/while condition visible in the source snippet that encloses blocked-side line {blocked_side_line_number}. For each proposed path, state whether that enclosing condition is entered (true) or skipped (false). Eliminate any path where an enclosing block is not entered — the blocked-side line is not executed in that case.",
  "[2. Required blocked-side condition]: ...",
  "[3. Solvability evidence]: ...",
  "[4. Classifier conflict check]: ...",
  "[5. Triage decision]: ..."
],
```

**Why**: Rule 5 references step 1b.  Making it a named, required step in the schema forces
the LLM to perform the enclosing-block check before reasoning about solvability, rather than
skipping it.

**Effect on convert_code_r_2715**: With step 1b, the LLM correctly wrote:
> "if `slen == 0`, the `if (slen)` block (lines 2713–2719) is skipped, and the `if (!offset)`
> check at line 2715 is not executed."
First-layer correctly changed from Generation-solvable to **Non-generation-solvable /
Resource-Exhaustion Guard**.

---

## Result Summary

| Case | Before | After | Fix |
|------|--------|-------|-----|
| convert_code_r_2715 | Gen-solvable ❌ | **Non-gen ✅** | Step 1b (nesting verification) |
| newchunk_642 | Gen-solvable ❌ | **Non-gen ✅** | normalize label→first_layer constraint |
| compute_local_ud_641 | Gen-solvable ❌ | Gen-solvable ❌ | Requires upstream BPF validation knowledge not in source snippet — documented limitation |
| pcap_parse_3594 | Gen-solvable ❌ | Gen-solvable ❌ | Requires Bison grammar YYABORT behaviour knowledge — documented limitation |

**First-layer accuracy: 5/9 → 7/9 (56% → 78%)**

The two remaining false positives both require reasoning about behaviour that is not visible
in the local source snippet (upstream compiler validation for compute_local_ud; grammar-level
error recovery semantics for pcap_parse).  These are documented as limitations of
LLM-based triage that relies solely on source snippets without whole-program analysis.

---

## Commands to Re-run Full Triage with Updated Code/Template

```bash
# Full 9-case re-run (uses updated template + normalize)
.venv/bin/python blocker_process/blocker_triage.py \
  --attempts-jsonl experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl \
  --blocker-json-path experiments/20260612_020723_run_all_fuzzer/branch_blockers/libpcap_initial_introspector_refresh.json \
  --manual-labels-csv TODO_MD/blocker_ground_truth_labels.csv \
  --project-name libpcap \
  --backend vertexai \
  --model gemini-2.5-flash \
  --output-jsonl TODO_MD/triage_decisions_v2.jsonl \
  --save-prompts-dir TODO_MD/triage_prompts_v2_final
```
