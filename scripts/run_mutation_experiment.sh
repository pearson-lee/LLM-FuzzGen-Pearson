#!/usr/bin/env bash
# Mutation-mode experiment: does starting from a known-valid base seed beat fresh synthesis?
#
# Why this experiment exists
# --------------------------
# Across the six archived campaigns, 62 blockers reached the LLM seed generator and exactly
# one produced a seed that crossed the blocked side (lcms SetDataFormat:1675). Reading the
# branch conditions of all 62 and the seeds that were actually generated points at a single
# pattern: the seeds are "predicate-shaped" but not "format-valid". They encode the target
# condition yet are 3-101x smaller than a seed known to reach the branch, so they never
# survive the parsing and validation that sits upstream of the predicate. The one success is
# the case where the predicate *is* a surface property of the input (an IT8 text file that
# lists more fields than it declares) -- no container structure to get right.
#
# Mutation mode starts from the triggering seed, which reaches the branch by construction,
# and spends its edit budget only on the predicate. That is the direct counter to the
# observed failure mode. It has never been run: DEFAULT_SEED_GENERATION_MODE is "fresh" and
# `--seed-generation-mode` appears zero times in every archived run.log.
#
# Reading the results
# -------------------
# The outcome to look at is `blocked_side_hit_count` in each iteration's
# representative_results.json, or "Generated family reached blocked side" in evaluation.txt.
#
# Two of these cases have known expected outcomes and are here as controls:
#   * lcms SetDataFormat:1675 already solved under fresh -- mutation must also solve it,
#     otherwise mutation has regressed.
#   * zlib gzwrite:251 is unreachable through its harness: gzwrite() returns at the
#     `file == NULL` check on line 241, before the `(int)len < 0` check on line 251, and the
#     only call carrying a controllable len needs FDP_get_data(2^31) -- a 2GB input. No seed
#     can solve it; a failure here means nothing.
#
# Caveat on comparing against the archive: the archived fresh runs predate the branch
# attribution fix, so labels differ. The `blocked_side_hit_count` measurement itself did not
# change, so the binary "did any seed cross" comparison stays valid.
#
# Quota
# -----
# These prompts are ~68KB. Vertex AI has been returning 429 ResourceExhausted on prompts
# that size while a 20-token probe passes, which suggests a token-per-minute rather than a
# request-per-minute limit -- so a successful small probe does NOT mean these will run. Each
# case is a separate command on purpose: run them one at a time and stop if 429s appear,
# rather than losing a batch to a retry loop.

set -u
cd "$(dirname "$0")/.."
REPLAY=scripts/replay_blocker_seed_generation.py
PY=.venv/bin/python3

# --stage solver replays the production input_dependent_solver.py command recovered from the
# archived run.log, so seed generation AND SymCC both run, exactly as in a normal campaign.
# Use --stage seedgen instead to test seed generation alone (faster, no SymCC).
STAGE="${STAGE:-solver}"
MODE="${MODE:-mutation}"

run_case() {
  local experiment="$1" blocker="$2" note="$3"
  echo
  echo "=============================================================="
  echo "### $blocker   ($note)"
  echo "=============================================================="
  $PY "$REPLAY" \
      --stage "$STAGE" \
      --experiment "$experiment" \
      --blocker "$blocker" \
      --seed-generation-mode "$MODE" \
      --run
}

# --------------------------------------------------------------------------------------
# Group C: seeds already reached the branch. Tests whether the predicate can be satisfied.
# --------------------------------------------------------------------------------------
c_group() {
  run_case experiments/20260720_232522_libpcap  gen_scode:7419 \
    "needs lookup_proto >= 0; reached 6x under fresh, never satisfied"
  run_case experiments/20260717_180129_libtiff  _TIFFCastUInt64ToSSize:86 \
    "needs a BigTIFF field > 2^63-1; strategy was right, value never exceeded the bound"
  run_case experiments/20260726_231453_libvpx   vpx_free_frame_buffer:138 \
    "needs a frame buffer to have been allocated, i.e. a genuinely decodable stream"
}

# --------------------------------------------------------------------------------------
# Group B: seeds never reached the branch, and were 15-101x smaller than the reference.
# This is where mutation should help most -- the failure mode is format validity, which is
# exactly what starting from a valid base seed preserves.
# --------------------------------------------------------------------------------------
b_group() {
  run_case experiments/20260726_231453_libvpx   setup_frame_size_with_refs:1596 \
    "reference 8002 bytes vs generated 72-86 -- 101x gap"
  run_case experiments/20260726_231453_libvpx   vp9_receive_compressed_data:428 \
    "reference 533 bytes vs generated 14-21 -- 30x gap"
  run_case experiments/20260726_231453_libvpx   setup_frame_size_with_refs:1563 \
    "reference 924 bytes vs generated 48-57 -- 17x gap"
}

# --------------------------------------------------------------------------------------
# Controls. Expected outcomes are known, so these calibrate the rest.
# --------------------------------------------------------------------------------------
controls() {
  run_case experiments/20260707_000202_lcms     SetDataFormat:1675 \
    "POSITIVE control: fresh already solved this; mutation must too"
  run_case experiments/20260714_035206_zlib     gzwrite:251 \
    "NEGATIVE control: harness-unreachable, no seed can solve it"
}

case "${1:-help}" in
  c)        c_group ;;
  b)        b_group ;;
  controls) controls ;;
  all)      controls; c_group; b_group ;;
  *)
    cat <<'EOF'
Usage: scripts/run_mutation_experiment.sh {c|b|controls|all}

  c         3 cases whose seeds already reached the branch
  b         3 cases whose seeds were 17-101x too small
  controls  1 known-solvable + 1 known-unsolvable, to calibrate the rest
  all       controls, then c, then b

Environment:
  STAGE=solver|seedgen   default solver (full pipeline incl. SymCC)
  MODE=mutation|fresh    default mutation

Run a matched fresh arm for a clean comparison under today's code:
  MODE=fresh scripts/run_mutation_experiment.sh c

Inspect results:
  grep -E "Iteration status|Generated family reached blocked side" \
       replays/*/generated/**/evaluation.txt
EOF
    ;;
esac
