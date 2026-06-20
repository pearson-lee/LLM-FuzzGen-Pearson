# Blocker Selector 驗證與人工標記方式（2026-06-20）

## 這次改了什麼

新版 selector 不再把「branch hit 很多」直接當成高價值，而是分開計算：

```text
score = reach_confidence × coverage_benefit × solvability_score
```

- `reach_confidence`：branch 確實可達，但 hit 超過門檻後就飽和，不再重複獎勵幾百萬次 hit。
- `coverage_benefit`：主要看 blocked side 後方尚未覆蓋的 unique complexity 與 `unlock_ratio`。
- `solvability_score`：只有 deterministic strong evidence 才重降權。這輪 Resource Guard 的 strong evidence 是「同一變數接收 call result、同一變數被 NULL check，而且 blocked side 明確是 OOM/ENOMEM/allocation failure」；普通 nullable API 保持 unknown，不降權。
- source evidence pool 改成「舊分數前 20 名 + coverage benefit 前 10 名」，避免高效益但不夠 hot 的 blocker 根本沒被檢查。

這些規則不使用 LLM、不 hard reject blocker，也不依賴 `_cmsMalloc`、`xmalloc` 等 project-specific 名稱。

## 先跑自動測試

```bash
PYTHONPATH=. .venv/bin/pytest -q unitest/test_global_blocker_selector.py
.venv/bin/python -m py_compile \
  blocker_process/global_blocker_selector.py \
  tools/replay_blocker_selector.py \
  tools/summarize_blocker_selector_audit.py
```

測試確認：

- 單字元 `p` 與 `(TYPE*)` cast 可以被辨識。
- `!p`、`p == NULL`、`NULL == p`、`p == nullptr` 可關聯同一變數。
- 有 OOM strong evidence 才降到 `0.25`。
- 一般 `get_optional_config(); if (!p)` 不會被誤降權。
- comments 內的假訊號不會被當成 evidence，但 string literal 內的 OOM 訊息會保留。
- reach score 有 0.5 floor，並在 threshold 飽和。

## Offline replay

目前 replay 已產生在：

```text
TODO_MD/blocker_selector_replay_20260620/
├── replay_report.json
├── new_ranking.json
└── manual_audit.csv
```

重跑 command：

```bash
.venv/bin/python tools/replay_blocker_selector.py \
  experiments/20260618_213959_run_all_fuzzer/branch_blockers/lcms_initial_introspector_refresh.json \
  --project-name lcms \
  --output-dir TODO_MD/blocker_selector_replay_20260620 \
  --thresholds 10000 100000 \
  --production-threshold 100000 \
  --known-success cmsDetectBlackPoint:267:0 \
  --known-success _cmsReadDevicelinkLUT:745:0 \
  --known-success cmsDeleteContext:979:0 \
  --known-success cmsWriteTag:1787:0 \
  --known-success AddMLUBlock:150:0
```

目前可先確認的結果：`AddToList:1274` 從舊排名第 6 降到第 42，並留下 `p <- AllocChunk`、`p == NULL`、`out of memory` 三段可追溯證據。這只證明該 case 被修正，不能直接代表整體 selector 正確；整體判斷要完成下面的人工 audit。

## 人工標記怎麼做

打開 `manual_audit.csv`。它只包含 old top-20 與 new top-20 的 union，目前共 28 列，不需要人工看全部 424 個 blocker。

每一列先讀：

1. `branch_context`：誰產生值、branch 在檢查什麼。
2. `blocked_side_context`：進入 blocked side 後實際做什麼。
3. `evidence_*`：程式抓到的變數、callee 與 resource 字串。這是「待驗證預測」，不能直接照抄成答案。
4. context 不足時，再依 `source_file` 與行號開完整 source。

只填三個 label：

### `resource_guard`

blocked side 明確是在處理 allocation/resource failure，例如同一 pointer 接收配置結果後被 NULL check，失敗側回報 OOM、ENOMEM 或 allocation failure。重點是正常 legal input 不能可靠製造這個 failure。

範例：

```c
p = AllocChunk(...);
if (p == NULL) {
    error("out of memory");
    return NULL;
}
```

### `non_resource_nullable`

雖然有 NULL/error check，但 NULL 是正常 API/input 語意的一部分，可以由合法 input、缺少資料或 API state 造成，不是 allocator failure。

範例：

```c
cfg = find_optional_config(input);
if (cfg == NULL)
    use_default_config();
```

### `unknown`

局部 source 無法證明是哪一種，或 call 的 definition/資料流不清楚。不要猜；unknown 會被保留，不會當成 Resource Guard。

另外填：

- `manual_reason`：一行事實依據，例如 `p comes from AllocChunk; blocked side reports out of memory`。
- `reviewer`：標記者名稱。

人工標記時不要看 `old_rank/new_rank` 決定 label，也不要因為 `evidence_grade=strong` 就直接標 `resource_guard`，否則會變成用規則驗證自己。

## 填完後算指標

```bash
.venv/bin/python tools/summarize_blocker_selector_audit.py \
  TODO_MD/blocker_selector_replay_20260620/manual_audit.csv \
  --top-k 10 20 \
  --output TODO_MD/blocker_selector_replay_20260620/audit_report.json
```

主要看四個值：

- `strong_evidence_precision`：被程式重降權的 strong cases 中，人工確認真的是 Resource Guard 的比例。這個 audit set 應追求 `1.0`。
- `resource_guard_recall`：人工找到的 Resource Guard 有多少被 strong rule 抓到。漏判可以接受，因為漏判只是不降權；誤判會把可解 blocker 壓下去，風險更高。
- `false_downrank_count`：strong rule 卻被人工標成 `non_resource_nullable` 的數量。目標是 `0`。
- `unknown_count`：現有 source context 不足的數量，必須如實保留，不能硬算對或錯。

再比較 `old_resource_guard_count` 與 `new_resource_guard_count`：新版 top-10/top-20 裡的 Resource Guard 應下降，同時 `replay_report.json` 中已知成功 blocker 不應整批被移出前段。低 benefit 的已知成功 blocker排名下降不一定是錯，因為目標不是單純最大化成功數，而是優先選「可解且解開後有較高 coverage benefit」的 blocker。

## 通過標準與下一步

先不要直接跑 24 小時。這輪通過條件是：

1. unit tests 全過。
2. `false_downrank_count = 0`，Strong precision 在已決定案例為 `1.0`。
3. AddToList 類已知 OOM guard 明顯降名。
4. known-success blockers 沒有因 hotness saturation 全面消失；個別低 benefit case 可下降，但要在報告寫明原因。
5. 10k/100k threshold 的 top ranking 不應劇烈翻轉；目前 production 暫用 100k，最後依 audit 結果決定是否保留。

通過後依序做：focused short run → 未參與規則設計的 held-out project short run → 最後才做 24hr A/B。Triage 維持 optional，不是這份 deterministic selector 的必要條件。
