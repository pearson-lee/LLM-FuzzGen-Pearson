# Thesis Next 30 Days TODO

目標：不要再追求完整系統重構或完整 ground truth。接下來要交付的是一篇可防守的 minimum viable thesis：把 fuzz blocker resolution 定義成 `triage + target/seed generation`，並清楚說明哪些 blocker 適合 generation，哪些不適合。

## 最高優先原則

- [ ] Freeze 目前系統，不再大改 classifier、solver、SymCC pipeline。
- [ ] 不做完整 ground truth，只使用 `minimal_ground_truth_protocol.md` 作為 operational triage protocol。
- [ ] 不把所有 failed blockers 算成 solver failure。
- [ ] 論文主張改成：raw fuzz blockers 需要 triage，target/seed generation 只適用於 actionable blockers。
- [ ] 實驗主體改成 case-study + refined triage，不追求大規模成功率。

## 48 小時內完成

- [ ] 在論文草稿或 `TODO_MD/infer.md` 開頭寫下最終 thesis claim：

```text
本研究提出一個結合 fuzz target generation、seed generation 與 blocker triage 的 fuzz blocker resolution 方法。實驗顯示，raw fuzz blockers 中包含大量 non-actionable cases；若不先 triage，generation-based solver 會被錯誤評估。本文透過 source-level dataflow audit 與 runtime evidence 區分 actionable target gaps 與 resource/environment/internal/generated-code blockers，並分析 target/seed generation 適用的條件與限制。
```

- [ ] 決定 evaluation scope：目前只使用 `20260612_020723_run_all_fuzzer` 這 9 個 case 做主 case study。
- [ ] 把 `TODO_MD/blocker_ground_truth_labels.md` 轉成論文中的 refined triage table。
- [ ] 把 `TODO_MD/blocker_cases_20260612_analysis.md` 轉成 appendix 或 detailed case study。
- [ ] 列出論文需要的 3 張核心表：
  - [ ] Raw blocker result table。
  - [ ] Refined triage label table。
  - [ ] Representative case study table。

## 本週完成

### 實驗資料整理

- [ ] 從 `experiments/20260612_020723_run_all_fuzzer/blocker_attempts.jsonl` 整理 raw blocker table。
- [ ] 每個 case 至少列出：
  - [ ] function name。
  - [ ] branch line。
  - [ ] blocked-side line。
  - [ ] original dependency label。
  - [ ] live branch hit count。
  - [ ] live blocked-side hit count。
  - [ ] pipeline failure stage。
  - [ ] refined triage label。
  - [ ] include/exclude solver evaluation。
- [ ] 把 `pcap_compile_788`、`yy_get_next_buffer_4629`、`compute_local_ud_641`、`convert_code_r_2715`、`number_blks_r_2471` 的 source evidence 壓成 1-2 句。
- [ ] 把 `gen_prevlinkhdr_check_3149` 作為唯一 `Actionable Target Gap` 詳細描述。
- [ ] 把 `pcap_parse_2056` 作為 crash-revealing path，不算普通失敗。

### 論文架構

- [ ] Chapter 1 Introduction 草稿完成。
- [ ] Chapter 2 Background 草稿完成。
- [ ] Chapter 3 Method 先寫架構，不追細節。
- [ ] Chapter 4 Evaluation 先放表格與 case study，不等完整文字。
- [ ] Chapter 5 Discussion / Limitations 先列 bullet。

## 第二週完成

### Method 章節

- [ ] 寫清楚 pipeline：
  - [ ] Blocker extraction。
  - [ ] Input dependency classification。
  - [ ] Minimal blocker triage。
  - [ ] Seed generation。
  - [ ] Fuzz target generation。
  - [ ] Validation / revalidation。
- [ ] 定義 `resolve` 的兩種 outcome：
  - [ ] Coverage-resolving：透過 seed/target generation 覆蓋 blocked side。
  - [ ] Diagnosis-resolving：診斷為 non-actionable blocker，避免錯算 solver failure。
- [ ] 放入 minimal triage labels：
  - [ ] `Actionable Target Gap`
  - [ ] `Bounded Extreme Value`
  - [ ] `Resource-Exhaustion Guard`
  - [ ] `Environmental Failure`
  - [ ] `Internal Invariant Guard`
  - [ ] `Generated Parser State`
  - [ ] `Structurally Unreachable API Path`
  - [ ] `Infeasible Counter Overflow`
  - [ ] `Crash-Revealing Path`

### Evaluation 章節

- [ ] 不使用「全部 blocker success rate」作為主指標。
- [ ] 改用：
  - [ ] raw blockers 中 actionable / non-actionable 的比例。
  - [ ] original classifier 與 refined triage 的差異。
  - [ ] representative case studies。
  - [ ] pipeline failure reason taxonomy。
- [ ] 對 `gen_prevlinkhdr_check_3149` 寫清楚目前 generator 失敗原因：只抓到 `geneve` setter，少抓 setter 後仍會讀 `is_geneve` 的 caller / predicate sequence。

## 第三週完成

### Related Work

- [ ] 引用 fuzz blocker paper 這段觀察：
  - [ ] 大量 blockers 不是 input-dependent。
  - [ ] blockers 可分 wrong argument、missing call、missing order、unreachable、missing extreme input。
  - [ ] allocation failure 可能同時像 input-dependent 與 input-independent。
- [ ] 對應到你的 refined labels。
- [ ] 寫 FuzzIntrospector / fuzz blocker background。
- [ ] 寫 automated fuzz driver generation / FuzzGen / seed generation / structure-aware fuzzing。
- [ ] 寫 dynamic taint / DFSan 作為未來更強 GT 的方法，不宣稱你已完整做。

### Discussion / Threats

- [ ] 明確承認 refined triage 是 minimal source-level audit，不是大規模完整 GT。
- [ ] 說明為什麼不把 allocator failure、counter overflow、internal invariant 算成 generation failure。
- [ ] 說明 generated parser/scanner code 的限制。
- [ ] 說明未來工作：
  - [ ] DFSan taint validation。
  - [ ] allocator fault injection。
  - [ ] larger benchmark。
  - [ ] automated producer-domain analysis。

## 第四週完成

- [ ] 全文打通。
- [ ] 圖表編號與引用修完。
- [ ] Appendix 放 detailed 9-case audit。
- [ ] 把口試可能問題整理成 Q&A。
- [ ] 檢查所有 claim 是否都有 evidence。
- [ ] 不再新增實驗，只修文字與表格。

## 最少需要的圖表

- [ ] Figure：整體 pipeline。
  - Blocker extraction -> dependency classification -> triage -> seed/target generation -> validation。
- [ ] Table：raw blocker results。
- [ ] Table：refined triage labels。
- [ ] Table：mapping prior fuzz blocker taxonomy to your labels。
- [ ] Table：representative case studies。

## 口試防守句

### 如果被問「為什麼你的系統很多 case 沒解出來？」

回答：

```text
這正是本研究發現的核心問題之一。raw fuzz blockers 並不等於 generation-solvable blockers。若不先 triage，系統會把 allocator failure、internal invariant、counter overflow、generated parser state 都錯當成 seed generation failure。因此本文將 blocker diagnosis 納入 resolution pipeline，並只對 actionable blockers 評估 target/seed generation。
```

### 如果被問「你的 ground truth 不完整怎麼辦？」

回答：

```text
本文沒有宣稱建立完整 ground truth，而是使用 operational triage protocol。每個 case 依 source-level dataflow、producer domain、runtime validation 與 feasibility evidence 標註。這足以支撐本研究的目的：區分哪些 blockers 適合作為 generation target，哪些不應納入 solver evaluation。
```

### 如果被問「這樣還算 resolving fuzz blockers 嗎？」

回答：

```text
本文中的 resolve 包含兩種結果：一種是透過 target/seed generation 覆蓋 actionable blocked side；另一種是診斷該 blocker 不適合 input-generation-based solving，避免把 non-actionable branch 誤算為 solver failure。這對 fuzz blocker workflow 本身是必要的一步。
```

## 不要做

- [ ] 不要重寫 classifier。
- [ ] 不要重跑大規模實驗。
- [ ] 不要新增更多 project。
- [ ] 不要嘗試完整 DFSan ground truth。
- [ ] 不要把所有 dependent case 都硬說成可解。
- [ ] 不要把 allocator/OOM/counter overflow 當一般 seed-generation target。
- [ ] 不要為了追求漂亮成功率改動核心 pipeline。

## 每日最小進度

每天只問三件事：

- [ ] 今天是否讓論文多完成一個表、一節、或一段可直接使用的文字？
- [ ] 今天是否避免了不必要的系統重構？
- [ ] 今天是否把一個 claim 接上了 source/log evidence？
