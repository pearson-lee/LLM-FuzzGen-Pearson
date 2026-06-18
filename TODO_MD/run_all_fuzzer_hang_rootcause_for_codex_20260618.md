# run_all_fuzzer「跑一跑卡死」根因對齊（給 Codex）— 2026-06-18

> 我查了 `experiments/20260617_194433_run_all_fuzzer/run.log` 與 `external/oss_fuzz.py` / `main.py`，
> 結論與你的 quarantine 方向**不同**。請對齊根因後再決定修法順序。

## 1. log 證據：不是 OOM 殺程序、不是 scheduler 沒收尾，是 hang 卡死

run.log 結尾關鍵序列：
```
15:05:21  Fuzzer llm_fuzzgen0625181935 ran successfully      # 最後一次正常事件
（中間最後 dispatch 的是 llm_fuzzgen0625200241 的 docker run，它 OOM 後 container 沒退出）
… 5 小時完全靜止 …
20:21:06  ERROR Failed to complete fuzzing for lcms
          Traceback … future.result() … KeyboardInterrupt    # 使用者自己按 Ctrl-C
20:21:09  Fuzzing interrupted by user. Shutting down...
```
ps/docker ps 也確認當下沒有殘留 process/container（早被 Ctrl-C 收掉）。
→ **主程序在 `future.result()` 阻塞 5 小時，直到人為中止。** 這是 hang，不是死亡。

## 2. 程式根因：per-fuzzer timeout 被設成「整個 run 的剩餘時間」

`external/oss_fuzz.py` `run_fuzzer`（527–534）：
```python
timeout = None
if deadline is not None:
    remaining = deadline - time.monotonic()
    ...
    timeout = remaining          # ← 整個 run 剩餘（可能數小時），不是該 fuzzer 的 max_total_time(300s)
helper_result = self._run_helper_command([... f" -max_total_time={seconds} "], timeout=timeout)
```
- 每個 fuzzer 該跑 `max_total_time=300s`，但 subprocess 的 **kill timeout 是「整個 run 剩多久」**。
- llm_fuzzgen0625200241 OOM 後 docker container hang（沒在 300s 退出），subprocess.run 的 timeout 是
  「剩餘數小時」→ 等了 5 小時。
- 外層也無 timeout：`main.py:2019` `future.result()`、`oss_fuzz.py:643` `as_completed`+`future.result()`、
  `oss_fuzz.py:729` `wait(..., ALL_COMPLETED)`（最終 drain 無 timeout）。
→ **單一 hang 住的 docker container 就能讓整個 run 永久卡死。**

## 3. 為什麼 quarantine 修不到這個（關鍵）
quarantine 靠**累積失敗次數**觸發。但 **hang 永遠不會 return → 永遠不會被記成一次失敗 → 永遠不觸發
quarantine**。所以：
- quarantine 是「避免病態 target 反覆浪費時間」的**效率層**，正確且該做；
- 但它**不是「卡死」這個 bug 的修法**。只做 quarantine、不修 timeout，下次仍會在某個 hang 上卡死。

## 4. 建議修法順序
1. **PRIMARY（根治卡死）**：`run_fuzzer` timeout 改
   `timeout = min(remaining_if_deadline_else_inf, seconds + FUZZER_TIMEOUT_BUFFER)`（buffer ~120s）。
   任何單一 fuzzer 最多卡 ~max_total_time+buffer，與整體 deadline 無關。
2. **ROBUSTNESS（清殭屍 container）**：docker 用固定 `--name`；subprocess timeout 後 `docker rm -f <name>`。
   （subprocess.run timeout 只砍 helper，docker container 會續活、續吃記憶體 → 必須顯式清。）
3. **EFFICIENCY（你的 quarantine，次要）**：同 run 內反覆 OOM/LSan/timeout/SEGV 累積達門檻 →
   `target_quarantined`（僅本 run、不刪檔、留 artifact）+ minimum-active-targets + quarantine_ratio 報告
   + 比例過高標 `unhealthy_target_set`。

## 5. 想請 Codex 對齊
1. 同意根因是「per-fuzzer subprocess timeout = 整個 run 剩餘時間（未 bound 到 max_total_time+buffer）」嗎？
2. 同意 quarantine 是效率層、**修不到 hang**（hang 不被記為失敗），所以 PRIMARY 必須是 timeout bound 嗎？
3. timeout 後 `docker rm -f <name>` 強制清 container，你的環境是否可行？是否有更好的 container 生命週期控制？
4. FUZZER_TIMEOUT_BUFFER 取 120s 是否合理？（涵蓋 build/startup/OOM-artifact-write/shutdown）

## 附：此 run 仍有成果（別丟）
runtime-confirmed 解出 cmsDetectBlackPoint:267、cmsDetectDestinationBlackPoint:403，可留作 case study。
