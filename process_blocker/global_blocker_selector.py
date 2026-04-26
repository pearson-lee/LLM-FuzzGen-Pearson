import json
import math
from typing import List, Dict, Any

def aggregate_and_score_blockers(json_path: str, top_k: int = 12) -> List[Dict[str, Any]]:
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[Error] File not found: {json_path}")
        return []

    global_blockers = {}

    for target_name, blockers in data.items():
        for blocker in blockers[:top_k]:
            source_file = blocker.get("source_file", "")
            branch_line = str(blocker.get("branch_line_number", ""))
            blocked_side = str(blocker.get("blocked_side", ""))
            
            # use a tuple of (source_file, branch_line, blocked_side)
            # as the key to aggregate blockers that hit the same location
            key = (source_file, branch_line, blocked_side)
            
            if key not in global_blockers:
                global_blockers[key] = {
                    "source_file": source_file,
                    "branch_line_number": branch_line,
                    "blocked_side": blocked_side,
                    "function_name": blocker.get("function_name", ""),
                    "blocked_side_line_numder": blocker.get("blocked_side_line_numder", ""),
                    
                    "occurrence_count": 0,
                    "blocked_unique_not_covered_complexity": 0,
                    "blocked_unique_reachable_complexity": 0,
                    "blocked_not_covered_complexity": 0,
                    "blocked_reachable_complexity": 0,
                    "sides_hitcount_diff": 0,
                    "blocked_unique_functions": set(),
                    
                    # which target contributes the most to this blocker(for later CFG parsing)
                    "best_target": target_name,
                    "max_hitcount_diff_for_target": -1
                }
            
            gb = global_blockers[key]
            
            gb["occurrence_count"] += 1
            
            gb["blocked_unique_not_covered_complexity"] = max(
                gb["blocked_unique_not_covered_complexity"], 
                blocker.get("blocked_unique_not_covered_complexity", 0)
            )
            gb["blocked_unique_reachable_complexity"] = max(
                gb["blocked_unique_reachable_complexity"], 
                blocker.get("blocked_unique_reachable_complexity", 0)
            )
            gb["blocked_not_covered_complexity"] = max(
                gb["blocked_not_covered_complexity"], 
                blocker.get("blocked_not_covered_complexity", 0)
            )
            gb["blocked_reachable_complexity"] = max(
                gb["blocked_reachable_complexity"], 
                blocker.get("blocked_reachable_complexity", 0)
            )
            
            # the number of times this blocker was hit across all targets
            hitcount_diff = blocker.get("sides_hitcount_diff", 0)
            gb["sides_hitcount_diff"] += hitcount_diff
            
            # 如果這個 target 撞的次數比之前的記錄高，設它為 best_target
            if hitcount_diff > gb["max_hitcount_diff_for_target"]:
                gb["max_hitcount_diff_for_target"] = hitcount_diff
                gb["best_target"] = target_name
                
            # 4. blocked_unique_functions (union)
            funcs = blocker.get("blocked_unique_functions", [])
            if funcs:
                gb["blocked_unique_functions"].update(funcs)

    # 計算總分準備排序
    result = []
    for key, gb in global_blockers.items():
        # score = unique_complexity * log(1 + occurrence) * log(1 + hitcount_diff)
        score = (gb["blocked_unique_not_covered_complexity"] * 
                 math.log(1 + gb["occurrence_count"]) * 
                 math.log(1 + gb["sides_hitcount_diff"]))
        
        gb["score"] = score
        # 轉回 List 以便未來轉跳或輸出 JSON
        gb["blocked_unique_functions"] = list(gb["blocked_unique_functions"])
        
        result.append(gb)
        
    # 使用四維 tiebreaker 排序 (由大到小)
    result.sort(
        key=lambda x: (
            x["score"], 
            x["blocked_unique_reachable_complexity"], 
            x["blocked_not_covered_complexity"], 
            x["blocked_reachable_complexity"]
        ),
        reverse=True
    )
    
    return result

def main():
    json_path = "branch-blockers.json" 
    
    print("[Info] Aggregate and evaluate global blockers...")
    global_blockers = aggregate_and_score_blockers(json_path, top_k=12)
    
    if not global_blockers:
        print("[Warn] No blockers found or file missing.")
        return

    print(f"[Info] Total unique global blockers aggregated: {len(global_blockers)}")
    
    top1 = global_blockers[0]
    
    print("\n" + "="*50)
    print("Top-1 Global Blocker")
    print("="*50)
    print(f"Location    : {top1['source_file']} (Line: {top1['branch_line_number']}, Side: {top1['blocked_side']})")
    print(f"Function    : {top1['function_name']}")
    print(f"Score       : {top1['score']:.2f}")
    print(f"Occurrence  : {top1['occurrence_count']} targets blocked")
    print(f"Total HitDiff: {top1['sides_hitcount_diff']}")
    print(f"Uniq Not-Cov: {top1['blocked_unique_not_covered_complexity']}")
    print(f"Best Target : {top1['best_target']} (Use this to parse CFG)")
    print("="*50)

if __name__ == "__main__":
    main()