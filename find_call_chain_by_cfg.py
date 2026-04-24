import json
from types import SimpleNamespace

from fuzz_introspector import utils, cfg_load, analysis
from fuzz_introspector.analyses.calltree_analysis import FuzzCalltreeAnalysis

# 1) 讀入 .data 文字並解析成 calltree root
data_path = "fuzzerLogFile-0-AA7rfCazZm.data"
with open(data_path, "r", encoding="utf-8", errors="ignore") as f:
    cfg_content = f.read()

root = cfg_load.data_file_read_calltree(cfg_content)

# 2) 攤平 calltree
all_nodes = cfg_load.extract_all_callsites(root)
print("total nodes:", len(all_nodes))
print("first 5 nodes:")
for n in all_nodes[:5]:
    print(" ", n.depth, n.dst_function_name, n.dst_function_source_file, n.src_linenumber)

# 3) 模擬一筆 blocker（你可改成從 [branch-blockers.json](http://_vscodecontentref_/2) 讀）
blocker = SimpleNamespace(
    blocked_side="0",
    blocked_unique_not_covered_complexity=20,
    blocked_unique_reachable_complexity=20,
    blocked_unique_functions=["tinyxml2::StrPair::CollapseWhitespace()"],
    blocked_not_covered_complexity=20,
    blocked_reachable_complexity=20,
    sides_hitcount_diff=1800,
    source_file="/src/tinyxml2/tinyxml2.cpp",
    branch_line_number="372",
    blocked_side_line_numder="373",
    function_name="tinyxml2::StrPair::GetStr()",
    coverage_report_link=""
)

# 4) 先把 blocker function_name 轉成 raw（這步可選）
# 目前 collect_calltree_nodes 直接比 node.dst_function_name，常是 mangled
# 這裡示範反過來：把 node demangle 後人眼檢查
matches = []
for n in all_nodes:
    demangled = utils.demangle_cpp_func(n.dst_function_name)
    if demangled == blocker.function_name:
        matches.append(n)

print("demangled name matches:", len(matches))
for n in matches[:3]:
    print("  candidate:", n.depth, n.dst_function_name, n.dst_function_source_file, n.src_linenumber)

# 5) 直接用 collect_calltree_nodes（注意：它預設用 raw name 比對）
# 如果 blocker.function_name 不是 raw，這裡可能找不到
cta = FuzzCalltreeAnalysis()
mapping = cta.collect_calltree_nodes([blocker], root)

if not mapping:
    print("collect_calltree_nodes: no mapping found")
else:
    node = next(iter(mapping.values()))
    print("mapped node:", node.depth, node.dst_function_name, node.dst_function_source_file, node.src_linenumber)

    chain = []
    cur = node
    while cur is not None:
        chain.append(cur)
        cur = cur.parent_calltree_callsite
    chain.reverse()

    print("call chain:")
    for x in chain:
        print(" ", "  " * x.depth, x.depth, x.dst_function_name, x.dst_function_source_file, x.src_linenumber)