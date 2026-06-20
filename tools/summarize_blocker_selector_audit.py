#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path

VALID_LABELS = {"resource_guard", "non_resource_nullable", "unknown"}


def _rank_at_most(raw: str, top_k: int) -> bool:
    try:
        return int(raw) <= top_k
    except (TypeError, ValueError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize a manually labeled blocker-selector audit CSV."
    )
    parser.add_argument("audit_csv", type=Path)
    parser.add_argument("--top-k", type=int, nargs="+", default=[10, 20])
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    with args.audit_csv.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    invalid = [
        row.get("blocker_key", "")
        for row in rows
        if row.get("manual_label", "").strip() not in VALID_LABELS
    ]
    if invalid:
        raise SystemExit(
            "Every row must use resource_guard, non_resource_nullable, or unknown. "
            f"Missing/invalid rows: {', '.join(invalid[:10])}"
        )

    strong = [row for row in rows if row.get("evidence_grade") == "strong"]
    decided_strong = [row for row in strong if row["manual_label"] != "unknown"]
    strong_true_positive = [
        row for row in decided_strong if row["manual_label"] == "resource_guard"
    ]
    resource_rows = [row for row in rows if row["manual_label"] == "resource_guard"]
    resource_with_strong = [row for row in resource_rows if row.get("evidence_grade") == "strong"]
    false_downrank = [
        row for row in strong if row["manual_label"] == "non_resource_nullable"
    ]

    report = {
        "audited_count": len(rows),
        "label_counts": {
            label: sum(row["manual_label"] == label for row in rows)
            for label in sorted(VALID_LABELS)
        },
        "strong_evidence_count": len(strong),
        "strong_evidence_decided_count": len(decided_strong),
        "strong_evidence_precision": (
            len(strong_true_positive) / len(decided_strong) if decided_strong else None
        ),
        "resource_guard_recall": (
            len(resource_with_strong) / len(resource_rows) if resource_rows else None
        ),
        "false_downrank_count": len(false_downrank),
        "false_downrank_blockers": [row["blocker_key"] for row in false_downrank],
        "unknown_count": sum(row["manual_label"] == "unknown" for row in rows),
        "top_k": {},
    }
    for top_k in args.top_k:
        report["top_k"][str(top_k)] = {
            "old_resource_guard_count": sum(
                row["manual_label"] == "resource_guard"
                and _rank_at_most(row.get("old_rank", ""), top_k)
                for row in rows
            ),
            "new_resource_guard_count": sum(
                row["manual_label"] == "resource_guard"
                and _rank_at_most(row.get("new_rank", ""), top_k)
                for row in rows
            ),
        }

    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Audit report: {args.output}")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
