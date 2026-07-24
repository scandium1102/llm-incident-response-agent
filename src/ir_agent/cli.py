from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pipeline import run_all, run_case


def build_evaluation_summary(results: list[dict], output_root: Path) -> None:
    evaluation_dir = output_root / "evaluation"
    evaluation_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for result in results:
        evaluation = result["evaluation"]
        rows.append(
            {
                "case_id": result["case"]["case_id"],
                "title": result["case"]["title"],
                "incident_type": result["classification"]["incident_type"],
                "severity": result["classification"]["severity"],
                "total_score": evaluation["total_score"],
                "max_score": evaluation["max_score"],
                "classification_score": evaluation["classification_score"],
                "evidence_score": evaluation["evidence_score"],
                "severity_score": evaluation["severity_score"],
                "playbook_score": evaluation["playbook_score"],
                "hallucination_score": evaluation["hallucination_score"],
            }
        )
    summary_json = {"cases": rows, "average_score": sum(r["total_score"] for r in rows) / max(len(rows), 1)}
    (evaluation_dir / "evaluation_summary.json").write_text(
        json.dumps(summary_json, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    lines = [
        "# Evaluation Summary",
        "",
        "| Case | Type | Severity | Score | Classification | Evidence | Playbook | Hallucination |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {row['case_id']} | {row['incident_type']} | {row['severity']} | "
            f"{row['total_score']}/{row['max_score']} | {row['classification_score']} | "
            f"{row['evidence_score']} | {row['playbook_score']} | {row['hallucination_score']} |"
        )
    lines.append("")
    lines.append(f"Average score: {summary_json['average_score']:.2f}/10")
    (evaluation_dir / "evaluation_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the incident response agent PoC.")
    parser.add_argument("--case", type=Path, help="Path to a single case JSON file.")
    parser.add_argument("--all", action="store_true", help="Run every case under data/cases.")
    parser.add_argument("--cases-dir", type=Path, default=Path("data/cases"))
    parser.add_argument("--output-root", type=Path, default=Path("outputs"))
    args = parser.parse_args()

    if args.case:
        result = run_case(args.case, args.output_root)
        build_evaluation_summary([result], args.output_root)
        print(json.dumps({"ran": [result["case"]["case_id"]]}, ensure_ascii=False))
        return
    if args.all:
        results = run_all(args.cases_dir, args.output_root)
        build_evaluation_summary(results, args.output_root)
        print(json.dumps({"ran": [r["case"]["case_id"] for r in results]}, ensure_ascii=False))
        return
    parser.error("Use --case PATH or --all")


if __name__ == "__main__":
    main()
