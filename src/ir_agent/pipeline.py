from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .agents import DeterministicIncidentAgents
from .evaluator import evaluate_case
from .report_writer import write_markdown_report
from .schemas import IncidentCase


def load_case(path: Path) -> IncidentCase:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    return IncidentCase.from_dict(payload)


def run_case(case_path: Path, output_root: Path) -> dict:
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "json").mkdir(parents=True, exist_ok=True)
    (output_root / "reports").mkdir(parents=True, exist_ok=True)

    agents = DeterministicIncidentAgents()
    case = load_case(case_path)
    classification = agents.classify(case)
    evidence = agents.extract_evidence(case)
    playbook = agents.generate_playbook(classification, evidence)
    preliminary_report = write_markdown_report(case, classification, evidence, playbook)
    evaluation = evaluate_case(case, classification, evidence, playbook, preliminary_report)
    final_report = write_markdown_report(case, classification, evidence, playbook, evaluation)

    result = {
        "case": asdict(case),
        "classification": asdict(classification),
        "evidence": asdict(evidence),
        "playbook": asdict(playbook),
        "evaluation": asdict(evaluation),
        "report_path": str(output_root / "reports" / f"{case.case_id}_report.md"),
    }
    json_path = output_root / "json" / f"{case.case_id}_result.json"
    report_path = output_root / "reports" / f"{case.case_id}_report.md"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(final_report, encoding="utf-8")
    return result


def run_all(cases_dir: Path, output_root: Path) -> list[dict]:
    results = []
    for case_path in sorted(cases_dir.glob("*.json")):
        results.append(run_case(case_path, output_root))
    return results
