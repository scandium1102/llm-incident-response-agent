from __future__ import annotations

from .schemas import ClassificationResult, EvaluationResult, EvidenceResult, IncidentCase, PlaybookResult


def write_markdown_report(
    case: IncidentCase,
    classification: ClassificationResult,
    evidence: EvidenceResult,
    playbook: PlaybookResult,
    evaluation: EvaluationResult | None = None,
) -> str:
    lines: list[str] = []
    lines.append(f"# Incident Report: {case.title}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(
        f"The workflow classified `{case.case_id}` as `{classification.incident_type}` "
        f"with `{classification.severity}` severity and confidence `{classification.confidence:.2f}`. "
        "This report is generated from the provided case evidence and should be reviewed by a human analyst before operational use."
    )
    lines.append("")
    lines.append("## Incident Classification")
    lines.append(f"- Incident type: `{classification.incident_type}`")
    lines.append(f"- Severity: `{classification.severity}`")
    lines.append(f"- Confidence: `{classification.confidence:.2f}`")
    lines.append("- Supporting evidence:")
    for item in classification.supporting_evidence:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("## Evidence Table")
    lines.append("| Category | Values |")
    lines.append("| --- | --- |")
    for key, values in evidence.observables.items():
        rendered = ", ".join(values) if values else "None observed"
        lines.append(f"| {key} | {rendered} |")
    lines.append("")
    lines.append("## Behavioral Evidence")
    if evidence.behaviors:
        for behavior in evidence.behaviors:
            lines.append(f"- {behavior}")
    else:
        lines.append("- No behavior rule was triggered; manual review is needed.")
    lines.append("")
    lines.append("## Recommended Response Playbook")
    for phase, steps in [
        ("Containment", playbook.containment),
        ("Investigation", playbook.investigation),
        ("Eradication", playbook.eradication),
        ("Recovery", playbook.recovery),
        ("Post-Incident Review", playbook.post_incident_review),
    ]:
        lines.append(f"### {phase}")
        for step in steps:
            lines.append(f"- {step}")
        lines.append("")
    lines.append("## Evaluation Notes")
    if evaluation:
        lines.append(f"- Total score: {evaluation.total_score}/{evaluation.max_score}")
        for note in evaluation.notes:
            lines.append(f"- {note}")
    else:
        lines.append("- Evaluation has not been run.")
    lines.append("")
    lines.append("## Limitations and Uncertainties")
    lines.append("- This is a course PoC and not a production SOC tool.")
    lines.append("- The default backend is deterministic and simulates an LLM-style agent workflow.")
    lines.append("- The report does not prove compromise; it organizes evidence and recommends analyst actions.")
    return "\n".join(lines) + "\n"
