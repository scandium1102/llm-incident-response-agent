from __future__ import annotations

from .schemas import ClassificationResult, EvaluationResult, EvidenceResult, IncidentCase, PlaybookResult


def evaluate_case(
    case: IncidentCase,
    classification: ClassificationResult,
    evidence: EvidenceResult,
    playbook: PlaybookResult,
    report_text: str,
) -> EvaluationResult:
    truth = case.ground_truth
    notes: list[str] = []

    classification_score = 2 if classification.incident_type == truth.incident_type else 0
    if classification_score == 2:
        notes.append("Classification matched ground truth.")
    else:
        notes.append(f"Classification mismatch: expected {truth.incident_type}, got {classification.incident_type}.")

    severity_score = 2 if classification.severity == truth.severity else 1 if classification.severity else 0
    if severity_score == 2:
        notes.append("Severity matched ground truth.")
    else:
        notes.append(f"Severity differs: expected {truth.severity}, got {classification.severity}.")

    searchable = " ".join(
        [
            case.raw_alert,
            " ".join(classification.supporting_evidence),
            " ".join(evidence.evidence_notes),
            str(evidence.observables),
        ]
    ).lower()
    evidence_hits = [item for item in truth.required_evidence if item.lower() in searchable]
    evidence_ratio = len(evidence_hits) / max(len(truth.required_evidence), 1)
    evidence_score = 2 if evidence_ratio >= 0.75 else 1 if evidence_ratio >= 0.4 else 0
    notes.append(f"Evidence matched {len(evidence_hits)}/{len(truth.required_evidence)} required items.")

    playbook_text = " ".join(
        playbook.containment
        + playbook.investigation
        + playbook.eradication
        + playbook.recovery
        + playbook.post_incident_review
    ).lower()
    response_hits = [item for item in truth.expected_response_keywords if item.lower() in playbook_text]
    response_ratio = len(response_hits) / max(len(truth.expected_response_keywords), 1)
    playbook_score = 2 if response_ratio >= 0.6 else 1 if response_ratio >= 0.3 else 0
    notes.append(f"Playbook covered {len(response_hits)}/{len(truth.expected_response_keywords)} expected response keywords.")

    unsupported_markers = ["definitely stolen", "confirmed breach", "all users compromised"]
    hallucination_found = [marker for marker in unsupported_markers if marker in report_text.lower()]
    hallucination_score = 2 if not hallucination_found else 0
    if hallucination_found:
        notes.append("Potential unsupported claim detected: " + ", ".join(hallucination_found))
    else:
        notes.append("No high-risk unsupported claim marker detected.")

    scores = [classification_score, evidence_score, severity_score, playbook_score, hallucination_score]
    return EvaluationResult(
        classification_score=classification_score,
        evidence_score=evidence_score,
        severity_score=severity_score,
        playbook_score=playbook_score,
        hallucination_score=hallucination_score,
        total_score=sum(scores),
        max_score=10,
        notes=notes,
    )
