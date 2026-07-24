from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GroundTruth:
    incident_type: str
    severity: str
    required_evidence: list[str]
    expected_response_keywords: list[str]


@dataclass
class IncidentCase:
    case_id: str
    title: str
    raw_alert: str
    ground_truth: GroundTruth

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IncidentCase":
        truth = GroundTruth(**payload["ground_truth"])
        return cls(
            case_id=payload["case_id"],
            title=payload["title"],
            raw_alert=payload["raw_alert"],
            ground_truth=truth,
        )


@dataclass
class ClassificationResult:
    incident_type: str
    severity: str
    confidence: float
    supporting_evidence: list[str] = field(default_factory=list)


@dataclass
class EvidenceResult:
    observables: dict[str, list[str]]
    behaviors: list[str]
    evidence_notes: list[str]


@dataclass
class PlaybookResult:
    containment: list[str]
    investigation: list[str]
    eradication: list[str]
    recovery: list[str]
    post_incident_review: list[str]


@dataclass
class EvaluationResult:
    classification_score: int
    evidence_score: int
    severity_score: int
    playbook_score: int
    hallucination_score: int
    total_score: int
    max_score: int
    notes: list[str]
