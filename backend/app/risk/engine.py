from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.models.artefact import Artefact, QuantumStatus
from backend.app.risk.classifier import Criticality, LifetimeClass
from backend.app.risk.mosca import MoscaAssessment, MoscaEngine


class RiskSummary(BaseModel):
    total_artefacts: int
    at_risk_count: int
    quantum_vulnerable_count: int
    percent_quantum_vulnerable: float
    counts_by_risk_level: Dict[str, int]
    counts_by_lifetime: Dict[str, int]
    counts_by_criticality: Dict[str, int]
    top_riskiest: List[MoscaAssessment]
    assessments: List[MoscaAssessment]


class RiskEngine:
    """
    High-level orchestrator for enterprise cryptographic risk assessment.
    Runs Mosca's inequality, computes asset exposure, and aggregates posture summaries.
    """

    @classmethod
    def assess_artefacts(
        cls,
        artefacts: List[Artefact],
        default_y: float = 3.0,
        default_z: float = 12.0,
        overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> RiskSummary:
        overrides = overrides or {}
        assessments: List[MoscaAssessment] = []

        counts_by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        counts_by_life = {"short": 0, "medium": 0, "long": 0}
        counts_by_crit = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        at_risk_count = 0
        qv_count = 0

        for art in artefacts:
            art_overrides = overrides.get(art.id, {})

            assessment = MoscaEngine.evaluate(
                artefact=art,
                x_override=art_overrides.get("x"),
                y=art_overrides.get("y", default_y),
                z=art_overrides.get("z", default_z),
                lifetime_override=art_overrides.get("lifetime"),
                criticality_override=art_overrides.get("criticality"),
            )
            assessments.append(assessment)

            # Accumulate metrics
            counts_by_level[assessment.risk_level] = counts_by_level.get(assessment.risk_level, 0) + 1
            counts_by_life[assessment.lifetime_class.value] = counts_by_life.get(assessment.lifetime_class.value, 0) + 1
            counts_by_crit[assessment.criticality.value] = counts_by_crit.get(assessment.criticality.value, 0) + 1

            if assessment.is_at_risk:
                at_risk_count += 1

            if art.quantum_status in {QuantumStatus.VULNERABLE_SHOR, QuantumStatus.WEAKENED_GROVER}:
                qv_count += 1

        total = len(artefacts)
        percent_qv = round((qv_count / total * 100.0), 1) if total > 0 else 0.0

        # Sort assessments by risk score descending
        sorted_assessments = sorted(assessments, key=lambda a: a.risk_score, reverse=True)
        top_10 = sorted_assessments[:10]

        return RiskSummary(
            total_artefacts=total,
            at_risk_count=at_risk_count,
            quantum_vulnerable_count=qv_count,
            percent_quantum_vulnerable=percent_qv,
            counts_by_risk_level=counts_by_level,
            counts_by_lifetime=counts_by_life,
            counts_by_criticality=counts_by_crit,
            top_riskiest=top_10,
            assessments=assessments,
        )


def assess_scan_risk(
    artefacts: List[Artefact],
    y: float = 3.0,
    z: float = 12.0,
    overrides: Optional[Dict[str, Dict[str, Any]]] = None,
) -> RiskSummary:
    """Convenience helper to assess risk across a collection of discovered artefacts."""
    return RiskEngine.assess_artefacts(artefacts, default_y=y, default_z=z, overrides=overrides)
