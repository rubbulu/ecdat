from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from backend.app.models.artefact import Artefact, QuantumStatus
from backend.app.risk.classifier import AssetClassifier, Criticality, LifetimeClass


class MoscaParameters(BaseModel):
    """
    Parameters for Mosca's Inequality (X + Y > Z).
    - X: Data confidentiality shelf-life (years)
    - Y: Migration time to deploy quantum-safe standards (years)
    - Z: Time until a Cryptanalytically Relevant Quantum Computer (CRQC) arrives (years)
    """
    x: float = Field(default=5.0, ge=0.0, description="Data shelf-life in years")
    y: float = Field(default=3.0, ge=0.0, description="Migration time in years")
    z: float = Field(default=12.0, ge=0.1, description="Years until CRQC collapses classical crypto")


class MoscaAssessment(BaseModel):
    artefact_id: str
    artefact_name: str
    lifetime_class: LifetimeClass
    criticality: Criticality
    x: float
    y: float
    z: float
    is_at_risk: bool
    margin: float
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: str
    explanation: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MoscaEngine:
    """
    Evaluates quantum risk urgency using Mosca's Inequality:
        At Risk If: X + Y > Z
    Produces a composite 0-100 risk score and plain-English risk explanation.
    """

    DEFAULT_Y: float = 3.0   # 3 years default migration timeline
    DEFAULT_Z: float = 12.0  # 12 years default quantum threat horizon

    @classmethod
    def evaluate(
        cls,
        artefact: Artefact,
        x_override: Optional[float] = None,
        y: Optional[float] = None,
        z: Optional[float] = None,
        lifetime_override: Optional[LifetimeClass | str] = None,
        criticality_override: Optional[Criticality | str] = None,
    ) -> MoscaAssessment:
        # 1. Resolve Classification
        crit = AssetClassifier.infer_criticality(artefact, override=criticality_override)
        lifetime = AssetClassifier.infer_lifetime(artefact, override=lifetime_override)

        # 2. Resolve Mosca parameters
        x = x_override if x_override is not None else lifetime.default_years
        y_val = y if y is not None else cls.DEFAULT_Y
        z_val = z if z is not None else cls.DEFAULT_Z
        margin = (x + y_val) - z_val
        mosca_condition = (x + y_val) > z_val

        # 3. Determine Quantum & Classical Vulnerability
        q_status = artefact.quantum_status
        name = artefact.name
        key_size = artefact.key_size

        # Base score determination
        if q_status == QuantumStatus.CLASSICALLY_BROKEN:
            base_score = 80.0
            is_at_risk = True
            explanation = (
                f"{name} is classically broken and obsolete; vulnerable to immediate exploitation today "
                f"regardless of quantum timeline."
            )
        elif q_status == QuantumStatus.VULNERABLE_SHOR:
            if mosca_condition:
                base_score = 70.0
                is_at_risk = True
                ks_str = f"-{key_size}" if key_size else ""
                explanation = (
                    f"{name}{ks_str} protects {x:g}-year data; {x:g} + {y_val:g} > {z_val:g}, "
                    f"so this is at risk from Shor's algorithm."
                )
            else:
                base_score = 45.0
                is_at_risk = False
                explanation = (
                    f"{name} is vulnerable to Shor's algorithm, but migration horizon "
                    f"({x:g} + {y_val:g} = {x+y_val:g}y) fits within estimated CRQC timeline ({z_val:g}y)."
                )
        elif q_status == QuantumStatus.WEAKENED_GROVER:
            if mosca_condition:
                base_score = 50.0
                is_at_risk = True
                effective_bits = (key_size // 2) if key_size else 64
                explanation = (
                    f"{name} is weakened by Grover's algorithm to ~{effective_bits}-bit effective security; "
                    f"with {x:g}-year data retention ({x:g} + {y_val:g} > {z_val:g}), upgrade to AES-256 is required."
                )
            else:
                base_score = 30.0
                is_at_risk = False
                explanation = (
                    f"{name} has reduced quantum security margin under Grover's search, but current "
                    f"migration window allows scheduled upgrade."
                )
        elif q_status == QuantumStatus.QUANTUM_SAFE:
            base_score = 5.0
            is_at_risk = False
            explanation = (
                f"{name} is quantum-safe ({artefact.nist_replacement or 'NIST PQC compliant'}); "
                f"timeline {x:g} + {y_val:g} > {z_val:g} does not present quantum compromise risk."
            )
        else:
            # Unclassified algorithm
            base_score = 25.0
            is_at_risk = False
            explanation = f"{name} is unclassified in the cryptographic catalogue; manual review recommended."

        # 4. Modifiers
        # Criticality modifier
        crit_mod = {
            Criticality.CRITICAL: 15.0,
            Criticality.HIGH: 10.0,
            Criticality.MEDIUM: 5.0,
            Criticality.LOW: 0.0,
        }.get(crit, 0.0)

        # Margin urgency modifier
        margin_mod = 0.0
        if is_at_risk and margin > 0:
            margin_mod = min(10.0, margin * 1.5)

        # Key size weakness penalty
        key_size_mod = 0.0
        if key_size is not None:
            if "RSA" in name.upper() and key_size <= 1024:
                key_size_mod += 15.0
                explanation += f" Critical: {key_size}-bit RSA key length is severely weak classically."
            elif "DES" in name.upper() and key_size <= 56:
                key_size_mod += 10.0

        # Calculate final composite risk score (clamped between 0.0 and 100.0)
        final_score = round(min(100.0, max(0.0, base_score + crit_mod + margin_mod + key_size_mod)), 1)

        # Categorize risk level
        if final_score >= 80.0:
            risk_level = "critical"
        elif final_score >= 60.0:
            risk_level = "high"
        elif final_score >= 35.0:
            risk_level = "medium"
        else:
            risk_level = "low"

        return MoscaAssessment(
            artefact_id=artefact.id,
            artefact_name=artefact.name,
            lifetime_class=lifetime,
            criticality=crit,
            x=x,
            y=y_val,
            z=z_val,
            is_at_risk=is_at_risk,
            margin=round(margin, 2),
            risk_score=final_score,
            risk_level=risk_level,
            explanation=explanation,
            metadata={
                "quantum_status": q_status.value if q_status else None,
                "file": artefact.location.file,
                "line": artefact.location.line,
                "key_size": key_size,
            },
        )
