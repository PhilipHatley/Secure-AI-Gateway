"""Policy Engine — adresserer Gap G3: forklarlig risikobeslutning for prompts."""

from __future__ import annotations

from dataclasses import dataclass

from .dlp_pipeline import DLPResult


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    reason: str
    triggered_rule: int
    aup_reference: str


def decide_policy(result: DLPResult) -> PolicyDecision:
    labels = {entity.label for entity in result.detected_entities}

    if result.risk_level == "HIGH" and labels & {"CPR_NUMBER", "IBAN"}:
        return _decision("BLOCK", "CPR-nummer eller IBAN må ikke sendes eksternt.", 1, "AUP § 3.2")
    if result.risk_level == "HIGH" and "API_KEY" in labels:
        return _decision("BLOCK", "API-nøgle må ikke sendes til eksterne LLM-tjenester.", 2, "AUP § 3.3")
    if result.risk_level == "HIGH" and "CREDIT_CARD" in labels:
        return _decision("MASK_AND_FORWARD", "Kreditkortdata maskeres før videresendelse.", 3, "AUP § 3.4")
    if result.risk_level == "LOW":
        # Forretningsreglen afspejler interviewfund: lav risiko håndteres med maskering.
        return _decision("MASK_AND_FORWARD", "Person-, organisations- eller emaildata maskeres.", 4, "AUP § 3.1")
    return _decision("ALLOW", "Ingen følsomme data detekteret.", 5, "AUP § 2.1")


def _decision(action: str, reason: str, rule: int, reference: str) -> PolicyDecision:
    return PolicyDecision(
        action=action,
        reason=reason,
        triggered_rule=rule,
        aup_reference=reference,
    )
