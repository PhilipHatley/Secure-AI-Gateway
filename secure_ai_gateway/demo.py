"""Demo Script — reproducerbare testscenarier til evaluering af gatewayen."""

from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import uuid4

from .audit_logger import build_audit_entry, log_interaction
from .config import get_settings
from .dlp_pipeline import DLPResult, analyze_prompt
from .masker import MaskingResult, mask_text
from .policy_engine import PolicyDecision, decide_policy


@dataclass(frozen=True)
class Scenario:
    title: str
    expected: str
    prompt: str


SCENARIOS = (
    Scenario(
        title="SCENARIO 1 — CPR i prompt",
        expected="BLOCK",
        prompt=(
            "Kan du hjælpe mig med at vurdere kreditrisikoen for kunden Lars Jensen, "
            "CPR 150892-1234, der søger et lån på 500.000 kr?"
        ),
    ),
    Scenario(
        title="SCENARIO 2 — Forretningsdata med navn og email",
        expected="MASK_AND_FORWARD",
        prompt=(
            "Skriv et mødereferat: Vi mødtes med Mærsk Gruppen og direktør Anders "
            "Nielsen for at diskutere Q3-strategien. Kontakt: anders.nielsen@maersk.com"
        ),
    ),
    Scenario(
        title="SCENARIO 3 — Neutral faglig prompt",
        expected="ALLOW",
        prompt="Hvad er forskellen mellem DORA og NIS2 regulering for finansielle institutioner?",
    ),
)


def main() -> None:
    print("SECURE AI GATEWAY — DEMO")
    print("=" * 80)
    for scenario in SCENARIOS:
        _run_scenario(scenario)


def _run_scenario(scenario: Scenario) -> None:
    request_id = str(uuid4())
    result = analyze_prompt(scenario.prompt)
    decision = decide_policy(result)
    masking = _mask_if_needed(scenario.prompt, result, decision)
    forwarded = _forwarded_prompt(scenario.prompt, decision, masking)
    audit_entry = _audit_scenario(request_id, scenario.prompt, result, decision, masking)

    _print_scenario(scenario, result, decision, forwarded, audit_entry)


def _mask_if_needed(prompt: str, result: DLPResult, decision: PolicyDecision) -> MaskingResult | None:
    if decision.action != "MASK_AND_FORWARD":
        return None
    return mask_text(prompt, result.detected_entities)


def _forwarded_prompt(prompt: str, decision: PolicyDecision, masking: MaskingResult | None) -> str:
    if decision.action == "BLOCK":
        return "INTET — prompten blev blokeret og ikke videresendt."
    if masking is not None:
        return masking.masked_text
    return prompt


def _audit_scenario(
    request_id: str,
    prompt: str,
    result: DLPResult,
    decision: PolicyDecision,
    masking: MaskingResult | None,
) -> dict[str, object]:
    settings = get_settings()
    entry = build_audit_entry(
        request_id=request_id,
        target_api=settings.target_api,
        original_prompt_length=len(prompt),
        detected_entities=result.detected_entities,
        masked_values_stored=bool(masking and masking.token_mapping),
        policy_decision=decision,
        forwarded_to_llm=decision.action != "BLOCK",
    )
    log_interaction(entry, settings.log_file)
    return entry


def _print_scenario(
    scenario: Scenario,
    result: DLPResult,
    decision: PolicyDecision,
    forwarded: str,
    audit_entry: dict[str, object],
) -> None:
    print(f"\n{scenario.title}")
    print("-" * 80)
    print(f"Forventet beslutning: {scenario.expected}")
    print(f"Original prompt:\n{scenario.prompt}\n")
    print(f"DLP pipeline result:\n{json.dumps(_dlp_summary(result), ensure_ascii=False, indent=2)}\n")
    print(f"Policy decision: {decision.action} (regel {decision.triggered_rule})")
    print(f"Begrundelse: {decision.reason}\n")
    print(f"Videresendt til LLM:\n{forwarded}\n")
    print(f"Audit log entry:\n{json.dumps(audit_entry, ensure_ascii=False, indent=2)}")


def _dlp_summary(result: DLPResult) -> dict[str, object]:
    return {
        "risk_level": result.risk_level,
        "detected_entities": [
            {"label": entity.label, "stage": entity.stage}
            for entity in result.detected_entities
        ],
    }


if __name__ == "__main__":
    main()
