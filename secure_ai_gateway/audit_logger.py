"""Audit Trail — adresserer Gap G5: sporbarhed uden lagring af prompthemmeligheder.

The audit log supports thesis demonstration of technical control and traceability
while enforcing the data minimisation requirement: no original prompt text and no
original sensitive values are written to disk.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .dlp_pipeline import DetectedEntity
from .policy_engine import PolicyDecision


def build_audit_entry(
    request_id: str,
    target_api: str,
    original_prompt_length: int,
    detected_entities: list[DetectedEntity],
    masked_values_stored: bool,
    policy_decision: PolicyDecision,
    forwarded_to_llm: bool,
) -> dict[str, Any]:
    """Build a sanitized audit entry that contains metadata only."""
    return {
        "timestamp": _timestamp(),
        "request_id": request_id,
        "target_api": target_api,
        "original_prompt_length": original_prompt_length,
        "detected_entities": _entity_metadata(detected_entities),
        "masked_values_stored": masked_values_stored,
        "policy_action": policy_decision.action,
        "policy_rule_triggered": policy_decision.triggered_rule,
        "aup_reference": policy_decision.aup_reference,
        "forwarded_to_llm": forwarded_to_llm,
    }


def log_interaction(entry: dict[str, Any], log_file: str) -> None:
    """Append one JSON object to the audit log."""
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True) if log_path.parent != Path(".") else None
    with log_path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_last_entries(log_file: str, limit: int = 20) -> list[dict[str, Any]]:
    """Read the latest JSONL audit entries for the demo endpoint."""
    log_path = Path(log_file)
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8").splitlines()[-limit:]
    return [_parse_json_line(line) for line in lines if line.strip()]


def _entity_metadata(entities: list[DetectedEntity]) -> list[dict[str, str]]:
    """Return entity labels and detection stages only."""
    return [{"label": entity.label, "stage": entity.stage} for entity in entities]


def _parse_json_line(line: str) -> dict[str, Any]:
    """Parse one audit line and tolerate malformed historic entries."""
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"malformed": True}


def _timestamp() -> str:
    """Return a timezone-aware ISO 8601 timestamp."""
    return datetime.now(UTC).isoformat()
