"""Masking Module — adresserer Gap G1/G_KI1: dataminimering før LLM-kald.

This component addresses the empirical need to reduce leakage risk by replacing
sensitive values with Danish masking tokens before any prompt is forwarded to an
externally hosted LLM service.
"""

from __future__ import annotations

from dataclasses import dataclass

from .dlp_pipeline import DetectedEntity


TOKEN_BY_LABEL = {
    "CPR_NUMBER": "[CPR-MASKERET]",
    "IBAN": "[IBAN-MASKERET]",
    "PERSON": "[NAVN-MASKERET]",
    "ORG": "[ORG-MASKERET]",
    "EMAIL": "[EMAIL-MASKERET]",
    "API_KEY": "[API-NØGLE-MASKERET]",
    "CREDIT_CARD": "[KREDITKORT-MASKERET]",
}


@dataclass(frozen=True)
class MaskingResult:
    """Masked prompt text and in-memory token mapping."""

    masked_text: str
    token_mapping: dict[str, str]


def mask_text(prompt: str, entities: list[DetectedEntity]) -> MaskingResult:
    """Replace maskable entity spans with Danish masking tokens."""
    maskable_entities = _deduplicate_entities(_maskable_entities(entities))
    masked_text = prompt
    token_mapping: dict[str, str] = {}

    for entity in reversed(maskable_entities):
        token = TOKEN_BY_LABEL[entity.label]
        masked_text = _replace_span(masked_text, entity.start, entity.end, token)
        token_mapping.setdefault(token, entity.value)

    return MaskingResult(masked_text=masked_text, token_mapping=token_mapping)


def _maskable_entities(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    """Return only entities that policy allows the gateway to mask."""
    return [entity for entity in entities if entity.label in TOKEN_BY_LABEL]


def _replace_span(text: str, start: int, end: int, replacement: str) -> str:
    """Replace a character span without changing surrounding text."""
    return f"{text[:start]}{replacement}{text[end:]}"


def _deduplicate_entities(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    """Remove overlapping spans, preferring the earliest complete match."""
    ordered = sorted(entities, key=lambda entity: (entity.start, -(entity.end - entity.start)))
    selected: list[DetectedEntity] = []
    occupied_until = -1
    for entity in ordered:
        if entity.start < occupied_until:
            continue
        selected.append(entity)
        occupied_until = entity.end
    return selected
