"""Masking Module — adresserer Gap G1/G_KI1: dataminimering før LLM-kald."""

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
    masked_text: str
    token_mapping: dict[str, str]


def mask_text(prompt: str, entities: list[DetectedEntity]) -> MaskingResult:
    maskable_entities = _deduplicate_entities(_maskable_entities(entities))
    masked_text = prompt
    token_mapping: dict[str, str] = {}

    for entity in reversed(maskable_entities):
        token = TOKEN_BY_LABEL[entity.label]
        masked_text = _replace_span(masked_text, entity.start, entity.end, token)
        token_mapping.setdefault(token, entity.value)

    return MaskingResult(masked_text=masked_text, token_mapping=token_mapping)


def _maskable_entities(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    return [entity for entity in entities if entity.label in TOKEN_BY_LABEL]


def _replace_span(text: str, start: int, end: int, replacement: str) -> str:
    return f"{text[:start]}{replacement}{text[end:]}"


def _deduplicate_entities(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    ordered = sorted(entities, key=lambda entity: (entity.start, -(entity.end - entity.start)))
    selected: list[DetectedEntity] = []
    occupied_until = -1
    for entity in ordered:
        if entity.start < occupied_until:
            continue
        selected.append(entity)
        occupied_until = entity.end
    return selected
