"""DLP Pipeline — adresserer Gap G1/G_KI1: regex- og NER-kontrol af prompts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any


HIGH_RISK_LABELS = {"CPR_NUMBER", "IBAN", "CREDIT_CARD", "API_KEY"}
LOW_RISK_LABELS = {"EMAIL", "PERSON", "ORG"}
NER_LABEL_MAP = {"PER": "PERSON", "PERSON": "PERSON", "ORG": "ORG"}


@dataclass(frozen=True)
class DetectedEntity:
    label: str
    value: str
    start: int
    end: int
    stage: str


@dataclass(frozen=True)
class DLPResult:
    detected_entities: list[DetectedEntity]
    risk_level: str


REGEX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?P<CPR_NUMBER>\b\d{6}-?\d{4}\b)"),
    re.compile(r"(?P<IBAN>\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,19}\b)"),
    re.compile(r"(?P<CREDIT_CARD>\b(?:\d{4}[- ]){3}\d{4}\b)"),
    re.compile(r"(?P<API_KEY>\b(sk-[A-Za-z0-9]{20,}|Bearer [A-Za-z0-9\-_.]+)\b)"),
    re.compile(r"(?P<EMAIL>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)"),
)


def analyze_prompt(prompt: str) -> DLPResult:
    entities = detect_regex_entities(prompt)
    entities.extend(detect_ner_entities(prompt))
    entities = _sort_entities(entities)
    return DLPResult(detected_entities=entities, risk_level=_risk_level(entities))


def detect_regex_entities(prompt: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for pattern in REGEX_PATTERNS:
        entities.extend(_entities_from_pattern(pattern, prompt))
    return entities


def _entities_from_pattern(pattern: re.Pattern[str], prompt: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for match in pattern.finditer(prompt):
        label = match.lastgroup
        if label is None:
            continue
        entities.append(
            DetectedEntity(label, match.group(label), match.start(label), match.end(label), "regex")
        )
    return entities


@lru_cache(maxsize=1)
def _load_spacy_model() -> Any | None:
    try:
        import spacy
    except ImportError:
        return None

    for model_name in ("da_core_news_sm", "en_core_web_sm"):
        try:
            return spacy.load(model_name)
        except OSError:
            continue
    return None


def detect_ner_entities(prompt: str) -> list[DetectedEntity]:
    nlp = _load_spacy_model()
    if nlp is None:
        return []
    return [_entity_from_spacy(ent) for ent in nlp(prompt).ents if _normalise_ner_label(ent.label_)]


def _entity_from_spacy(ent: Any) -> DetectedEntity:
    return DetectedEntity(
        label=_normalise_ner_label(ent.label_),
        value=ent.text,
        start=ent.start_char,
        end=ent.end_char,
        stage="ner",
    )


def _normalise_ner_label(label: str) -> str:
    return NER_LABEL_MAP.get(label, "")


def _risk_level(entities: list[DetectedEntity]) -> str:
    labels = {entity.label for entity in entities}
    if labels & HIGH_RISK_LABELS:
        return "HIGH"
    if labels & LOW_RISK_LABELS:
        return "LOW"
    return "NONE"


def _sort_entities(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    return sorted(entities, key=lambda entity: (entity.start, entity.end, entity.label))
