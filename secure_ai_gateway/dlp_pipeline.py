"""DLP Pipeline — implements Gap G1/G_KI1 from the empirical analysis.

The pipeline operationalises the thesis feature set by combining deterministic
regex detection for high-risk identifiers with spaCy NER for names,
organisations, and locations before a policy decision is made.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any


HIGH_RISK_LABELS = {"CPR_NUMBER", "IBAN", "CREDIT_CARD", "API_KEY"}
LOW_RISK_LABELS = {"EMAIL", "PERSON", "ORG"}
NER_LABEL_MAP = {"PER": "PERSON", "PERSON": "PERSON", "ORG": "ORG", "GPE": "GPE", "LOC": "GPE"}


@dataclass(frozen=True)
class DetectedEntity:
    """A sensitive or low-risk entity found in a prompt."""

    label: str
    value: str
    start: int
    end: int
    stage: str


@dataclass(frozen=True)
class DLPResult:
    """The complete DLP result passed to the policy engine."""

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
    """Run regex detection first, then NER, and return the risk result."""
    entities = detect_regex_entities(prompt)
    entities.extend(detect_ner_entities(prompt))
    entities = _sort_entities(entities)
    return DLPResult(detected_entities=entities, risk_level=_risk_level(entities))


def detect_regex_entities(prompt: str) -> list[DetectedEntity]:
    """Detect deterministic sensitive-data patterns using named regex groups."""
    entities: list[DetectedEntity] = []
    for pattern in REGEX_PATTERNS:
        entities.extend(_entities_from_pattern(pattern, prompt))
    return entities


def _entities_from_pattern(pattern: re.Pattern[str], prompt: str) -> list[DetectedEntity]:
    """Convert regex matches into DetectedEntity objects."""
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
    """Load Danish NER with English fallback; return None if unavailable."""
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
    """Detect PERSON, ORG, and GPE entities via spaCy when a model is installed."""
    nlp = _load_spacy_model()
    if nlp is None:
        return []
    return [_entity_from_spacy(ent) for ent in nlp(prompt).ents if _normalise_ner_label(ent.label_)]


def _entity_from_spacy(ent: Any) -> DetectedEntity:
    """Map a spaCy entity into the gateway's canonical labels."""
    return DetectedEntity(
        label=_normalise_ner_label(ent.label_),
        value=ent.text,
        start=ent.start_char,
        end=ent.end_char,
        stage="ner",
    )


def _normalise_ner_label(label: str) -> str:
    """Normalise Danish and English spaCy entity labels."""
    return NER_LABEL_MAP.get(label, "")


def _risk_level(entities: list[DetectedEntity]) -> str:
    """Calculate risk, leaving GPE-only detections as ALLOW by default."""
    labels = {entity.label for entity in entities}
    if labels & HIGH_RISK_LABELS:
        return "HIGH"
    if labels & LOW_RISK_LABELS:
        return "LOW"
    return "NONE"


def _sort_entities(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    """Sort entities by prompt position to keep demo output stable."""
    return sorted(entities, key=lambda entity: (entity.start, entity.end, entity.label))

