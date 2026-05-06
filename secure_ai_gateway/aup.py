"""Acceptable Use Policy — adresserer Gap G6: dansk governance-feedback til brugeren.

Blocked prompts receive a clear Danish explanation that ties the gateway's proxy
control to organisational AI policy and the DORA/NIS2 third-party ICT risk basis.
"""

from __future__ import annotations


POLICY_REFERENCE = (
    "Organisationens AI-brugspolitik § 3.2 — Fortrolige data må ikke sendes til "
    "eksterne LLM-tjenester."
)
REGULATORY_BASIS = (
    "DORA artikel 28 / NIS2 artikel 21 — Krav om teknisk kontrol af "
    "IKT-tredjepartsrisiko."
)
ACTION_REQUIRED = (
    "Fjern venligst fortrolige data fra din forespørgsel. Kontakt IT-sikkerhed "
    "for godkendt alternativ."
)

ENTITY_NAMES = {
    "CPR_NUMBER": "CPR-nummer",
    "IBAN": "IBAN",
    "API_KEY": "API-nøgle",
    "CREDIT_CARD": "kreditkortnummer",
    "EMAIL": "emailadresse",
    "PERSON": "personnavn",
    "ORG": "organisationsnavn",
    "GPE": "lokation",
}


def blocked_message(entity_labels: list[str], request_id: str) -> dict[str, str | bool]:
    """Build the Danish AUP response body for blocked prompts."""
    entity_type = _blocked_entity_type(entity_labels)
    return {
        "blocked": True,
        "message": f"Blokeret: {entity_type} detekteret i din prompt.",
        "policy_reference": POLICY_REFERENCE,
        "regulatory_basis": REGULATORY_BASIS,
        "action_required": ACTION_REQUIRED,
        "request_id": request_id,
    }


def warning_header_value() -> str:
    """Return the Danish warning header for masked prompts."""
    return "Følsomme data maskeret. Se IT-sikkerhedspolitik."


def _blocked_entity_type(entity_labels: list[str]) -> str:
    """Prefer the entity type that caused a BLOCK decision."""
    for label in ("CPR_NUMBER", "IBAN", "API_KEY"):
        if label in entity_labels:
            return ENTITY_NAMES[label]
    return ENTITY_NAMES.get(entity_labels[0], "fortrolige data") if entity_labels else "fortrolige data"
