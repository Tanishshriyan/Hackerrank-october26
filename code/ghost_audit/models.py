"""Small, serializable domain models used by the audit pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class Identity:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime | None
    aliases: set[str] = field(default_factory=set)


@dataclass
class Case:
    case_id: str
    email: str
    requested_at: datetime | None
    reported_status: str
    reported_at: datetime | None
    audit_at: datetime | None
    request_text: str


@dataclass
class EvidenceFact:
    """One grounded observation extracted from one participant-facing source."""

    evidence_id: str
    captured_at: datetime | None
    observed_at: datetime | None
    system_id: str
    resource_id: str
    category: str
    state: str
    identifiers: set[str] = field(default_factory=set)
    direct_identifiers: set[str] = field(default_factory=set)
    user_refs: set[str] = field(default_factory=set)
    location: str = "global"
    source_kind: str = "structured"
    confidence: int = 3
    detail: str = ""
    user_ids: set[str] = field(default_factory=set)

    @property
    def effective_time(self) -> datetime | None:
        return self.observed_at or self.captured_at

    def valid_at(self, cutoff: datetime | None) -> bool:
        if cutoff is None:
            return True
        if self.captured_at and self.captured_at > cutoff:
            return False
        if self.observed_at and self.observed_at > cutoff:
            return False
        return True


@dataclass
class ResourceState:
    system_id: str
    resource_id: str
    category: str
    state: str
    evidence_id: str
    fact: EvidenceFact
    facts: list[EvidenceFact] = field(default_factory=list)


@dataclass
class AuditResult:
    case_id: str
    deletion_status: str
    steps: list[dict[str, Any]]

