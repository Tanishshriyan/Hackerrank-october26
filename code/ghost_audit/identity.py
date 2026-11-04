"""Current and historical identifier resolution."""

from __future__ import annotations

import csv
import re
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from .models import Identity, parse_time


EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.I)
USER_RE = re.compile(r"\buser_\d+\b", re.I)


def normalize(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip().casefold()
    return " ".join(text.split())


def normalize_email(value: object) -> str:
    return normalize(value)


def normalize_name(value: object) -> str:
    text = normalize(value)
    return re.sub(r"[^\w]+", " ", text, flags=re.UNICODE).strip()


def all_emails(text: object) -> set[str]:
    return {normalize_email(x) for x in EMAIL_RE.findall(str(text or ""))}


class IdentityResolver:
    def __init__(self, dataset_dir: Path) -> None:
        self.dataset_dir = dataset_dir
        self.identities: dict[str, Identity] = {}
        self.identifier_users: dict[str, set[str]] = defaultdict(set)
        self.user_aliases: dict[str, set[str]] = defaultdict(set)
        self._load()

    def _add(self, user_id: str, value: object, *, name: bool = False) -> None:
        if not value:
            return
        key = normalize_name(value) if name else normalize(value)
        if not key:
            return
        self.user_aliases[user_id].add(key)
        self.identifier_users[key].add(user_id)

    def _load(self) -> None:
        identity_path = self.dataset_dir / "user_identities.csv"
        audit_path = self.dataset_dir / "user_audit_log.csv"
        with identity_path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                identity = Identity(
                    user_id=row["user_id"],
                    name=row.get("name", ""),
                    email=row.get("email", ""),
                    phone=row.get("phone", ""),
                    email_hash=row.get("email_hash", ""),
                    updated_at=parse_time(row.get("updated_at")),
                )
                self.identities[identity.user_id] = identity
                self._add(identity.user_id, identity.user_id)
                self._add(identity.user_id, identity.name, name=True)
                self._add(identity.user_id, identity.email)
                self._add(identity.user_id, identity.phone)
                self._add(identity.user_id, identity.email_hash)

        with audit_path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                user_id = row.get("user_id", "")
                if user_id not in self.identities:
                    continue
                field = row.get("field_name", "")
                # Historical names are not present in this dataset. Keep this
                # branch explicit so a future field cannot silently become a
                # false identity match.
                if field in {"email", "email_hash", "phone"}:
                    self._add(user_id, row.get("old_value"))
                    self._add(user_id, row.get("new_value"))
                    self.identities[user_id].aliases.update(
                        x for x in (normalize(row.get("old_value")), normalize(row.get("new_value"))) if x
                    )

    def resolve_email(self, email: str) -> str | None:
        users = self.identifier_users.get(normalize_email(email), set())
        return next(iter(users)) if len(users) == 1 else None

    def resolve_aliases(self, values: Iterable[str]) -> set[str]:
        resolved: set[str] = set()
        for value in values:
            key = normalize(value)
            if not key:
                continue
            resolved.update(self.identifier_users.get(key, set()))
            name_key = normalize_name(value)
            resolved.update(self.identifier_users.get(name_key, set()))
        return resolved

    def aliases_for(self, user_id: str) -> set[str]:
        identity = self.identities[user_id]
        values = set(self.user_aliases.get(user_id, set()))
        values.update({normalize_name(identity.name), normalize(identity.user_id)})
        return {x for x in values if x}

    def explain(self, user_id: str, supplied_email: str) -> dict[str, object]:
        identity = self.identities[user_id]
        email_key = normalize_email(supplied_email)
        current = email_key == normalize_email(identity.email)
        return {
            "user_id": user_id,
            "supplied_email": supplied_email,
            "match_type": "current_email" if current else "historical_identifier",
            "current_email": identity.email,
            "alias_count": len(self.aliases_for(user_id)),
        }

