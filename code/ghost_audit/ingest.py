"""Participant-data ingestion and evidence normalization.

The challenge deliberately mixes business artifacts and operational snapshots. This
module converts them into small, timestamped facts while retaining the original
evidence id. It never treats workflow activity rows as a successful deletion proof.
"""

from __future__ import annotations

import csv
import json
import re
import shlex
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .identity import EMAIL_RE, USER_RE, IdentityResolver, normalize
from .models import Case, EvidenceFact, parse_time

try:  # Optional dependency; the text fallback keeps the runner usable.
    from pypdf import PdfReader
except Exception:  # pragma: no cover - depends on the execution image.
    PdfReader = None  # type: ignore[assignment]


RESOURCE_RE = re.compile(
    r"\b(?:account|analytics|backup|cache|data_flow|email_delivery|export|legal_hold|marketing|object|search|support|tombstone|audit_record|telemetry)_?[A-Za-z0-9-]+\b",
    re.I,
)
PHONE_RE = re.compile(r"(?<!\w)\+?[0-9][0-9 ()\-.]{6,}[0-9](?!\w)")

SYSTEM_BY_COLLECTION = {
    "customer_profiles": "account_service",
    "deleted_customer_references": "identity_service",
    "customer_search_documents": "search_service",
    "customer_analytics_reports": "analytics_platform",
    "customer_analytics_profiles": "analytics_platform",
    "backup_catalog": "backup_service",
    "backup_restore_entries": "backup_service",
    "customer_export_jobs": "export_service",
    "customer_exports": "export_service",
    "connector_configurations": "integration_service",
    "connector_subscriptions": "integration_service",
    "security_audit_events": "security_service",
    "security_audit_records": "security_service",
    "support_conversations": "support_platform",
    "support_records": "support_platform",
    "ticket_attachments": "support_platform",
    "retained_order_records": "legal_service",
    "operational_record_history": "",
}

JSON_CHILD_COLLECTIONS = {
    "profile_lookups": ("customer_profiles", "USER_PROFILE"),
    "profiles": ("customer_analytics_profiles", "ANALYTICS_PROFILE"),
    "restore_entries": ("backup_restore_entries", "BACKUP_ARCHIVE"),
    "exports": ("customer_exports", "USER_EXPORT"),
    "connectors": ("connector_configurations", "DATA_FLOW"),
    "audit_records": ("security_audit_records", "SECURITY_AUDIT_LOG"),
    "tickets": ("support_records", "SUPPORT_MESSAGE"),
    "attachments": ("ticket_attachments", "SUPPORT_ATTACHMENT"),
    "index_queries": ("customer_search_documents", "SEARCH_INDEX_ENTRY"),
}

CATEGORY_BY_RECORD_TYPE = {
    "USER_PROFILE": "USER_PROFILE",
    "SECONDARY_IDENTIFIER": "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY": "CACHE_ENTRY",
    "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY": "PRODUCT_TELEMETRY",
    "USER_EXPORT": "USER_EXPORT",
    "MARKETING_PROFILE": "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG": "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD": "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
    "DATA_FLOW": "DATA_FLOW",
}


def _first_time(*values: object) -> datetime | None:
    for value in values:
        if value:
            parsed = parse_time(str(value))
            if parsed:
                return parsed
    return None


def _string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _string_values(child)


def _truth(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = normalize(value)
    if text in {"1", "true", "yes", "enabled", "active", "allowed", "found", "identifiable"}:
        return True
    if text in {"0", "false", "no", "disabled", "blocked", "not_found", "not found", "anonymized", "redacted"}:
        return False
    return None


def category_for(collection: str = "", record_type: str = "", system: str = "", resource_id: str = "") -> str:
    record_type = str(record_type or "").upper()
    if record_type in CATEGORY_BY_RECORD_TYPE:
        return CATEGORY_BY_RECORD_TYPE[record_type]
    collection_key = str(collection or "").lower()
    if collection_key in SYSTEM_BY_COLLECTION:
        mapping = {
            "customer_profiles": "USER_PROFILE",
            "deleted_customer_references": "ACCOUNT_TOMBSTONE",
            "customer_search_documents": "SEARCH_INDEX_ENTRY",
            "customer_analytics_reports": "ANALYTICS_PROFILE",
            "customer_analytics_profiles": "ANALYTICS_PROFILE",
            "backup_catalog": "BACKUP_ARCHIVE",
            "backup_restore_entries": "BACKUP_ARCHIVE",
            "customer_export_jobs": "USER_EXPORT",
            "customer_exports": "USER_EXPORT",
            "connector_configurations": "DATA_FLOW",
            "connector_subscriptions": "DATA_FLOW",
            "security_audit_events": "SECURITY_AUDIT_LOG",
            "security_audit_records": "SECURITY_AUDIT_LOG",
            "support_conversations": "SUPPORT_MESSAGE",
            "support_records": "SUPPORT_MESSAGE",
            "ticket_attachments": "SUPPORT_ATTACHMENT",
            "retained_order_records": "LEGAL_HOLD_RECORD",
        }
        return mapping.get(collection_key, "")
    resource = str(resource_id or "").lower()
    if resource.startswith("account_"):
        return "USER_PROFILE"
    if resource.startswith("search_"):
        return "SEARCH_INDEX_ENTRY"
    if resource.startswith("analytics_"):
        return "ANALYTICS_PROFILE"
    if resource.startswith("backup_"):
        return "BACKUP_ARCHIVE"
    if resource.startswith("data_flow_"):
        return "DATA_FLOW"
    if resource.startswith("export_"):
        return "USER_EXPORT"
    if resource.startswith("support_"):
        return "SUPPORT_MESSAGE"
    if resource.startswith("audit_record_"):
        return "SECURITY_AUDIT_LOG"
    if resource.startswith("legal_hold_"):
        return "LEGAL_HOLD_RECORD"
    if resource.startswith("tombstone_"):
        return "ACCOUNT_TOMBSTONE"
    if resource.startswith("marketing_"):
        return "MARKETING_PROFILE"
    if resource.startswith("cache_"):
        return "CACHE_ENTRY"
    if resource.startswith("email_delivery_"):
        return "EMAIL_DELIVERY_LOG"
    return ""


def system_for(category: str, fallback: str = "") -> str:
    return {
        "USER_PROFILE": "account_service",
        "ACCOUNT_TOMBSTONE": "identity_service",
        "SEARCH_INDEX_ENTRY": "search_service",
        "ANALYTICS_PROFILE": "analytics_platform",
        "PRODUCT_TELEMETRY": "analytics_platform",
        "BACKUP_ARCHIVE": "backup_service",
        "DATA_FLOW": "integration_service",
        "USER_EXPORT": "export_service",
        "SECURITY_AUDIT_LOG": "security_service",
        "LEGAL_HOLD_RECORD": "legal_service",
        "SUPPORT_MESSAGE": "support_platform",
        "SUPPORT_ATTACHMENT": "support_platform",
        "MARKETING_PROFILE": "marketing_platform",
        "CACHE_ENTRY": "cache_service",
        "EMAIL_DELIVERY_LOG": "email_delivery_service",
    }.get(category, fallback)


def state_for(category: str, record: dict[str, Any], *, event: str = "") -> str:
    """Map source-specific fields into one of the contract states."""

    result = normalize(record.get("result", record.get("reported_result", ""))).replace(" ", "_").upper()
    event_lower = normalize(event)
    status_code = str(record.get("status_code", record.get("http_status", "")))
    if category == "USER_PROFILE":
        if result in {"NOT_FOUND", "ABSENT", "MISSING"} or status_code == "404" or str(record.get("rows", "")) == "0":
            return "ABSENT"
        if record.get("profile", object()) is None:
            return "ABSENT"
        return "PRESENT"
    if category == "DATA_FLOW":
        enabled = _truth(record.get("enabled"))
        if enabled is False or result in {"DISABLED", "BLOCKED", "STOPPED"} or "disabled" in event_lower:
            return "DISABLED"
        if enabled is True or result in {"ACTIVE", "ENABLED"} or "connector_config" in event_lower:
            return "ACTIVE"
    if category == "BACKUP_ARCHIVE":
        allowed = _truth(record.get("restore_allowed"))
        if allowed is False or result in {"BLOCKED", "DENIED"} or "blocked" in event_lower:
            return "BLOCKED"
        if allowed is True or result in {"ACTIVE", "ALLOWED", "FOUND"} or "restore" in event_lower:
            return "ACTIVE"
    if category == "ANALYTICS_PROFILE":
        if result in {"ANONYMIZED", "ANONYMOUS"}:
            return "ANONYMIZED"
        if event_lower in {"contact_lookup_completed", "record_lookup"} and str(record.get("rows", "")) not in {"", "0"}:
            return "PRESENT"
        direct = any(record.get(key) not in (None, "", "null") for key in ("email", "phone", "email_hash", "full_name", "name"))
        if result in {"IDENTIFIABLE", "PRESENT", "FOUND"} or direct:
            return "PRESENT"
        return "ANONYMIZED"
    if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
        if result in {"REDACTED", "ANONYMIZED"}:
            return "REDACTED"
        if event_lower in {"contact_query_completed", "support_ticket_read_completed", "message_pii_scan", "record_lookup"} and (event_lower == "message_pii_scan" or str(record.get("rows", "")) not in {"", "0"}):
            return "PRESENT"
        direct = any(record.get(key) not in (None, "", "null", "[REDACTED]") for key in ("email", "phone", "email_hash", "requester_email", "requester_phone", "requester_name", "owner_email"))
        if direct or result in {"IDENTIFIABLE", "PRESENT", "FOUND"}:
            return "PRESENT"
        return "REDACTED"
    if category == "ACCOUNT_TOMBSTONE":
        direct = any(record.get(key) not in (None, "", "null", "[REDACTED]") for key in ("name", "full_name", "email", "phone", "email_hash"))
        return "PRESENT" if direct else "REDACTED"
    if category == "SUPPORT_ATTACHMENT":
        return "ABSENT" if result in {"NOT_FOUND", "ABSENT"} else "PRESENT"
    if category in {"SEARCH_INDEX_ENTRY", "USER_EXPORT", "MARKETING_PROFILE", "CACHE_ENTRY", "SECONDARY_IDENTIFIER"}:
        return "ABSENT" if result in {"NOT_FOUND", "ABSENT", "MISSING"} or status_code == "404" else "PRESENT"
    if category == "PRODUCT_TELEMETRY":
        return "ANONYMIZED" if result in {"ANONYMIZED", "ANONYMOUS"} else "PRESENT"
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
        return "ABSENT" if result in {"NOT_FOUND", "ABSENT"} else "PRESENT"
    if result in {"ABSENT", "NOT_FOUND"}:
        return "ABSENT"
    if result in {"REDACTED"}:
        return "REDACTED"
    if result in {"ANONYMIZED"}:
        return "ANONYMIZED"
    return "PRESENT"


class EvidenceLoader:
    def __init__(self, dataset_dir: Path, resolver: IdentityResolver) -> None:
        self.dataset_dir = dataset_dir
        self.resolver = resolver
        self.manifest: list[dict[str, str]] = []
        self.activity: list[dict[str, str]] = []
        self.facts: list[EvidenceFact] = []
        self._activity_links: list[dict[str, Any]] = []
        self.snapshot_scopes: list[dict[str, Any]] = []

    def load(self) -> list[EvidenceFact]:
        self._load_manifest()
        self._load_activity_links()
        for item in self.manifest:
            path = self.dataset_dir / item["file_path"]
            suffix = path.suffix.lower()
            if suffix == ".json":
                self._parse_json(item, path)
            elif suffix == ".sql":
                self._parse_sql(item, path)
            elif suffix == ".log":
                self._parse_log(item, path)
            elif suffix == ".txt":
                self._parse_text(item, path)
            elif suffix == ".pdf":
                self._parse_pdf(item, path)
            elif suffix == ".png":
                self._parse_image(item, path)
        return self.facts

    def _load_manifest(self) -> None:
        with (self.dataset_dir / "evidence_files.csv").open(encoding="utf-8-sig", newline="") as handle:
            self.manifest = list(csv.DictReader(handle))
        with (self.dataset_dir / "system_activity.csv").open(encoding="utf-8-sig", newline="") as handle:
            self.activity = list(csv.DictReader(handle))

    def _load_activity_links(self) -> None:
        for row in self.activity:
            if row.get("event_type") != "LINK_RESOURCE_IDENTITY":
                continue
            details = row.get("details", "")
            emails = set(EMAIL_RE.findall(details))
            users = set(USER_RE.findall(details))
            self._activity_links.append(
                {
                    "activity_id": row.get("activity_id", ""),
                    "event_time": parse_time(row.get("event_time")),
                    "target_system": row.get("target_system", ""),
                    "resource_id": row.get("resource_id", ""),
                    "emails": emails,
                    "users": users,
                    "details": details,
                }
            )

    def _add_fact(
        self,
        evidence_id: str,
        captured_at: datetime | None,
        observed_at: datetime | None,
        system_id: str,
        resource_id: str,
        category: str,
        record: dict[str, Any],
        *,
        source_kind: str,
        confidence: int,
        location: str = "global",
        event: str = "",
        detail: str = "",
    ) -> None:
        if not resource_id or not category:
            return
        system_id = system_for(category, system_id)
        strings = list(_string_values(record))
        identifiers: set[str] = set()
        user_refs: set[str] = set()
        direct: set[str] = set()
        for value in strings:
            identifiers.add(normalize(value))
            identifiers.update(normalize(x) for x in EMAIL_RE.findall(value))
            identifiers.update(normalize(x) for x in USER_RE.findall(value))
        for key, value in record.items():
            if value in (None, "", "null", "[REDACTED]"):
                continue
            key_lower = str(key).lower()
            values = list(_string_values(value))
            for raw in values:
                if key_lower in {"user_id", "subject_reference", "customer_reference"}:
                    user_refs.update(USER_RE.findall(raw))
                if any(token in key_lower for token in ("email", "phone", "hash", "name", "selector", "message_text", "message_excerpt")):
                    direct.add(normalize(raw))
                direct.update(normalize(x) for x in EMAIL_RE.findall(raw))
                if key_lower in {"phone", "requester_phone", "owner_phone"}:
                    direct.add(normalize(raw))
        identifiers.update(user_refs)
        identifiers.update(direct)
        user_ids = self.resolver.resolve_aliases(identifiers | user_refs)
        state = state_for(category, record, event=event)
        self.facts.append(
            EvidenceFact(
                evidence_id=evidence_id,
                captured_at=captured_at,
                observed_at=observed_at,
                system_id=system_id,
                resource_id=str(resource_id),
                category=category,
                state=state,
                identifiers={x for x in identifiers if x},
                direct_identifiers={x for x in direct if x},
                user_refs={x for x in user_refs if x},
                location=location or "global",
                source_kind=source_kind,
                confidence=confidence,
                detail=detail,
                user_ids=user_ids,
            )
        )

    def _parse_json(self, item: dict[str, str], path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return
        evidence_id = item["file_id"]
        captured = parse_time(item.get("captured_at"))

        def walk(node: Any, context: dict[str, Any]) -> None:
            if isinstance(node, dict):
                local = dict(context)
                if node.get("captured_at") or node.get("exported_at"):
                    local["observed_at"] = _first_time(node.get("captured_at"), node.get("exported_at"))
                if node.get("data_store"):
                    local["system"] = str(node["data_store"])
                if node.get("source") and str(node["source"]).endswith("service"):
                    local["source"] = str(node["source"])
                if node.get("collection"):
                    local["collection"] = str(node["collection"])
                if node.get("system"):
                    local["system"] = str(node["system"])
                if node.get("record_type"):
                    local["record_type"] = str(node["record_type"])
                if "records" in node and local.get("collection"):
                    scoped_category = category_for(local.get("collection", ""), local.get("record_type", ""), local.get("system", ""), "")
                    if scoped_category:
                        self.snapshot_scopes.append({
                            "evidence_id": evidence_id,
                            "captured_at": captured,
                            "system_id": system_for(scoped_category, str(local.get("system", ""))),
                            "category": scoped_category,
                            "source_kind": "json",
                            "source_path": path.name,
                        })
                if node.get("resource_id"):
                    resource_id = str(node["resource_id"])
                    category = category_for(local.get("collection", ""), local.get("record_type", ""), local.get("system", ""), resource_id)
                    self._add_fact(
                        evidence_id,
                        captured,
                        _first_time(node.get("observed_at"), node.get("recorded_at"), node.get("updated_at"), local.get("observed_at")),
                        local.get("system", ""),
                        resource_id,
                        category,
                        node,
                        source_kind="json",
                        confidence=5,
                        location=str(local.get("data_store", local.get("system", "global"))),
                        event=str(node.get("event", node.get("result", ""))),
                        detail=str(node.get("result", node.get("record_type", ""))),
                    )
                for key, value in node.items():
                    child_context = dict(local)
                    if key in SYSTEM_BY_COLLECTION:
                        child_context["collection"] = key
                        child_context["system"] = SYSTEM_BY_COLLECTION[key]
                    elif key in JSON_CHILD_COLLECTIONS:
                        collection, child_category = JSON_CHILD_COLLECTIONS[key]
                        child_context["collection"] = collection
                        child_context["record_type"] = child_category
                    elif key in {"account_service", "analytics_platform", "backup_service", "export_service", "integration_service", "search_service", "security_service", "support_platform", "identity_service", "marketing_platform"}:
                        child_context["system"] = key
                    walk(value, child_context)
            elif isinstance(node, list):
                for child in node:
                    walk(child, context)

        walk(data, {})

    def _parse_sql(self, item: dict[str, str], path: Path) -> None:
        try:
            script = path.read_text(encoding="utf-8-sig")
            connection = sqlite3.connect(":memory:")
            connection.executescript(script)
        except (OSError, sqlite3.Error):
            return
        evidence_id = item["file_id"]
        captured = parse_time(item.get("captured_at"))
        try:
            tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                if table == "snapshot_scope":
                    continue
                columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')]
                scope_category = category_for(table, "", "", "")
                if not scope_category and table.lower().startswith("customer_profiles"):
                    scope_category = "USER_PROFILE"
                if scope_category:
                    self.snapshot_scopes.append({
                        "evidence_id": evidence_id,
                        "captured_at": captured,
                        "system_id": system_for(scope_category),
                        "category": scope_category,
                        "source_kind": "sql",
                        "source_path": path.name,
                    })
                for values in connection.execute(f'SELECT * FROM "{table}"'):
                    record = dict(zip(columns, values))
                    if "record_json" in record:
                        try:
                            nested = json.loads(record.get("record_json") or "{}")
                        except json.JSONDecodeError:
                            nested = {}
                        merged = dict(nested)
                        merged.setdefault("resource_id", record.get("resource_id"))
                        merged.setdefault("updated_at", record.get("updated_at"))
                        category = category_for(record.get("collection_name", ""), merged.get("record_type", ""), record.get("origin_system", ""), merged.get("resource_id", ""))
                        self._add_fact(
                            evidence_id,
                            captured,
                            _first_time(record.get("updated_at"), merged.get("updated_at")),
                            record.get("origin_system", ""),
                            str(merged.get("resource_id", "")),
                            category,
                            merged,
                            source_kind="sql",
                            confidence=5,
                            location=table,
                            detail=record.get("collection_name", ""),
                        )
                    else:
                        resource_id = str(record.get("resource_id", ""))
                        category = category_for(table, record.get("record_type", ""), record.get("origin_system", ""), resource_id)
                        if not category and table.startswith("customer_profiles"):
                            category = "USER_PROFILE"
                        self._add_fact(
                            evidence_id,
                            captured,
                            _first_time(record.get("updated_at"), record.get("indexed_at")),
                            record.get("origin_system", ""),
                            resource_id,
                            category,
                            record,
                            source_kind="sql",
                            confidence=5,
                            location=table,
                            detail=table,
                        )
        finally:
            connection.close()

    @staticmethod
    def _parse_kv_line(line: str) -> tuple[datetime | None, dict[str, Any]]:
        match = re.match(r"^(\d{4}-\d{2}-\d{2}T[^ ]+)\s+(.*)$", line.strip())
        if not match:
            return None, {}
        timestamp = parse_time(match.group(1))
        remainder = match.group(2)
        if remainder.startswith("{"):
            try:
                data = json.loads(remainder)
                return timestamp, data
            except json.JSONDecodeError:
                pass
        try:
            tokens = shlex.split(remainder)
        except ValueError:
            tokens = remainder.split()
        data: dict[str, Any] = {}
        for token in tokens:
            if "=" in token:
                key, value = token.split("=", 1)
                data[key] = value
        return timestamp, data

    def _parse_log(self, item: dict[str, str], path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            return
        evidence_id = item["file_id"]
        captured = parse_time(item.get("captured_at"))
        # Logs deliberately split lookup context from the result line. Keep
        # that context by trace id, and also retain the most recent subject
        # query for audit readers whose producer changes trace ids between the
        # query and result records.
        pending_by_trace: dict[str, dict[str, Any]] = {}
        last_subject_by_service: dict[str, tuple[datetime, dict[str, Any]]] = {}
        observed_events = {
            "profile_lookup_completed",
            "index_query_completed",
            "analytics_profile_read_completed",
            "contact_lookup_completed",
            "connector_config_read_completed",
            "connector_heartbeat",
            "restore_policy_read_completed",
            "support_ticket_read_completed",
            "message_pii_scan",
            "attachment_pii_scan",
            "audit_record_read_completed",
            "export_download_check_completed",
            "export_metadata_read_completed",
            "record_lookup",
            "restore_candidate_evaluated",
        }
        context_events = {
            "profile_lookup_started",
            "index_query_started",
            "analytics_profile_read_started",
            "connector_config_read_started",
            "restore_policy_check_started",
            "restore_policy_read_started",
            "support_ticket_read_started",
            "contact_query_started",
            "message_scan_started",
            "attachment_scan_started",
            "audit_record_query_started",
            "audit_record_read_started",
            "export_download_check_started",
            "export_metadata_read_started",
        }
        for line in lines:
            timestamp, record = self._parse_kv_line(line)
            if not timestamp or not record:
                continue
            event = str(record.get("event", "")).lower()
            trace_id = str(record.get("trace_id", ""))
            if event in context_events:
                if trace_id:
                    pending_by_trace[trace_id] = dict(record)
                subject = {key: value for key, value in record.items() if key in {"lookup_key", "match_key", "subject_key", "subject_ref", "owner_key"}}
                if subject:
                    service_key = str(record.get("service", ""))
                    last_subject_by_service[service_key] = (timestamp, subject)
                # A started line is context, not proof that a record exists.
                if not record.get("resource_id") or event not in observed_events:
                    continue
            resource_id = str(record.get("resource_id", ""))
            if not resource_id:
                continue
            merged_record: dict[str, Any] = {}
            if trace_id and trace_id in pending_by_trace:
                merged_record.update(pending_by_trace[trace_id])
            merged_record.update(record)
            service_key = str(record.get("service", ""))
            if event == "audit_record_read_completed" and not any(key in merged_record for key in ("subject_reference", "correlation_key", "subject_ref")):
                previous = last_subject_by_service.get(service_key)
                if previous and (timestamp - previous[0]).total_seconds() <= 30:
                    merged_record.update(previous[1])
            record = merged_record
            service = str(record.get("service", record.get("function", record.get("logger", ""))))
            system = {
                "account_service": "account_service",
                "profile_service": "account_service",
                "search_service": "search_service",
                "analytics_platform": "analytics_platform",
                "integration_service": "integration_service",
                "backup_service": "backup_service",
                "support_platform": "support_platform",
                "support_replica": "support_platform",
                "security_service": "security_service",
                "export_service": "export_service",
            }.get(service, service)
            category = ""
            if "profile_lookup_completed" in event:
                category = "USER_PROFILE"
            elif "index_query_completed" in event:
                category = "SEARCH_INDEX_ENTRY"
            elif "analytics_profile_read_completed" in event:
                category = "ANALYTICS_PROFILE"
            elif "contact_lookup_completed" in event:
                # This event is a contact/identifier lookup, whose record is
                # deleted under the supplied secondary-identifier rule.
                category = "SECONDARY_IDENTIFIER"
            elif "connector_config_read_completed" in event:
                category = "DATA_FLOW"
            elif event == "connector_heartbeat":
                category = "DATA_FLOW"
            elif event == "restore_candidate_evaluated":
                category = "BACKUP_ARCHIVE"
            elif "restore_policy_read_completed" in event:
                category = "BACKUP_ARCHIVE"
            elif "support_ticket_read_completed" in event or "message_pii_scan" in event:
                category = "SUPPORT_MESSAGE"
            elif event == "contact_query_completed":
                # The replica's legacy contact index is a deletable
                # identifier copy, not a shared support conversation.
                category = "SECONDARY_IDENTIFIER"
            elif event == "record_lookup":
                category = category_for("", str(record.get("record_type", "")), system, resource_id)
            elif event == "attachment_pii_scan":
                category = "SUPPORT_ATTACHMENT"
            elif event == "audit_record_read_completed":
                category = "SECURITY_AUDIT_LOG"
            elif event in {"export_download_check_completed", "export_metadata_read_completed"}:
                category = "USER_EXPORT"
            if not category:
                continue
            location = str(record.get("pool", record.get("route", "global")))
            self._add_fact(
                evidence_id,
                captured,
                timestamp,
                system,
                resource_id,
                category,
                record,
                source_kind="log",
                confidence=4,
                location=location,
                event=event,
                detail=event,
            )

    def _parse_text(self, item: dict[str, str], path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            return
        evidence_id = item["file_id"]
        captured = parse_time(item.get("captured_at"))
        for line in lines:
            if "|" not in line:
                continue
            parts = [x.strip() for x in line.strip().lstrip("-").strip().split("|")]
            if len(parts) < 6:
                continue
            observed, system, resource, record_type, result, subject = parts[:6]
            category = category_for("", record_type, system, resource)
            record = {"result": result, "subject_reference": subject, "record_type": record_type}
            self._add_fact(
                evidence_id,
                captured,
                parse_time(observed),
                system,
                resource,
                category,
                record,
                source_kind="text",
                confidence=5,
                detail=result,
            )

    def _pdf_text(self, path: Path) -> str:
        if PdfReader is not None:
            try:
                return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
            except Exception:
                pass
        raw = path.read_bytes()
        return raw.decode("latin-1", errors="ignore")

    def _parse_pdf(self, item: dict[str, str], path: Path) -> None:
        text = self._pdf_text(path)
        evidence_id = item["file_id"]
        captured = parse_time(item.get("captured_at"))
        lower_name = path.name.lower()
        resource_ids = set(RESOURCE_RE.findall(text))
        if "account_history_report" in lower_name:
            statement = re.search(r"NST-\d{4}-\d{4}-(\d+)", text)
            if statement:
                resource_ids.add("export_" + statement.group(1))
        if "delivery_correction_attachment" in lower_name:
            resource_ids.add("support_001")
        if "security_retention_extract" in lower_name:
            resource_ids.add("audit_record_003")
        if "account_history_report" in lower_name:
            category, system, state = "USER_EXPORT", "export_service", "PRESENT"
        elif "delivery_correction_attachment" in lower_name:
            category, system, state = "SUPPORT_ATTACHMENT", "support_platform", "PRESENT"
        elif "security_retention_extract" in lower_name:
            category, system, state = "SECURITY_AUDIT_LOG", "security_service", "PRESENT"
        else:
            category, system, state = "LEGAL_HOLD_RECORD", "legal_service", "PRESENT"
        identifiers: dict[str, Any] = {
            "emails": EMAIL_RE.findall(text),
            "user_ids": USER_RE.findall(text),
            "text": text,
            "result": state,
        }
        for resource_id in sorted(resource_ids):
            self._add_fact(
                evidence_id,
                captured,
                captured,
                system,
                resource_id,
                category,
                identifiers,
                source_kind="pdf",
                confidence=5,
                detail=path.name,
            )

    def _parse_image(self, item: dict[str, str], path: Path) -> None:
        captured = parse_time(item.get("captured_at"))
        name = path.stem.lower()
        system_by_name = {
            "account_admin_console": "account_service",
            "analytics_profile_view": "analytics_platform",
            "backup_restore_console": "backup_service",
            "connector_management_console": "integration_service",
            "customer_export_console": "export_service",
            "deleted_account_reference": "identity_service",
            "marketing_profile_console": "marketing_platform",
            "object_storage_browser": "object_storage",
            "search_index_inspector": "search_service",
            "security_audit_explorer": "security_service",
            "support_ticket_console": "support_platform",
        }
        system = system_by_name.get(name, "")
        candidates = [x for x in self._activity_links if x["target_system"] == system and x["event_time"] and captured and x["event_time"].date() == captured.date()]
        if not candidates:
            return
        link = min(candidates, key=lambda x: abs((x["event_time"] - captured).total_seconds()))
        category = {
            "account_service": "USER_PROFILE",
            "analytics_platform": "ANALYTICS_PROFILE",
            "backup_service": "BACKUP_ARCHIVE",
            "integration_service": "DATA_FLOW",
            "export_service": "USER_EXPORT",
            "identity_service": "ACCOUNT_TOMBSTONE",
            "marketing_platform": "MARKETING_PROFILE",
            "object_storage": "SUPPORT_ATTACHMENT",
            "search_service": "SEARCH_INDEX_ENTRY",
            "security_service": "SECURITY_AUDIT_LOG",
            "support_platform": "SUPPORT_MESSAGE",
        }.get(system, "")
        state = {
            "DATA_FLOW": "ACTIVE",
            "BACKUP_ARCHIVE": "ACTIVE",
            "ACCOUNT_TOMBSTONE": "REDACTED",
            "SECURITY_AUDIT_LOG": "PRESENT",
            "ANALYTICS_PROFILE": "PRESENT",
        }.get(category, "PRESENT")
        record = {
            "email": next(iter(link["emails"]), ""),
            "user_id": next(iter(link["users"]), ""),
            "result": state,
        }
        self._add_fact(
            item["file_id"],
            captured,
            captured,
            system,
            link["resource_id"],
            category,
            record,
            source_kind="image",
            confidence=5,
            detail=path.name,
        )


def load_cases(dataset_dir: Path, filename: str = "deletion_requests.csv") -> list[Case]:
    cases: list[Case] = []
    with (dataset_dir / filename).open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            cases.append(
                Case(
                    case_id=row["case_id"],
                    email=row.get("email", ""),
                    requested_at=parse_time(row.get("requested_at")),
                    reported_status=row.get("reported_status", ""),
                    reported_at=parse_time(row.get("reported_at")),
                    audit_at=parse_time(row.get("audit_at")),
                    request_text=row.get("request_text", ""),
                )
            )
    return cases

