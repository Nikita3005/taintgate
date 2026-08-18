from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from .models import ApprovalAction, ArgumentSummary, AuditEvent, ProvenanceSummary


class AuditSink(Protocol):
    def write(self, event: AuditEvent) -> None:
        """Persist a sanitized audit event."""


class JsonlAuditSink:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def write(self, event: AuditEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = _serialize_event(event)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")


JsonlAuditLog = JsonlAuditSink


def _serialize_event(event: AuditEvent) -> dict[str, object]:
    return {
        "schema_version": event.schema_version,
        "timestamp": event.timestamp,
        "event_id": event.event_id,
        "tool": event.tool,
        "policy_action": event.policy_action.value,
        "risk_score": event.risk_score,
        "matched_policies": list(event.matched_policies),
        "finding_ids": list(event.finding_ids),
        "provenance": [_serialize_provenance(item) for item in event.provenance],
        "argument_summary": [_serialize_summary(item) for item in event.argument_summary],
        "tool_metadata": {
            "side_effecting": event.tool_metadata.side_effecting,
            "external_destination": event.tool_metadata.external_destination,
            "destructive": event.tool_metadata.destructive,
        },
        "approval_action": _serialize_approval_action(event.approval_action),
        "execution_state": event.execution_state.value,
        "error_type": event.error_type,
    }


def _serialize_summary(summary: ArgumentSummary) -> dict[str, object]:
    return {
        "path": summary.path,
        "python_type": summary.python_type,
        "string_length": summary.string_length,
        "collection_size": summary.collection_size,
        "trust": summary.trust.value if summary.trust is not None else None,
        "source_type": summary.source_type,
        "origin": summary.origin,
        "truncated": summary.truncated,
    }


def _serialize_provenance(summary: ProvenanceSummary) -> dict[str, object]:
    return {
        "path": summary.path,
        "trust": summary.trust.value,
        "source_type": summary.source_type,
        "origin": summary.origin,
    }


def _serialize_approval_action(action: ApprovalAction | None) -> str | None:
    if action is None:
        return None
    return action.value
