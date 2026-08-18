from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import Finding, TaintedString, TaintedValue, ToolMetadata, Trust

_MAX_SCAN_DEPTH = 8
_MAX_SCAN_NODES = 1024
_SCAN_LIMIT_SCORE = 60
_PROMPT_INJECTION_SCORE = 20
_UNTRUSTED_PROMPT_INJECTION_SCORE = 55
_SECRET_SCORE = 75
_PII_EMAIL_SCORE = 15
_PII_PHONE_SCORE = 25
_PII_SSN_SCORE = 60
_SENSITIVE_PATH_SCORE = 55
_UNTRUSTED_TO_SIDE_EFFECT_SCORE = 35
_UNTRUSTED_TO_EXTERNAL_SCORE = 45
_SENSITIVE_TO_EXTERNAL_SCORE = 70

_SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("secret.openai_api_key", "OpenAI-style API key detected", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("secret.aws_access_key", "AWS access key detected", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret.github_token", "GitHub token detected", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    (
        "secret.bearer_token",
        "Bearer token detected",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE),
    ),
    (
        "secret.private_key",
        "Private key marker detected",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
)

_PII_PATTERNS: tuple[tuple[str, str, int, re.Pattern[str]], ...] = (
    (
        "pii.email",
        "Email address detected",
        _PII_EMAIL_SCORE,
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    ),
    (
        "pii.phone",
        "Phone number detected",
        _PII_PHONE_SCORE,
        re.compile(r"(?<!\w)(?:\+1[-.\s]?)?(?:\(\d{3}\)\s*|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b"),
    ),
    (
        "pii.us_ssn",
        "US SSN detected",
        _PII_SSN_SCORE,
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
)

_PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"reveal\s+(?:the\s+)?(?:system|developer)\s+prompt", re.IGNORECASE),
    re.compile(r"(?:retrieve|send|exfiltrate)\s+.{0,80}?(?:secret|credential|api[_ -]?key)", re.IGNORECASE),
)

_SHELL_DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|\s)rm\s+-rf\s+(?:/|~|/\*|~/\*|\*)", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\breboot\b", re.IGNORECASE),
    re.compile(r"\bmkfs(?:\.[A-Za-z0-9_]+)?\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=/dev/zero\b", re.IGNORECASE),
    re.compile(
        r"\bRemove-Item\b(?=.*\b-Recurse\b)(?=.*\b-Force\b)(?=.*(?:[A-Za-z]:\\\*|~\\\*|\$HOME\\\*))",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:del|erase)\b(?=.*(?:/s|/q))(?=.*[A-Za-z]:\\)", re.IGNORECASE),
)

_SQL_DROP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
)

_ROOT_SENSITIVE_PATHS = frozenset(
    {
        "$.to",
        "$.cc",
        "$.bcc",
        "$.recipient",
        "$.recipients",
        "$.email",
        "$.address",
    }
)
_SAFE_PATH_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


@dataclass(frozen=True)
class _WalkEntry:
    path: str
    value: Any
    trust: Trust | None
    origin: str | None
    source_type: str | None


@dataclass
class _WalkState:
    visited_ids: set[int]
    nodes_seen: int = 0
    limit_reached: bool = False


def collect_findings(
    tool: str,
    args: Mapping[str, Any],
    metadata: ToolMetadata | None = None,
) -> list[Finding]:
    entries, limit_reached = _scan_entries(args)
    effective_metadata = metadata or ToolMetadata()

    findings: list[Finding] = []
    findings.extend(detect_secrets(entries))
    findings.extend(detect_pii(entries))
    findings.extend(detect_prompt_injection(entries))
    findings.extend(detect_destructive(entries))
    findings.extend(detect_sensitive_paths(entries))
    findings.extend(detect_untrusted_to_side_effect(entries, metadata=effective_metadata))
    findings.extend(detect_untrusted_to_external(entries, metadata=effective_metadata))
    findings.extend(detect_sensitive_to_external(findings, metadata=effective_metadata))

    if limit_reached:
        findings.append(
            Finding(
                "runtime.scan_limit",
                "Security scan limit reached before traversal completed",
                _SCAN_LIMIT_SCORE,
                path="$",
            )
        )

    del tool  # reserved for future detector tuning without framework coupling
    return findings


def walk(
    value: Any,
    path: str = "$",
    inherited_trust: Trust | None = None,
    inherited_origin: str | None = None,
    inherited_source_type: str | None = None,
) -> Iterable[tuple[str, Any, Trust | None, str | None, str | None]]:
    entries, _limit_reached = _scan_entries(
        value,
        path=path,
        inherited_trust=inherited_trust,
        inherited_origin=inherited_origin,
        inherited_source_type=inherited_source_type,
    )
    for entry in entries:
        yield entry.path, entry.value, entry.trust, entry.origin, entry.source_type


def detect_secrets(entries: Sequence[_WalkEntry] | Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in _coerce_entries(entries):
        if not isinstance(entry.value, str):
            continue
        matched_rule_ids: set[str] = set()
        for rule_id, label, pattern in _SECRET_PATTERNS:
            if pattern.search(entry.value):
                if rule_id == "secret.bearer_token" and matched_rule_ids:
                    continue
                findings.append(Finding(rule_id, f"{label} at {entry.path}", _SECRET_SCORE, path=entry.path))
                matched_rule_ids.add(rule_id)
    return findings


def detect_pii(entries: Sequence[_WalkEntry] | Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in _coerce_entries(entries):
        if not isinstance(entry.value, str):
            continue
        for rule_id, label, score, pattern in _PII_PATTERNS:
            if pattern.search(entry.value):
                findings.append(Finding(rule_id, f"{label} at {entry.path}", score, path=entry.path))
    return findings


def detect_prompt_injection(entries: Sequence[_WalkEntry] | Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in _coerce_entries(entries):
        if not isinstance(entry.value, str):
            continue
        if not any(pattern.search(entry.value) for pattern in _PROMPT_INJECTION_PATTERNS):
            continue

        if entry.trust == Trust.UNTRUSTED:
            findings.append(
                Finding(
                    "input.prompt_injection",
                    f"Prompt-injection-like instruction from {_describe_origin(entry.origin, entry.source_type)} at {entry.path}",
                    _UNTRUSTED_PROMPT_INJECTION_SCORE,
                    path=entry.path,
                )
            )
            continue

        findings.append(
            Finding(
                "input.prompt_injection",
                f"Prompt-injection-like instruction detected at {entry.path}",
                _PROMPT_INJECTION_SCORE,
                path=entry.path,
            )
        )
    return findings


def detect_destructive(entries: Sequence[_WalkEntry] | Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(detect_destructive_shell(entries))
    findings.extend(detect_destructive_sql(entries))
    return findings


def detect_destructive_shell(entries: Sequence[_WalkEntry] | Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in _coerce_entries(entries):
        if not isinstance(entry.value, str):
            continue
        if any(pattern.search(entry.value) for pattern in _SHELL_DESTRUCTIVE_PATTERNS) or _is_windows_remove_item_destructive(
            entry.value
        ):
            findings.append(
                Finding(
                    "action.shell.destructive",
                    f"Destructive shell command detected at {entry.path}",
                    90,
                    path=entry.path,
                )
            )
    return findings


def detect_destructive_sql(entries: Sequence[_WalkEntry] | Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in _coerce_entries(entries):
        if not isinstance(entry.value, str):
            continue
        if any(pattern.search(entry.value) for pattern in _SQL_DROP_PATTERNS) or _has_delete_without_where(entry.value):
            findings.append(
                Finding(
                    "action.sql.destructive",
                    f"Destructive SQL statement detected at {entry.path}",
                    90,
                    path=entry.path,
                )
            )
    return findings


def detect_sensitive_paths(entries: Sequence[_WalkEntry] | Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in _coerce_entries(entries):
        if not isinstance(entry.value, str):
            continue
        if _is_sensitive_path(entry.value):
            findings.append(
                Finding(
                    "filesystem.sensitive_path",
                    f"Sensitive filesystem path detected at {entry.path}",
                    _SENSITIVE_PATH_SCORE,
                    path=entry.path,
                )
            )
    return findings


def detect_untrusted_to_side_effect(
    entries: Sequence[_WalkEntry] | Mapping[str, Any],
    *,
    metadata: ToolMetadata,
) -> list[Finding]:
    if not metadata.side_effecting:
        return []

    entry = _first_untrusted_entry(_coerce_entries(entries))
    if entry is None:
        return []

    return [
        Finding(
            "flow.untrusted_to_side_effect",
            f"Untrusted data from {_describe_origin(entry.origin, entry.source_type)} flows into side-effecting tool at {entry.path}",
            _UNTRUSTED_TO_SIDE_EFFECT_SCORE,
            path=entry.path,
        )
    ]


def detect_untrusted_to_external(
    entries: Sequence[_WalkEntry] | Mapping[str, Any],
    *,
    metadata: ToolMetadata,
) -> list[Finding]:
    if not (metadata.side_effecting and metadata.external_destination):
        return []

    entry = _first_untrusted_entry(_coerce_entries(entries))
    if entry is None:
        return []

    return [
        Finding(
            "flow.untrusted_to_external",
            f"Untrusted data from {_describe_origin(entry.origin, entry.source_type)} flows into side-effecting external tool at {entry.path}",
            _UNTRUSTED_TO_EXTERNAL_SCORE,
            path=entry.path,
        )
    ]


def detect_sensitive_to_external(
    findings: Sequence[Finding],
    *,
    metadata: ToolMetadata,
) -> list[Finding]:
    if not (metadata.side_effecting and metadata.external_destination):
        return []

    sensitive_paths = [
        finding.path
        for finding in findings
        if _is_sensitive_rule(finding.rule_id) and finding.path is not None and not _is_destination_path(finding.path)
    ]
    if not sensitive_paths:
        return []

    path = sensitive_paths[0]
    return [
        Finding(
            "flow.sensitive_to_external",
            f"Sensitive content detected at {path} flows into side-effecting external tool",
            _SENSITIVE_TO_EXTERNAL_SCORE,
            path=path,
        )
    ]


def _scan_entries(
    value: Any,
    *,
    path: str = "$",
    inherited_trust: Trust | None = None,
    inherited_origin: str | None = None,
    inherited_source_type: str | None = None,
) -> tuple[list[_WalkEntry], bool]:
    entries: list[_WalkEntry] = []
    state = _WalkState(visited_ids=set())
    _walk_value(
        value,
        path=path,
        inherited_trust=inherited_trust,
        inherited_origin=inherited_origin,
        inherited_source_type=inherited_source_type,
        depth=0,
        state=state,
        entries=entries,
    )
    return entries, state.limit_reached


def _walk_value(
    value: Any,
    *,
    path: str,
    inherited_trust: Trust | None,
    inherited_origin: str | None,
    inherited_source_type: str | None,
    depth: int,
    state: _WalkState,
    entries: list[_WalkEntry],
) -> None:
    if state.limit_reached:
        return
    if state.nodes_seen >= _MAX_SCAN_NODES or depth > _MAX_SCAN_DEPTH:
        state.limit_reached = True
        return
    state.nodes_seen += 1

    if isinstance(value, TaintedString):
        entries.append(
            _WalkEntry(
                path=path,
                value=str(value),
                trust=value.trust,
                origin=value.origin,
                source_type=value.source_type,
            )
        )
        return

    if isinstance(value, str):
        entries.append(
            _WalkEntry(
                path=path,
                value=value,
                trust=inherited_trust,
                origin=inherited_origin,
                source_type=inherited_source_type,
            )
        )
        return

    if isinstance(value, TaintedValue):
        if _already_visited(value, state):
            return
        _walk_value(
            value.value,
            path=path,
            inherited_trust=value.trust,
            inherited_origin=value.origin,
            inherited_source_type=value.source_type,
            depth=depth + 1,
            state=state,
            entries=entries,
        )
        return

    if isinstance(value, dict):
        if _already_visited(value, state):
            return
        for key, item in value.items():
            _walk_value(
                item,
                path=_child_path(path, key),
                inherited_trust=inherited_trust,
                inherited_origin=inherited_origin,
                inherited_source_type=inherited_source_type,
                depth=depth + 1,
                state=state,
                entries=entries,
            )
            if state.limit_reached:
                return
        return

    if isinstance(value, (list, tuple)):
        if _already_visited(value, state):
            return
        for index, item in enumerate(value):
            _walk_value(
                item,
                path=f"{path}[{index}]",
                inherited_trust=inherited_trust,
                inherited_origin=inherited_origin,
                inherited_source_type=inherited_source_type,
                depth=depth + 1,
                state=state,
                entries=entries,
            )
            if state.limit_reached:
                return
        return

    if isinstance(value, (set, frozenset)):
        if _already_visited(value, state):
            return
        ordered_items = _ordered_set_items(value)
        if ordered_items is None:
            return
        for index, item in enumerate(ordered_items):
            _walk_value(
                item,
                path=f"{path}[{index}]",
                inherited_trust=inherited_trust,
                inherited_origin=inherited_origin,
                inherited_source_type=inherited_source_type,
                depth=depth + 1,
                state=state,
                entries=entries,
            )
            if state.limit_reached:
                return
        return


def _coerce_entries(entries: Sequence[_WalkEntry] | Mapping[str, Any]) -> list[_WalkEntry]:
    if isinstance(entries, Mapping):
        coerced, _limit_reached = _scan_entries(entries)
        return coerced
    return list(entries)


def _first_untrusted_entry(entries: Sequence[_WalkEntry]) -> _WalkEntry | None:
    for entry in entries:
        if entry.trust == Trust.UNTRUSTED:
            return entry
    return None


def _has_delete_without_where(value: str) -> bool:
    for statement in value.split(";"):
        normalized = " ".join(statement.strip().split())
        if not normalized:
            continue
        if not re.match(r"(?i)^DELETE\s+FROM\s+[A-Za-z0-9_.\"\[\]`]+(?:\s|$)", normalized):
            continue
        if re.search(r"(?i)\bWHERE\b", normalized):
            continue
        return True
    return False


def _is_windows_remove_item_destructive(value: str) -> bool:
    normalized = " ".join(value.lower().split())
    if "remove-item" not in normalized or "-recurse" not in normalized or "-force" not in normalized:
        return False
    return any(target in normalized for target in (r"c:\*", r"~\*", r"$home\*"))


def _is_sensitive_path(value: str) -> bool:
    normalized = value.replace("\\", "/").lower()
    sensitive_fragments = (
        "/.ssh/",
        "/.aws/",
        "/.gnupg/",
        "/appdata/roaming/gnupg/",
        "/appdata/local/aws/",
        "/.config/gcloud/",
    )
    sensitive_files = (
        "/.env",
        "/id_rsa",
        "/id_ed25519",
        "/application_default_credentials.json",
    )
    return any(fragment in normalized for fragment in sensitive_fragments) or any(
        normalized.endswith(fragment) for fragment in sensitive_files
    )


def _is_sensitive_rule(rule_id: str) -> bool:
    return rule_id.startswith(("secret.", "pii."))


def _is_destination_path(path: str) -> bool:
    return path.lower() in _ROOT_SENSITIVE_PATHS


def _already_visited(value: Any, state: _WalkState) -> bool:
    marker = id(value)
    if marker in state.visited_ids:
        return True
    state.visited_ids.add(marker)
    return False


def _child_path(path: str, key: Any) -> str:
    if isinstance(key, str) and _SAFE_PATH_KEY.fullmatch(key):
        return f"{path}.{key}"
    return f"{path}[<key>]"


def _ordered_set_items(value: set[Any] | frozenset[Any]) -> list[Any] | None:
    keyed_items: list[tuple[tuple[Any, ...], Any]] = []
    for item in value:
        key = _stable_set_key(item)
        if key is None:
            return None
        keyed_items.append((key, item))
    keyed_items.sort(key=lambda pair: pair[0])
    return [item for _key, item in keyed_items]


def _stable_set_key(value: Any) -> tuple[Any, ...] | None:
    if value is None:
        return ("none",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, TaintedString):
        return ("tainted-string", value.trust.value, value.origin, value.source_type, str(value))
    if isinstance(value, TaintedValue):
        inner_key = _stable_set_key(value.value)
        if inner_key is None:
            return None
        return ("tainted-value", value.trust.value, value.origin, value.source_type, inner_key)
    if isinstance(value, tuple):
        parts: list[tuple[Any, ...]] = []
        for item in value:
            item_key = _stable_set_key(item)
            if item_key is None:
                return None
            parts.append(item_key)
        return ("tuple", tuple(parts))
    if isinstance(value, frozenset):
        parts = _ordered_set_items(value)
        if parts is None:
            return None
        keys = tuple(_stable_set_key(item) for item in parts)
        if any(key is None for key in keys):
            return None
        return ("frozenset", keys)
    return None


def _describe_origin(origin: str | None, source_type: str | None) -> str:
    safe_origin = _sanitize_origin(origin)
    if source_type and source_type != "unknown":
        return f"{source_type} origin {safe_origin!r}"
    return f"untrusted origin {safe_origin!r}"


def _sanitize_origin(origin: str | None) -> str:
    if not origin:
        return "unknown"

    origin_text = str(origin)
    label, candidate = _split_origin_label(origin_text)
    sanitized = _sanitize_url(candidate)
    if label is None:
        return sanitized
    return f"{label}:{sanitized}"


def _split_origin_label(origin: str) -> tuple[str | None, str]:
    label, separator, remainder = origin.partition(":")
    if separator and remainder.startswith(("http://", "https://")):
        return label, remainder
    return None, origin


def _sanitize_url(origin: str) -> str:
    parts = urlsplit(origin)
    if not parts.scheme or not parts.netloc:
        return origin

    netloc = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _redact_sensitive_value(value: str, *, keep_start: int = 4, keep_end: int = 2) -> str:
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return f"{value[:keep_start]}***{value[-keep_end:]}"
