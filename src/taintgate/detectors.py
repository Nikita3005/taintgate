from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import Finding, TaintedString, TaintedValue, Trust

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("secret.openai", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("secret.aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret.github", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("secret.private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"reveal\s+(?:the\s+)?(?:system|developer)\s+prompt", re.IGNORECASE),
    re.compile(r"send\s+.*(?:secret|credential|api[_ -]?key)", re.IGNORECASE),
)

_DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|\s)rm\s+-rf\s+(?:/|~|\*)", re.IGNORECASE),
    re.compile(r"\b(?:drop|truncate)\s+(?:table|database)\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b|\breboot\b", re.IGNORECASE),
)

_SENSITIVE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|/)(?:\.ssh|\.aws|\.gnupg)(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:\.env|id_rsa|id_ed25519)$", re.IGNORECASE),
)


def walk(
    value: Any,
    path: str = "$",
    inherited_trust: Trust | None = None,
    inherited_origin: str | None = None,
    inherited_source_type: str | None = None,
) -> Iterable[tuple[str, Any, Trust | None, str | None, str | None]]:
    if isinstance(value, TaintedString):
        yield path, str(value), value.trust, value.origin, value.source_type
        return
    if isinstance(value, TaintedValue):
        yield from walk(value.value, path, value.trust, value.origin, value.source_type)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, f"{path}.{key}", inherited_trust, inherited_origin, inherited_source_type)
        return
    if isinstance(value, (list, tuple, set)):
        for index, item in enumerate(value):
            yield from walk(item, f"{path}[{index}]", inherited_trust, inherited_origin, inherited_source_type)
        return
    yield path, value, inherited_trust, inherited_origin, inherited_source_type


def detect_secrets(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, value, _trust, _origin, _source_type in walk(args):
        if not isinstance(value, str):
            continue
        for rule_id, pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                findings.append(Finding(rule_id, f"Secret-like value detected at {path}", 75))
    return findings


def detect_prompt_injection(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, value, trust, origin, source_type in walk(args):
        if trust != Trust.UNTRUSTED or not isinstance(value, str):
            continue
        if any(pattern.search(value) for pattern in _INJECTION_PATTERNS):
            findings.append(
                Finding(
                    "input.prompt_injection",
                    f"Prompt-injection-like instruction from {_describe_origin(origin, source_type)} at {path}",
                    55,
                )
            )
    return findings


def detect_destructive(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, value, _trust, _origin, _source_type in walk(args):
        if isinstance(value, str) and any(pattern.search(value) for pattern in _DESTRUCTIVE_PATTERNS):
            findings.append(Finding("action.destructive", f"Destructive operation at {path}", 90))
    return findings


def detect_sensitive_paths(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, value, _trust, _origin, _source_type in walk(args):
        if isinstance(value, str) and any(pattern.search(value) for pattern in _SENSITIVE_PATH_PATTERNS):
            findings.append(Finding("data.sensitive_path", f"Sensitive path referenced at {path}", 55))
    return findings


def detect_untrusted_flow(tool: str, args: dict[str, Any]) -> list[Finding]:
    tool_l = tool.lower()
    sink_words = ("send", "email", "post", "upload", "request", "http", "write", "execute", "shell")
    if not any(word in tool_l for word in sink_words):
        return []

    findings: list[Finding] = []
    for path, _value, trust, origin, source_type in walk(args):
        if trust == Trust.UNTRUSTED:
            findings.append(
                Finding(
                    "flow.untrusted_to_side_effect",
                    f"Untrusted data from {_describe_origin(origin, source_type)} "
                    f"flows into side-effecting tool at {path}",
                    35,
                )
            )
            break
    return findings


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
