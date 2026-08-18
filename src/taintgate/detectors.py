from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .models import Finding, TaintedValue, Trust

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("secret.openai", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("secret.aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret.github", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("secret.private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.I),
    re.compile(r"reveal\s+(?:the\s+)?(?:system|developer)\s+prompt", re.I),
    re.compile(r"send\s+.*(?:secret|credential|api[_ -]?key)", re.I),
)

_DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|\s)rm\s+-rf\s+(?:/|~|\*)", re.I),
    re.compile(r"\b(?:drop|truncate)\s+(?:table|database)\b", re.I),
    re.compile(r"\bshutdown\b|\breboot\b", re.I),
)

_SENSITIVE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|/)(?:\.ssh|\.aws|\.gnupg)(?:/|$)", re.I),
    re.compile(r"(?:^|/)(?:\.env|id_rsa|id_ed25519)$", re.I),
)


def walk(
    value: Any,
    path: str = "$",
    inherited_trust: Trust | None = None,
    inherited_origin: str | None = None,
) -> Iterable[tuple[str, Any, Trust | None, str | None]]:
    if isinstance(value, TaintedValue):
        yield from walk(value.value, path, value.trust, value.origin)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, f"{path}.{key}", inherited_trust, inherited_origin)
        return
    if isinstance(value, (list, tuple, set)):
        for index, item in enumerate(value):
            yield from walk(item, f"{path}[{index}]", inherited_trust, inherited_origin)
        return
    yield path, value, inherited_trust, inherited_origin


def detect_secrets(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, value, _trust, _origin in walk(args):
        if not isinstance(value, str):
            continue
        for rule_id, pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                findings.append(Finding(rule_id, f"Secret-like value detected at {path}", 75))
    return findings


def detect_prompt_injection(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, value, trust, origin in walk(args):
        if trust != Trust.UNTRUSTED or not isinstance(value, str):
            continue
        if any(pattern.search(value) for pattern in _INJECTION_PATTERNS):
            findings.append(
                Finding(
                    "input.prompt_injection",
                    f"Prompt-injection-like instruction from untrusted origin {origin!r} at {path}",
                    55,
                )
            )
    return findings


def detect_destructive(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, value, _trust, _origin in walk(args):
        if isinstance(value, str) and any(pattern.search(value) for pattern in _DESTRUCTIVE_PATTERNS):
            findings.append(Finding("action.destructive", f"Destructive operation at {path}", 90))
    return findings


def detect_sensitive_paths(args: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, value, _trust, _origin in walk(args):
        if isinstance(value, str) and any(pattern.search(value) for pattern in _SENSITIVE_PATH_PATTERNS):
            findings.append(Finding("data.sensitive_path", f"Sensitive path referenced at {path}", 55))
    return findings


def detect_untrusted_flow(tool: str, args: dict[str, Any]) -> list[Finding]:
    tool_l = tool.lower()
    sink_words = ("send", "email", "post", "upload", "request", "http", "write", "execute", "shell")
    if not any(word in tool_l for word in sink_words):
        return []

    findings: list[Finding] = []
    for path, _value, trust, origin in walk(args):
        if trust == Trust.UNTRUSTED:
            findings.append(
                Finding(
                    "flow.untrusted_to_side_effect",
                    f"Untrusted data from {origin!r} flows into side-effecting tool at {path}",
                    35,
                )
            )
            break
    return findings
