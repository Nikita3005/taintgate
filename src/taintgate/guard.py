from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar

from .audit import JsonlAuditLog
from .detectors import (
    detect_destructive,
    detect_prompt_injection,
    detect_secrets,
    detect_sensitive_paths,
    detect_untrusted_flow,
)
from .exceptions import ApprovalRequired, BlockedAction
from .models import Action, CallContext, Decision, Finding, TaintedValue
from .policy import Policy

P = ParamSpec("P")
R = TypeVar("R")
ApprovalHandler = Callable[[Decision], bool]


class Guard:
    def __init__(
        self,
        *,
        policy: Policy | None = None,
        approval_handler: ApprovalHandler | None = None,
        audit_log: str | None = None,
    ) -> None:
        self.policy = policy or Policy()
        self.approval_handler = approval_handler
        self.audit = JsonlAuditLog(audit_log) if audit_log else None

    def check(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        context: CallContext | None = None,
    ) -> Decision:
        del context  # reserved for intent-aware policies in the next milestone
        findings: list[Finding] = []

        if tool in self.policy.denied_tools:
            findings.append(Finding("policy.denied_tool", f"Tool {tool!r} is denied by policy", 100))
        if tool in self.policy.review_tools:
            findings.append(Finding("policy.review_tool", f"Tool {tool!r} requires review", 65))

        findings.extend(detect_secrets(args))
        findings.extend(detect_prompt_injection(args))
        findings.extend(detect_destructive(args))
        findings.extend(detect_sensitive_paths(args))
        findings.extend(detect_untrusted_flow(tool, args))

        score = self._combine(findings)
        if score >= self.policy.block_at:
            action = Action.BLOCK
        elif score >= self.policy.review_at:
            action = Action.REVIEW
        else:
            action = Action.ALLOW

        decision = Decision(action=action, score=score, tool=tool, findings=tuple(findings))
        if self.audit:
            self.audit.write(decision)
        return decision

    def authorize(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        context: CallContext | None = None,
    ) -> Decision:
        decision = self.check(tool, args, context=context)
        if decision.action == Action.BLOCK:
            raise BlockedAction(decision)
        if decision.action == Action.REVIEW:
            if self.approval_handler is None:
                raise ApprovalRequired(decision)
            if not self.approval_handler(decision):
                raise BlockedAction(decision)
        return decision

    def protect(self, *, name: str | None = None) -> Callable[[Callable[P, R]], Callable[P, R]]:
        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            signature = inspect.signature(func)
            tool_name = name or func.__name__

            @functools.wraps(func)
            def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                raw = dict(bound.arguments)
                self.authorize(tool_name, raw)
                for key, value in list(bound.arguments.items()):
                    bound.arguments[key] = _unwrap(value)
                return func(*bound.args, **bound.kwargs)

            return wrapped

        return decorator

    @staticmethod
    def _combine(findings: list[Finding]) -> int:
        if not findings:
            return 0
        # Multiple independent warning signals should compound without simply summing to 100.
        remaining = 1.0
        for finding in findings:
            remaining *= 1.0 - (finding.score / 100.0)
        return min(100, round((1.0 - remaining) * 100))


def _unwrap(value: Any) -> Any:
    if isinstance(value, TaintedValue):
        return _unwrap(value.value)
    if isinstance(value, dict):
        return {key: _unwrap(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_unwrap(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_unwrap(item) for item in value)
    return value
