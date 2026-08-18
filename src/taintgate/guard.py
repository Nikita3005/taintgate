from __future__ import annotations

import functools
import inspect
from collections import abc
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar, cast

from .audit import JsonlAuditLog
from .detectors import (
    detect_destructive,
    detect_prompt_injection,
    detect_secrets,
    detect_sensitive_paths,
    detect_untrusted_flow,
)
from .exceptions import ApprovalRequired, BlockedAction
from .models import (
    Action,
    CallContext,
    Decision,
    Finding,
    TaintedString,
    TaintedValue,
    ToolMetadata,
    Trust,
)
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
        metadata: ToolMetadata | None = None,
    ) -> Decision:
        del context  # reserved for intent-aware policies in the next milestone
        findings: list[Finding] = []

        findings.extend(detect_secrets(args))
        findings.extend(detect_prompt_injection(args))
        findings.extend(detect_destructive(args))
        findings.extend(detect_sensitive_paths(args))
        findings.extend(detect_untrusted_flow(tool, args))

        decision = self.policy.evaluate(tool, args=args, findings=tuple(findings), metadata=metadata)
        if self.audit:
            self.audit.write(decision)
        return decision

    def authorize(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        context: CallContext | None = None,
        metadata: ToolMetadata | None = None,
    ) -> Decision:
        decision = self.check(tool, args, context=context, metadata=metadata)
        if decision.action == Action.BLOCK:
            raise BlockedAction(decision)
        if decision.action == Action.REVIEW:
            if self.approval_handler is None:
                raise ApprovalRequired(decision)
            if not self.approval_handler(decision):
                raise BlockedAction(decision)
        return decision

    def protect(
        self,
        *,
        name: str | None = None,
        metadata: ToolMetadata | None = None,
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            signature = inspect.signature(func)
            tool_name = name or func.__name__

            @functools.wraps(func)
            def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                raw = dict(bound.arguments)
                self.authorize(tool_name, raw, metadata=metadata)
                for key, value in list(bound.arguments.items()):
                    bound.arguments[key] = _unwrap(value)
                return func(*bound.args, **bound.kwargs)

            return wrapped

        return decorator

    def untrusted_source(
        self,
        source_type: str,
        *,
        origin_arg: str | None = None,
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            signature = inspect.signature(func)
            if origin_arg is not None and origin_arg not in signature.parameters:
                raise ValueError(
                    f"origin_arg {origin_arg!r} is not a parameter of {func.__name__!r}"
                )

            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapped(*args: P.args, **kwargs: P.kwargs) -> TaintedString:
                    result = await cast(Callable[P, abc.Awaitable[Any]], func)(*args, **kwargs)
                    origin = _resolve_origin(signature, origin_arg, args, kwargs)
                    return _taint_source_result(
                        result,
                        source_type=source_type,
                        origin=origin,
                        function_name=func.__name__,
                    )

                return cast(Callable[P, R], async_wrapped)

            @functools.wraps(func)
            def wrapped(*args: P.args, **kwargs: P.kwargs) -> TaintedString:
                result = func(*args, **kwargs)
                origin = _resolve_origin(signature, origin_arg, args, kwargs)
                return _taint_source_result(
                    result,
                    source_type=source_type,
                    origin=origin,
                    function_name=func.__name__,
                )

            return cast(Callable[P, R], wrapped)

        return decorator


def _unwrap(value: Any) -> Any:
    if isinstance(value, TaintedString):
        return _plain_str(value)
    if isinstance(value, TaintedValue):
        return _unwrap(value.value)
    if isinstance(value, dict):
        return {key: _unwrap(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_unwrap(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_unwrap(item) for item in value)
    return value


def _resolve_origin(
    signature: inspect.Signature,
    origin_arg: str | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> str:
    if origin_arg is None:
        return "unknown"
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    origin = _unwrap(bound.arguments[origin_arg])
    if origin is None:
        return "unknown"
    return str(origin)


def _taint_source_result(
    result: Any,
    *,
    source_type: str,
    origin: str,
    function_name: str,
) -> TaintedString:
    if not isinstance(result, str):
        raise TypeError(
            f"@guard.untrusted_source only supports str results; "
            f"{function_name!r} returned {type(result).__name__}"
        )
    return TaintedString(
        _plain_str(result),
        trust=Trust.UNTRUSTED,
        origin=origin,
        source_type=source_type,
    )


def _plain_str(value: str) -> str:
    return f"{value}"
