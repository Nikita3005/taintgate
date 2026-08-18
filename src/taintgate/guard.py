from __future__ import annotations

import functools
import inspect
import re
import uuid
import warnings
from collections import abc
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ParamSpec, TypeVar, cast

from .audit import AuditSink, JsonlAuditSink
from .detectors import _sanitize_origin, collect_findings
from .exceptions import (
    ApprovalError,
    ApprovalRequired,
    AuditSinkError,
    BlockedAction,
    InvalidApprovalResult,
)
from .models import (
    Action,
    ApprovalAction,
    ApprovalRequest,
    ApprovalResult,
    ArgumentSummary,
    AuditEvent,
    CallContext,
    Decision,
    ExecutionState,
    ProvenanceSummary,
    TaintedString,
    TaintedValue,
    ToolMetadata,
    Trust,
)
from .policy import Policy

P = ParamSpec("P")
R = TypeVar("R")
ApprovalHandler = Callable[[ApprovalRequest], object]

_SUMMARY_MAX_DEPTH = 8
_SUMMARY_MAX_NODES = 256
_SAFE_PATH_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


@dataclass(frozen=True)
class _ActionContext:
    event_id: str
    tool: str
    decision: Decision
    metadata: ToolMetadata
    argument_summary: tuple[ArgumentSummary, ...]
    provenance: tuple[ProvenanceSummary, ...]
    context: CallContext | None

    @property
    def approval_request(self) -> ApprovalRequest:
        return ApprovalRequest(
            event_id=self.event_id,
            tool=self.tool,
            decision=self.decision,
            argument_summary=self.argument_summary,
            provenance=self.provenance,
            metadata=self.metadata,
            context=self.context,
        )


@dataclass
class _SummaryState:
    visited_ids: set[int]
    nodes_seen: int = 0


class Guard:
    def __init__(
        self,
        *,
        policy: Policy | None = None,
        approval_handler: ApprovalHandler | None = None,
        audit_sink: AuditSink | None = None,
        audit_log: str | None = None,
    ) -> None:
        if audit_sink is not None and audit_log is not None:
            raise ValueError("Pass either audit_sink or audit_log, not both")
        if audit_sink is not None and not hasattr(audit_sink, "write"):
            raise TypeError("audit_sink must provide a write(event) method")

        self.policy = policy or Policy()
        self.approval_handler = approval_handler
        self.audit_sink = audit_sink or (JsonlAuditSink(audit_log) if audit_log else None)

    def check(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        context: CallContext | None = None,
        metadata: ToolMetadata | None = None,
    ) -> Decision:
        decision, _effective_metadata = self._evaluate(tool, args, context=context, metadata=metadata)
        return decision

    def authorize(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        context: CallContext | None = None,
        metadata: ToolMetadata | None = None,
    ) -> Decision:
        action_context = self._authorize_sync(tool, args, context=context, metadata=metadata)
        return action_context.decision

    async def authorize_async(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        context: CallContext | None = None,
        metadata: ToolMetadata | None = None,
    ) -> Decision:
        action_context = await self._authorize_async(tool, args, context=context, metadata=metadata)
        return action_context.decision

    def protect(
        self,
        *,
        name: str | None = None,
        metadata: ToolMetadata | None = None,
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            signature = inspect.signature(func)
            tool_name = name or func.__name__

            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
                    bound = signature.bind(*args, **kwargs)
                    bound.apply_defaults()
                    raw = dict(bound.arguments)
                    action_context = await self._authorize_async(
                        tool_name,
                        raw,
                        metadata=metadata,
                    )
                    for key, value in list(bound.arguments.items()):
                        bound.arguments[key] = _unwrap(value)
                    try:
                        result = await cast(Callable[P, Awaitable[R]], func)(*bound.args, **bound.kwargs)
                    except Exception as exc:
                        self._write_audit_best_effort(
                            action_context,
                            ExecutionState.EXECUTION_FAILED,
                            error_type=type(exc).__name__,
                        )
                        raise
                    self._write_audit_best_effort(action_context, ExecutionState.EXECUTED)
                    return result

                return cast(Callable[P, R], async_wrapped)

            @functools.wraps(func)
            def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                raw = dict(bound.arguments)
                action_context = self._authorize_sync(tool_name, raw, metadata=metadata)
                for key, value in list(bound.arguments.items()):
                    bound.arguments[key] = _unwrap(value)
                try:
                    result = func(*bound.args, **bound.kwargs)
                except Exception as exc:
                    self._write_audit_best_effort(
                        action_context,
                        ExecutionState.EXECUTION_FAILED,
                        error_type=type(exc).__name__,
                    )
                    raise
                self._write_audit_best_effort(action_context, ExecutionState.EXECUTED)
                return result

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

    def _evaluate(
        self,
        tool: str,
        args: Mapping[str, Any],
        *,
        context: CallContext | None = None,
        metadata: ToolMetadata | None = None,
    ) -> tuple[Decision, ToolMetadata]:
        del context  # reserved for intent-aware policies in a later milestone
        effective_metadata = self.policy.resolve_metadata(tool, metadata)
        findings = collect_findings(tool, args, effective_metadata)
        decision = self.policy.evaluate(tool, args=args, findings=tuple(findings), metadata=effective_metadata)
        return decision, effective_metadata

    def _authorize_sync(
        self,
        tool: str,
        args: Mapping[str, Any],
        *,
        context: CallContext | None = None,
        metadata: ToolMetadata | None = None,
    ) -> _ActionContext:
        action_context = self._build_action_context(tool, args, context=context, metadata=metadata)
        decision = action_context.decision

        if decision.action == Action.BLOCK:
            self._write_audit_best_effort(action_context, ExecutionState.BLOCKED)
            raise BlockedAction(decision)
        if decision.action == Action.REVIEW:
            return self._review_sync(action_context)

        self._write_audit_required(action_context, ExecutionState.ALLOWED)
        return action_context

    async def _authorize_async(
        self,
        tool: str,
        args: Mapping[str, Any],
        *,
        context: CallContext | None = None,
        metadata: ToolMetadata | None = None,
    ) -> _ActionContext:
        action_context = self._build_action_context(tool, args, context=context, metadata=metadata)
        decision = action_context.decision

        if decision.action == Action.BLOCK:
            self._write_audit_best_effort(action_context, ExecutionState.BLOCKED)
            raise BlockedAction(decision)
        if decision.action == Action.REVIEW:
            return await self._review_async(action_context)

        self._write_audit_required(action_context, ExecutionState.ALLOWED)
        return action_context

    def _review_sync(self, action_context: _ActionContext) -> _ActionContext:
        decision = action_context.decision
        handler = self.approval_handler
        if handler is None:
            self._write_audit_best_effort(action_context, ExecutionState.APPROVAL_FAILED)
            raise ApprovalRequired(decision)
        if _is_async_callable(handler):
            self._write_audit_best_effort(
                action_context,
                ExecutionState.APPROVAL_FAILED,
                error_type="async_handler_unsupported",
            )
            raise ApprovalError(
                "Synchronous protected tools require a synchronous approval handler",
                decision=decision,
            )

        self._write_audit_required(action_context, ExecutionState.APPROVAL_REQUESTED)
        try:
            raw_result = handler(action_context.approval_request)
        except Exception as exc:
            self._write_audit_best_effort(
                action_context,
                ExecutionState.APPROVAL_FAILED,
                error_type=type(exc).__name__,
            )
            raise ApprovalError("Approval handler failed", decision=decision) from exc

        if inspect.isawaitable(raw_result):
            _close_if_coroutine(raw_result)
            self._write_audit_best_effort(
                action_context,
                ExecutionState.APPROVAL_FAILED,
                error_type=type(raw_result).__name__,
            )
            raise ApprovalError("Synchronous approval handler returned an awaitable", decision=decision)

        approval = self._coerce_approval_result(raw_result, decision=decision, action_context=action_context)
        if approval.action == ApprovalAction.REJECT:
            self._write_audit_best_effort(
                action_context,
                ExecutionState.APPROVAL_REJECTED,
                approval_action=approval.action,
            )
            raise BlockedAction(decision)

        self._write_audit_required(
            action_context,
            ExecutionState.APPROVAL_GRANTED,
            approval_action=approval.action,
        )
        return action_context

    async def _review_async(self, action_context: _ActionContext) -> _ActionContext:
        decision = action_context.decision
        handler = self.approval_handler
        if handler is None:
            self._write_audit_best_effort(action_context, ExecutionState.APPROVAL_FAILED)
            raise ApprovalRequired(decision)

        self._write_audit_required(action_context, ExecutionState.APPROVAL_REQUESTED)
        try:
            if _is_async_callable(handler):
                raw_result = await cast(Callable[[ApprovalRequest], Awaitable[object]], handler)(
                    action_context.approval_request
                )
            else:
                raw_result = handler(action_context.approval_request)
                if inspect.isawaitable(raw_result):
                    _close_if_coroutine(raw_result)
                    self._write_audit_best_effort(
                        action_context,
                        ExecutionState.APPROVAL_FAILED,
                        error_type=type(raw_result).__name__,
                    )
                    raise ApprovalError(
                        "Synchronous approval handler returned an awaitable",
                        decision=decision,
                    )
        except ApprovalError:
            raise
        except Exception as exc:
            self._write_audit_best_effort(
                action_context,
                ExecutionState.APPROVAL_FAILED,
                error_type=type(exc).__name__,
            )
            raise ApprovalError("Approval handler failed", decision=decision) from exc

        approval = self._coerce_approval_result(raw_result, decision=decision, action_context=action_context)
        if approval.action == ApprovalAction.REJECT:
            self._write_audit_best_effort(
                action_context,
                ExecutionState.APPROVAL_REJECTED,
                approval_action=approval.action,
            )
            raise BlockedAction(decision)

        self._write_audit_required(
            action_context,
            ExecutionState.APPROVAL_GRANTED,
            approval_action=approval.action,
        )
        return action_context

    def _coerce_approval_result(
        self,
        result: object,
        *,
        decision: Decision,
        action_context: _ActionContext,
    ) -> ApprovalResult:
        try:
            return _normalize_approval_result(result, decision=decision)
        except InvalidApprovalResult as exc:
            self._write_audit_best_effort(
                action_context,
                ExecutionState.APPROVAL_FAILED,
                error_type=type(result).__name__,
            )
            raise exc from None

    def _build_action_context(
        self,
        tool: str,
        args: Mapping[str, Any],
        *,
        context: CallContext | None = None,
        metadata: ToolMetadata | None = None,
    ) -> _ActionContext:
        decision, effective_metadata = self._evaluate(tool, args, context=context, metadata=metadata)
        argument_summary, provenance = _summarize_arguments(args)
        return _ActionContext(
            event_id=str(uuid.uuid4()),
            tool=tool,
            decision=decision,
            metadata=effective_metadata,
            argument_summary=argument_summary,
            provenance=provenance,
            context=context,
        )

    def _build_audit_event(
        self,
        action_context: _ActionContext,
        execution_state: ExecutionState,
        *,
        approval_action: ApprovalAction | None = None,
        error_type: str | None = None,
    ) -> AuditEvent:
        return AuditEvent(
            timestamp=_utc_now_iso(),
            event_id=action_context.event_id,
            tool=action_context.tool,
            policy_action=action_context.decision.action,
            risk_score=action_context.decision.risk_score,
            execution_state=execution_state,
            matched_policies=action_context.decision.matched_policies,
            finding_ids=tuple(finding.rule_id for finding in action_context.decision.findings),
            provenance=action_context.provenance,
            argument_summary=action_context.argument_summary,
            tool_metadata=action_context.metadata,
            approval_action=approval_action,
            error_type=error_type,
        )

    def _write_audit_required(
        self,
        action_context: _ActionContext,
        execution_state: ExecutionState,
        *,
        approval_action: ApprovalAction | None = None,
        error_type: str | None = None,
    ) -> None:
        if self.audit_sink is None:
            return
        event = self._build_audit_event(
            action_context,
            execution_state,
            approval_action=approval_action,
            error_type=error_type,
        )
        try:
            write_result = self.audit_sink.write(event)
            if inspect.isawaitable(write_result):
                _close_if_coroutine(write_result)
                raise TypeError("Audit sinks must provide a synchronous write(event) implementation")
        except Exception as exc:
            raise AuditSinkError(event, exc) from exc

    def _write_audit_best_effort(
        self,
        action_context: _ActionContext,
        execution_state: ExecutionState,
        *,
        approval_action: ApprovalAction | None = None,
        error_type: str | None = None,
    ) -> None:
        if self.audit_sink is None:
            return
        event = self._build_audit_event(
            action_context,
            execution_state,
            approval_action=approval_action,
            error_type=error_type,
        )
        try:
            write_result = self.audit_sink.write(event)
            if inspect.isawaitable(write_result):
                _close_if_coroutine(write_result)
                raise TypeError("Audit sinks must provide a synchronous write(event) implementation")
        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"Audit sink failed while recording {event.execution_state.value} "
                f"for {event.tool!r} ({type(exc).__name__})",
                RuntimeWarning,
                stacklevel=3,
            )


def _unwrap(value: Any, memo: dict[int, Any] | None = None) -> Any:
    if memo is None:
        memo = {}
    if isinstance(value, TaintedString):
        return _plain_str(value)
    if isinstance(value, TaintedValue):
        return _unwrap(value.value, memo)
    if isinstance(value, dict):
        marker = id(value)
        if marker in memo:
            return memo[marker]
        unwrapped: dict[Any, Any] = {}
        memo[marker] = unwrapped
        for key, item in value.items():
            unwrapped[key] = _unwrap(item, memo)
        return unwrapped
    if isinstance(value, list):
        marker = id(value)
        if marker in memo:
            return memo[marker]
        unwrapped: list[Any] = []
        memo[marker] = unwrapped
        unwrapped.extend(_unwrap(item, memo) for item in value)
        return unwrapped
    if isinstance(value, tuple):
        marker = id(value)
        if marker in memo:
            return memo[marker]
        placeholder: list[Any] = []
        memo[marker] = placeholder
        unwrapped_tuple = tuple(_unwrap(item, memo) for item in value)
        memo[marker] = unwrapped_tuple
        return unwrapped_tuple
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


def _normalize_approval_result(result: object, *, decision: Decision) -> ApprovalResult:
    if isinstance(result, ApprovalResult):
        return result
    if isinstance(result, ApprovalAction):
        return ApprovalResult(action=result)
    if result is True:
        warnings.warn(
            "Boolean approval results are deprecated; return ApprovalAction or ApprovalResult instead",
            DeprecationWarning,
            stacklevel=3,
        )
        return ApprovalResult(action=ApprovalAction.APPROVE)
    if result is False:
        warnings.warn(
            "Boolean approval results are deprecated; return ApprovalAction or ApprovalResult instead",
            DeprecationWarning,
            stacklevel=3,
        )
        return ApprovalResult(action=ApprovalAction.REJECT)
    raise InvalidApprovalResult(result, decision=decision)


def _is_async_callable(handler: object) -> bool:
    if inspect.iscoroutinefunction(handler):
        return True
    if not callable(handler):
        return False
    return inspect.iscoroutinefunction(type(handler).__call__)


def _close_if_coroutine(value: object) -> None:
    if inspect.iscoroutine(value):
        value.close()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summarize_arguments(
    args: Mapping[str, Any],
) -> tuple[tuple[ArgumentSummary, ...], tuple[ProvenanceSummary, ...]]:
    state = _SummaryState(visited_ids=set())
    summaries: list[ArgumentSummary] = []
    provenance: list[ProvenanceSummary] = []
    provenance_paths: set[str] = set()
    _summarize_value(
        args,
        path="$",
        inherited_trust=None,
        inherited_origin=None,
        inherited_source_type=None,
        depth=0,
        state=state,
        summaries=summaries,
        provenance=provenance,
        provenance_paths=provenance_paths,
    )
    return tuple(summaries), tuple(provenance)


def _summarize_value(
    value: Any,
    *,
    path: str,
    inherited_trust: Trust | None,
    inherited_origin: str | None,
    inherited_source_type: str | None,
    depth: int,
    state: _SummaryState,
    summaries: list[ArgumentSummary],
    provenance: list[ProvenanceSummary],
    provenance_paths: set[str],
) -> None:
    if state.nodes_seen >= _SUMMARY_MAX_NODES or depth > _SUMMARY_MAX_DEPTH:
        summaries.append(
            ArgumentSummary(
                path=path,
                python_type=type(value).__name__,
                trust=inherited_trust,
                source_type=inherited_source_type,
                origin=_safe_origin(inherited_origin),
                truncated=True,
            )
        )
        _append_provenance(
            provenance,
            provenance_paths,
            path=path,
            trust=inherited_trust,
            source_type=inherited_source_type,
            origin=inherited_origin,
        )
        return

    state.nodes_seen += 1

    if isinstance(value, TaintedString):
        summary = ArgumentSummary(
            path=path,
            python_type="str",
            string_length=len(value),
            trust=value.trust,
            source_type=value.source_type,
            origin=_safe_origin(value.origin),
        )
        summaries.append(summary)
        _append_provenance(
            provenance,
            provenance_paths,
            path=path,
            trust=value.trust,
            source_type=value.source_type,
            origin=value.origin,
        )
        return

    if isinstance(value, str):
        summaries.append(
            ArgumentSummary(
                path=path,
                python_type="str",
                string_length=len(value),
                trust=inherited_trust,
                source_type=inherited_source_type,
                origin=_safe_origin(inherited_origin),
            )
        )
        _append_provenance(
            provenance,
            provenance_paths,
            path=path,
            trust=inherited_trust,
            source_type=inherited_source_type,
            origin=inherited_origin,
        )
        return

    if isinstance(value, TaintedValue):
        marker = id(value)
        if marker in state.visited_ids:
            summaries.append(
                ArgumentSummary(
                    path=path,
                    python_type=type(value.value).__name__,
                    trust=value.trust,
                    source_type=value.source_type,
                    origin=_safe_origin(value.origin),
                    truncated=True,
                )
            )
            _append_provenance(
                provenance,
                provenance_paths,
                path=path,
                trust=value.trust,
                source_type=value.source_type,
                origin=value.origin,
            )
            return
        state.visited_ids.add(marker)
        _summarize_value(
            value.value,
            path=path,
            inherited_trust=value.trust,
            inherited_origin=value.origin,
            inherited_source_type=value.source_type,
            depth=depth + 1,
            state=state,
            summaries=summaries,
            provenance=provenance,
            provenance_paths=provenance_paths,
        )
        return

    if isinstance(value, dict):
        marker = id(value)
        if marker in state.visited_ids:
            summaries.append(
                ArgumentSummary(
                    path=path,
                    python_type="dict",
                    collection_size=len(value),
                    trust=inherited_trust,
                    source_type=inherited_source_type,
                    origin=_safe_origin(inherited_origin),
                    truncated=True,
                )
            )
            _append_provenance(
                provenance,
                provenance_paths,
                path=path,
                trust=inherited_trust,
                source_type=inherited_source_type,
                origin=inherited_origin,
            )
            return
        state.visited_ids.add(marker)
        summaries.append(
            ArgumentSummary(
                path=path,
                python_type="dict",
                collection_size=len(value),
                trust=inherited_trust,
                source_type=inherited_source_type,
                origin=_safe_origin(inherited_origin),
            )
        )
        _append_provenance(
            provenance,
            provenance_paths,
            path=path,
            trust=inherited_trust,
            source_type=inherited_source_type,
            origin=inherited_origin,
        )
        for key, item in value.items():
            _summarize_value(
                item,
                path=_summary_child_path(path, key),
                inherited_trust=inherited_trust,
                inherited_origin=inherited_origin,
                inherited_source_type=inherited_source_type,
                depth=depth + 1,
                state=state,
                summaries=summaries,
                provenance=provenance,
                provenance_paths=provenance_paths,
            )
        return

    if isinstance(value, (list, tuple)):
        marker = id(value)
        type_name = type(value).__name__
        if marker in state.visited_ids:
            summaries.append(
                ArgumentSummary(
                    path=path,
                    python_type=type_name,
                    collection_size=len(value),
                    trust=inherited_trust,
                    source_type=inherited_source_type,
                    origin=_safe_origin(inherited_origin),
                    truncated=True,
                )
            )
            _append_provenance(
                provenance,
                provenance_paths,
                path=path,
                trust=inherited_trust,
                source_type=inherited_source_type,
                origin=inherited_origin,
            )
            return
        state.visited_ids.add(marker)
        summaries.append(
            ArgumentSummary(
                path=path,
                python_type=type_name,
                collection_size=len(value),
                trust=inherited_trust,
                source_type=inherited_source_type,
                origin=_safe_origin(inherited_origin),
            )
        )
        _append_provenance(
            provenance,
            provenance_paths,
            path=path,
            trust=inherited_trust,
            source_type=inherited_source_type,
            origin=inherited_origin,
        )
        for index, item in enumerate(value):
            _summarize_value(
                item,
                path=f"{path}[{index}]",
                inherited_trust=inherited_trust,
                inherited_origin=inherited_origin,
                inherited_source_type=inherited_source_type,
                depth=depth + 1,
                state=state,
                summaries=summaries,
                provenance=provenance,
                provenance_paths=provenance_paths,
            )
        return

    if isinstance(value, (set, frozenset)):
        marker = id(value)
        type_name = type(value).__name__
        if marker in state.visited_ids:
            summaries.append(
                ArgumentSummary(
                    path=path,
                    python_type=type_name,
                    collection_size=len(value),
                    trust=inherited_trust,
                    source_type=inherited_source_type,
                    origin=_safe_origin(inherited_origin),
                    truncated=True,
                )
            )
            _append_provenance(
                provenance,
                provenance_paths,
                path=path,
                trust=inherited_trust,
                source_type=inherited_source_type,
                origin=inherited_origin,
            )
            return
        state.visited_ids.add(marker)
        ordered_items = _ordered_summary_items(value)
        summaries.append(
            ArgumentSummary(
                path=path,
                python_type=type_name,
                collection_size=len(value),
                trust=inherited_trust,
                source_type=inherited_source_type,
                origin=_safe_origin(inherited_origin),
                truncated=ordered_items is None,
            )
        )
        _append_provenance(
            provenance,
            provenance_paths,
            path=path,
            trust=inherited_trust,
            source_type=inherited_source_type,
            origin=inherited_origin,
        )
        if ordered_items is None:
            return
        for index, item in enumerate(ordered_items):
            _summarize_value(
                item,
                path=f"{path}[{index}]",
                inherited_trust=inherited_trust,
                inherited_origin=inherited_origin,
                inherited_source_type=inherited_source_type,
                depth=depth + 1,
                state=state,
                summaries=summaries,
                provenance=provenance,
                provenance_paths=provenance_paths,
            )
        return

    summaries.append(
        ArgumentSummary(
            path=path,
            python_type=type(value).__name__,
            trust=inherited_trust,
            source_type=inherited_source_type,
            origin=_safe_origin(inherited_origin),
        )
    )
    _append_provenance(
        provenance,
        provenance_paths,
        path=path,
        trust=inherited_trust,
        source_type=inherited_source_type,
        origin=inherited_origin,
    )


def _append_provenance(
    provenance: list[ProvenanceSummary],
    provenance_paths: set[str],
    *,
    path: str,
    trust: Trust | None,
    source_type: str | None,
    origin: str | None,
) -> None:
    if trust is None or path in provenance_paths:
        return
    provenance_paths.add(path)
    provenance.append(
        ProvenanceSummary(
            path=path,
            trust=trust,
            source_type=source_type,
            origin=_safe_origin(origin),
        )
    )


def _safe_origin(origin: str | None) -> str | None:
    if origin is None:
        return None
    return _sanitize_origin(origin)


def _summary_child_path(path: str, key: Any) -> str:
    if isinstance(key, str) and _SAFE_PATH_KEY.fullmatch(key):
        return f"{path}.{key}"
    return f"{path}[<key>]"


def _ordered_summary_items(value: set[Any] | frozenset[Any]) -> list[Any] | None:
    keyed_items: list[tuple[tuple[Any, ...], Any]] = []
    for item in value:
        key = _summary_set_key(item)
        if key is None:
            return None
        keyed_items.append((key, item))
    keyed_items.sort(key=lambda pair: pair[0])
    return [item for _key, item in keyed_items]


def _summary_set_key(value: Any) -> tuple[Any, ...] | None:
    if value is None:
        return ("none",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    if isinstance(value, TaintedString):
        return ("tainted-string", value.trust.value, value.source_type, _safe_origin(value.origin), len(value))
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, TaintedValue):
        inner_key = _summary_set_key(value.value)
        if inner_key is None:
            return None
        return (
            "tainted-value",
            value.trust.value,
            value.source_type,
            _safe_origin(value.origin),
            inner_key,
        )
    if isinstance(value, tuple):
        parts: list[tuple[Any, ...]] = []
        for item in value:
            item_key = _summary_set_key(item)
            if item_key is None:
                return None
            parts.append(item_key)
        return ("tuple", tuple(parts))
    if isinstance(value, frozenset):
        parts = _ordered_summary_items(value)
        if parts is None:
            return None
        keys = tuple(_summary_set_key(item) for item in parts)
        if any(key is None for key in keys):
            return None
        return ("frozenset", keys)
    return None
