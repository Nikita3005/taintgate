from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

try:
    from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import BaseTool
    from langgraph.prebuilt import ToolNode
    from langgraph.types import Command
except ImportError as exc:  # pragma: no cover - exercised in subprocess test
    raise ImportError(
        'taintgate.langchain requires LangChain and LangGraph. '
        'Install it with: pip install "taintgate[langgraph]"'
    ) from exc

from .exceptions import ApprovalError, ApprovalRequired, AuditSinkError, BlockedAction
from .guard import Guard
from .models import Action, CallContext, Decision, Finding, ToolMetadata


@dataclass(frozen=True)
class _Invocation:
    tool_name: str
    tool_call_id: str
    args: dict[str, Any]
    metadata: ToolMetadata | None


class TaintGateToolMiddleware(AgentMiddleware[Any, Any, Any]):
    """LangChain/LangGraph tool middleware backed by TaintGate's Guard."""

    def __init__(
        self,
        guard: Guard,
        *,
        metadata: Mapping[str, ToolMetadata] | None = None,
    ) -> None:
        if not isinstance(guard, Guard):
            raise TypeError("guard must be a Guard")

        normalized_metadata: dict[str, ToolMetadata] = {}
        for tool_name, tool_metadata in dict(metadata or {}).items():
            if not isinstance(tool_name, str) or not tool_name:
                raise TypeError("metadata keys must be non-empty strings")
            if not isinstance(tool_metadata, ToolMetadata):
                raise TypeError("metadata values must be ToolMetadata instances")
            normalized_metadata[tool_name] = tool_metadata

        self._guard = guard
        self._metadata = normalized_metadata

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        return self._wrap_tool_call(request, handler, propagate_security_exceptions=False)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        return await self._awrap_tool_call(
            request,
            handler,
            propagate_security_exceptions=False,
        )

    def tool_node(
        self,
        tools: Sequence[BaseTool | Callable[..., Any]],
        *,
        name: str = "tools",
        tags: list[str] | None = None,
        messages_key: str = "messages",
    ) -> ToolNode:
        return ToolNode(
            tools=tools,
            name=name,
            tags=tags,
            handle_tool_errors=False,
            messages_key=messages_key,
            wrap_tool_call=self._wrap_tool_call_propagating,
            awrap_tool_call=self._awrap_tool_call_propagating,
        )

    def _wrap_tool_call_propagating(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        return self._wrap_tool_call(request, handler, propagate_security_exceptions=True)

    async def _awrap_tool_call_propagating(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        return await self._awrap_tool_call(
            request,
            handler,
            propagate_security_exceptions=True,
        )

    def _wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
        *,
        propagate_security_exceptions: bool,
    ) -> ToolMessage | Command[Any]:
        tool_call_id = _tool_call_id(request.tool_call)
        try:
            invocation = _resolve_invocation(request, metadata=self._metadata)
            context = CallContext(session_id=invocation.tool_call_id)
            self._guard.authorize(
                invocation.tool_name,
                invocation.args,
                context=context,
                metadata=invocation.metadata,
            )
        except (ApprovalRequired, ApprovalError, BlockedAction) as exc:
            if propagate_security_exceptions:
                raise
            return _tool_denied_message(
                exc.decision,
                tool_call_id=tool_call_id,
                review_required=exc.decision.action == Action.REVIEW,
            )
        except AuditSinkError as exc:
            if propagate_security_exceptions:
                raise
            return _audit_failure_message(exc, tool_call_id=tool_call_id)

        return handler(request)

    async def _awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
        *,
        propagate_security_exceptions: bool,
    ) -> ToolMessage | Command[Any]:
        tool_call_id = _tool_call_id(request.tool_call)
        try:
            invocation = _resolve_invocation(request, metadata=self._metadata)
            context = CallContext(session_id=invocation.tool_call_id)
            await self._guard.authorize_async(
                invocation.tool_name,
                invocation.args,
                context=context,
                metadata=invocation.metadata,
            )
        except (ApprovalRequired, ApprovalError, BlockedAction) as exc:
            if propagate_security_exceptions:
                raise
            return _tool_denied_message(
                exc.decision,
                tool_call_id=tool_call_id,
                review_required=exc.decision.action == Action.REVIEW,
            )
        except AuditSinkError as exc:
            if propagate_security_exceptions:
                raise
            return _audit_failure_message(exc, tool_call_id=tool_call_id)

        return await handler(request)


def _resolve_invocation(
    request: ToolCallRequest,
    *,
    metadata: Mapping[str, ToolMetadata],
) -> _Invocation:
    tool_call = request.tool_call
    tool_call_id = _tool_call_id(tool_call)
    registered_name = _registered_tool_name(request)
    model_name = _model_tool_name(tool_call)

    if registered_name is None:
        raise BlockedAction(
            _validation_decision(
                "unknown_tool",
                rule_id="runtime.unregistered_tool",
                message="Tool call did not resolve to a registered tool",
            )
        )

    if model_name != registered_name:
        raise BlockedAction(
            _validation_decision(
                registered_name,
                rule_id="runtime.tool_name_mismatch",
                message="Tool call name did not match the registered tool",
            )
        )

    args = _tool_arguments(tool_call, tool_name=registered_name)
    return _Invocation(
        tool_name=registered_name,
        tool_call_id=tool_call_id,
        args=args,
        metadata=metadata.get(registered_name),
    )


def _registered_tool_name(request: ToolCallRequest) -> str | None:
    tool = request.tool
    if tool is None:
        return None
    tool_name = getattr(tool, "name", None)
    if not isinstance(tool_name, str) or not tool_name:
        return None
    return tool_name


def _model_tool_name(tool_call: object) -> str | None:
    if not isinstance(tool_call, Mapping):
        return None
    tool_name = tool_call.get("name")
    if not isinstance(tool_name, str) or not tool_name:
        return None
    return tool_name


def _tool_call_id(tool_call: object) -> str:
    if isinstance(tool_call, Mapping):
        tool_call_id = tool_call.get("id")
        if isinstance(tool_call_id, str) and tool_call_id:
            return tool_call_id
    return "taintgate.invalid_tool_call"


def _tool_arguments(tool_call: object, *, tool_name: str) -> dict[str, Any]:
    if not isinstance(tool_call, Mapping):
        raise BlockedAction(
            _validation_decision(
                tool_name,
                rule_id="runtime.invalid_tool_call",
                message="Tool call payload was not an object",
            )
        )

    args = tool_call.get("args")
    if not isinstance(args, Mapping):
        raise BlockedAction(
            _validation_decision(
                tool_name,
                rule_id="runtime.invalid_tool_arguments",
                message="Tool arguments must be an object",
            )
        )
    return dict(args)


def _validation_decision(
    tool_name: str,
    *,
    rule_id: str,
    message: str,
) -> Decision:
    return Decision(
        action=Action.BLOCK,
        score=100,
        tool=tool_name,
        findings=(Finding(rule_id=rule_id, message=message, score=100, path="$"),),
        matched_policies=(),
    )


def _tool_denied_message(
    decision: Decision,
    *,
    tool_call_id: str,
    review_required: bool,
) -> ToolMessage:
    content = (
        "TaintGate requires explicit approval before this tool can run."
        if review_required
        else "TaintGate blocked this tool call."
    )
    return ToolMessage(
        content=content,
        name=decision.tool,
        tool_call_id=tool_call_id,
        status="error",
        artifact=_decision_artifact(decision),
    )


def _audit_failure_message(exc: AuditSinkError, *, tool_call_id: str) -> ToolMessage:
    return ToolMessage(
        content="TaintGate prevented this tool call because audit recording failed.",
        name=exc.event.tool,
        tool_call_id=tool_call_id,
        status="error",
        artifact=_audit_artifact(exc),
    )


def _decision_artifact(decision: Decision) -> dict[str, dict[str, object]]:
    return {
        "taintgate": {
            "action": decision.action.value,
            "risk_score": decision.risk_score,
            "finding_ids": _dedupe(finding.rule_id for finding in decision.findings),
            "matched_policies": list(decision.matched_policies),
        }
    }


def _audit_artifact(exc: AuditSinkError) -> dict[str, dict[str, object]]:
    return {
        "taintgate": {
            "action": exc.event.policy_action.value,
            "risk_score": exc.event.risk_score,
            "finding_ids": list(exc.event.finding_ids),
            "matched_policies": list(exc.event.matched_policies),
        }
    }


def _dedupe(values: Any) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


__all__ = ["TaintGateToolMiddleware"]
