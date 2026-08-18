from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

try:
    from agents import (
        FunctionTool,
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
        ToolInputGuardrailData,
        tool_input_guardrail,
    )
    from agents import function_tool as _sdk_function_tool
except ImportError as exc:  # pragma: no cover - exercised in subprocess test
    raise ImportError(
        'taintgate.openai_agents requires the OpenAI Agents SDK. '
        'Install it with: pip install "taintgate[openai]"'
    ) from exc

from .exceptions import ApprovalError, ApprovalRequired, AuditSinkError, BlockedAction
from .guard import Guard
from .models import Action, CallContext, Decision, ToolMetadata


class TaintGateToolGuardrail:
    """Adapter that applies TaintGate decisions through the OpenAI Agents SDK."""

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

    def for_tool(
        self,
        tool_name: str,
        *,
        metadata: ToolMetadata | None = None,
    ) -> ToolInputGuardrail[Any]:
        if not isinstance(tool_name, str) or not tool_name:
            raise TypeError("tool_name must be a non-empty string")
        if metadata is not None and not isinstance(metadata, ToolMetadata):
            raise TypeError("metadata must be a ToolMetadata instance or None")

        runtime_metadata = _merge_runtime_metadata(self._metadata.get(tool_name), metadata)

        @tool_input_guardrail(name=f"taintgate_{tool_name}")
        async def _guardrail(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
            try:
                args = _parse_tool_arguments(data.context.tool_arguments)
            except (TypeError, ValueError):
                return ToolGuardrailFunctionOutput.raise_exception(
                    output_info=_failure_output_info("runtime.invalid_tool_arguments")
                )

            context = CallContext(session_id=data.context.tool_call_id)
            try:
                action_context = await self._guard._authorize_async(
                    data.context.tool_name,
                    args,
                    context=context,
                    metadata=runtime_metadata,
                )
            except (ApprovalRequired, ApprovalError, BlockedAction) as exc:
                return ToolGuardrailFunctionOutput.raise_exception(
                    output_info=_decision_output_info(exc.decision)
                )
            except AuditSinkError as exc:
                return ToolGuardrailFunctionOutput.raise_exception(
                    output_info=_audit_event_output_info(exc.event)
                )

            return ToolGuardrailFunctionOutput.allow(
                output_info=_decision_output_info(
                    action_context.decision,
                    event_id=action_context.event_id,
                )
            )

        return _guardrail

    def function_tool(
        self,
        func: Callable[..., Any] | None = None,
        *,
        metadata: ToolMetadata | None = None,
        **kwargs: Any,
    ) -> FunctionTool | Callable[[Callable[..., Any]], FunctionTool]:
        if kwargs.get("needs_approval", False) is not False:
            raise ValueError(
                "TaintGateToolGuardrail.function_tool does not support SDK needs_approval. "
                "Use TaintGate approval on the Guard instead."
            )

        def decorator(real_func: Callable[..., Any]) -> FunctionTool:
            tool_name = kwargs.get("name_override") or real_func.__name__
            tool_input_guardrails = list(kwargs.get("tool_input_guardrails") or [])
            tool_input_guardrails.append(self.for_tool(tool_name, metadata=metadata))

            tool_kwargs = dict(kwargs)
            tool_kwargs["tool_input_guardrails"] = tool_input_guardrails
            return _sdk_function_tool(real_func, **tool_kwargs)

        if func is not None:
            return decorator(func)
        return decorator


def _merge_runtime_metadata(
    adapter_metadata: ToolMetadata | None,
    explicit_metadata: ToolMetadata | None,
) -> ToolMetadata | None:
    if adapter_metadata is None:
        return explicit_metadata
    return adapter_metadata.merge(explicit_metadata)


def _parse_tool_arguments(raw_arguments: str) -> dict[str, Any]:
    if not isinstance(raw_arguments, str):
        raise TypeError("tool_arguments must be a JSON string")
    try:
        parsed = json.loads(raw_arguments)
    except json.JSONDecodeError as exc:
        raise ValueError("tool_arguments must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise TypeError("tool_arguments must decode to a JSON object")
    return parsed


def _decision_output_info(
    decision: Decision,
    *,
    event_id: str | None = None,
) -> dict[str, dict[str, object]]:
    taintgate: dict[str, object] = {
        "action": decision.action.value,
        "risk_score": decision.risk_score,
        "finding_ids": _dedupe(finding.rule_id for finding in decision.findings),
        "matched_policies": list(decision.matched_policies),
    }
    if event_id is not None:
        taintgate["event_id"] = event_id
    return {"taintgate": taintgate}


def _audit_event_output_info(event: Any) -> dict[str, dict[str, object]]:
    taintgate: dict[str, object] = {
        "action": event.policy_action.value,
        "risk_score": event.risk_score,
        "finding_ids": list(event.finding_ids),
        "matched_policies": list(event.matched_policies),
        "event_id": event.event_id,
    }
    return {"taintgate": taintgate}


def _failure_output_info(rule_id: str) -> dict[str, dict[str, object]]:
    return {
        "taintgate": {
            "action": Action.BLOCK.value,
            "risk_score": 100,
            "finding_ids": [rule_id],
            "matched_policies": [],
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


__all__ = ["TaintGateToolGuardrail"]
