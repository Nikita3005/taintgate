from __future__ import annotations

import asyncio
import importlib.metadata
import inspect
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from agents import (
    ToolInputGuardrailData,
    ToolInputGuardrailTripwireTriggered,
    function_tool,
)
from agents.tool_context import ToolContext

from taintgate import ApprovalAction, Guard, ToolMetadata
from taintgate.openai_agents import TaintGateToolGuardrail

_FAKE_SECRET = "sk-FAKEOPENAI1234567890"


def test_core_import_remains_independent_of_openai_sdk() -> None:
    script = """
import builtins

real_import = builtins.__import__

def blocked(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "agents" or name.startswith("agents."):
        raise ImportError("blocked agents for test")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = blocked

import taintgate
print("core-ok")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path.cwd(),
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == "core-ok"


def test_openai_integration_missing_extra_error_is_clear() -> None:
    script = """
import builtins

real_import = builtins.__import__

def blocked(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "agents" or name.startswith("agents."):
        raise ImportError("blocked agents for test")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = blocked

try:
    import taintgate.openai_agents  # noqa: F401
except ImportError as exc:
    print(str(exc))
else:
    raise SystemExit("expected ImportError")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path.cwd(),
    )

    assert completed.returncode == 0
    assert 'pip install "taintgate[openai]"' in completed.stdout


def test_installed_sdk_version_and_public_api_smoke_test() -> None:
    version = importlib.metadata.version("openai-agents")
    data_signature = str(inspect.signature(ToolInputGuardrailData))

    assert version == "0.21.1"
    assert "tool_input_guardrails" in str(inspect.signature(function_tool))
    assert "context:" in data_signature
    assert "agent:" in data_signature


def test_allow_maps_to_sdk_allow() -> None:
    tg = TaintGateToolGuardrail(Guard())

    output = asyncio.run(_run_guardrail(tg.for_tool("search_docs"), "search_docs", {"query": "docs"}))

    assert output.behavior["type"] == "allow"
    assert output.output_info["taintgate"]["action"] == "allow"
    assert output.output_info["taintgate"]["risk_score"] == 0


def test_block_maps_to_sdk_raise_exception_and_tool_does_not_execute() -> None:
    state = {"called": False}
    tg = TaintGateToolGuardrail(
        Guard(),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )

    @tg.function_tool
    def send_email(to: str, body: str) -> str:
        state["called"] = True
        return "sent"

    with pytest.raises(ToolInputGuardrailTripwireTriggered) as exc_info:
        asyncio.run(
            _execute_tool(
                send_email,
                {"to": "outside@example.net", "body": _FAKE_SECRET},
            )
        )

    output_info = exc_info.value.output.output_info["taintgate"]
    assert state["called"] is False
    assert output_info["action"] == "block"
    assert "secret.openai_api_key" in output_info["finding_ids"]
    assert "flow.sensitive_to_external" in output_info["finding_ids"]
    assert _FAKE_SECRET not in json.dumps(exc_info.value.output.output_info)
    assert _FAKE_SECRET not in str(exc_info.value)


def test_review_without_approval_fails_closed() -> None:
    state = {"called": False}
    tg = TaintGateToolGuardrail(
        Guard(),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )

    @tg.function_tool
    def send_email(to: str, body: str) -> str:
        state["called"] = True
        return "sent"

    with pytest.raises(ToolInputGuardrailTripwireTriggered) as exc_info:
        asyncio.run(
            _execute_tool(
                send_email,
                {"to": "outside@example.net", "body": "Contact me at (415) 555-2671."},
            )
        )

    assert state["called"] is False
    assert exc_info.value.output.output_info["taintgate"]["action"] == "review"


def test_review_with_explicit_taintgate_approval_allows_execution() -> None:
    state = {"called": False}
    tg = TaintGateToolGuardrail(
        Guard(
            approval_handler=lambda _request: ApprovalAction.APPROVE,
        ),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )

    @tg.function_tool
    def send_email(to: str, body: str) -> str:
        state["called"] = True
        return "sent"

    result = asyncio.run(
        _execute_tool(
            send_email,
            {"to": "outside@example.net", "body": "Contact me at (415) 555-2671."},
        )
    )

    assert result == "sent"
    assert state["called"] is True


def test_malformed_json_fails_closed() -> None:
    tg = TaintGateToolGuardrail(Guard())

    output = asyncio.run(_run_guardrail_raw(tg.for_tool("search_docs"), "search_docs", "{"))

    assert output.behavior["type"] == "raise_exception"
    assert output.output_info["taintgate"]["finding_ids"] == ["runtime.invalid_tool_arguments"]


@pytest.mark.parametrize("raw_arguments", ["[]", "123", '"hello"', "null"])
def test_non_object_json_fails_closed(raw_arguments: str) -> None:
    tg = TaintGateToolGuardrail(Guard())

    output = asyncio.run(_run_guardrail_raw(tg.for_tool("search_docs"), "search_docs", raw_arguments))

    assert output.behavior["type"] == "raise_exception"
    assert output.output_info["taintgate"]["action"] == "block"


def test_tool_metadata_mapping_and_explicit_override_are_applied() -> None:
    tg = TaintGateToolGuardrail(
        Guard(),
        metadata={"deliver_message": ToolMetadata(side_effecting=True)},
    )

    output = asyncio.run(
        _run_guardrail(
            tg.for_tool(
                "deliver_message",
                metadata=ToolMetadata(external_destination=True),
            ),
            "deliver_message",
            {"body": "Contact me at (415) 555-2671."},
        )
    )

    assert output.behavior["type"] == "raise_exception"
    assert "flow.sensitive_to_external" in output.output_info["taintgate"]["finding_ids"]


def test_sanitized_output_info_contains_only_safe_decision_metadata() -> None:
    tg = TaintGateToolGuardrail(
        Guard(),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )

    output = asyncio.run(
        _run_guardrail(
            tg.for_tool("send_email"),
            "send_email",
            {"to": "outside@example.net", "body": _FAKE_SECRET},
        )
    )

    taintgate_info = output.output_info["taintgate"]
    assert set(taintgate_info).issubset(
        {"action", "risk_score", "finding_ids", "matched_policies", "event_id"}
    )
    assert _FAKE_SECRET not in json.dumps(output.output_info)


def test_async_guardrail_path_supports_async_taintgate_approval() -> None:
    state = {"called": False}

    async def approval_handler(_request) -> ApprovalAction:
        await asyncio.sleep(0)
        return ApprovalAction.APPROVE

    tg = TaintGateToolGuardrail(
        Guard(approval_handler=approval_handler),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )

    @tg.function_tool
    async def send_email(to: str, body: str) -> str:
        await asyncio.sleep(0)
        state["called"] = True
        return "sent"

    result = asyncio.run(
        _execute_tool(
            send_email,
            {"to": "outside@example.net", "body": "Contact me at (415) 555-2671."},
        )
    )

    assert result == "sent"
    assert state["called"] is True


def test_sdk_needs_approval_is_rejected_by_convenience_wrapper() -> None:
    tg = TaintGateToolGuardrail(Guard())

    def search_docs(query: str) -> str:
        return query

    with pytest.raises(ValueError, match="needs_approval"):
        tg.function_tool(search_docs, needs_approval=True)


async def _run_guardrail(
    guardrail,
    tool_name: str,
    arguments: dict[str, object],
):
    return await _run_guardrail_raw(guardrail, tool_name, json.dumps(arguments))


async def _run_guardrail_raw(
    guardrail,
    tool_name: str,
    raw_arguments: str,
):
    context = ToolContext(
        context=None,
        tool_name=tool_name,
        tool_call_id="call_123",
        tool_arguments=raw_arguments,
    )
    data = ToolInputGuardrailData(context=context, agent=SimpleNamespace(name="demo"))
    return await guardrail.run(data)


async def _execute_tool(tool, arguments: dict[str, object]):
    raw_arguments = json.dumps(arguments)
    context = ToolContext(
        context=None,
        tool_name=tool.name,
        tool_call_id="call_123",
        tool_arguments=raw_arguments,
    )
    data = ToolInputGuardrailData(context=context, agent=SimpleNamespace(name="demo"))
    for guardrail in tool.tool_input_guardrails or []:
        output = await guardrail.run(data)
        if output.behavior["type"] == "raise_exception":
            raise ToolInputGuardrailTripwireTriggered(guardrail, output)
    return await tool.on_invoke_tool(context, raw_arguments)
