from __future__ import annotations

import asyncio
import importlib.metadata
import inspect
import json
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool, tool
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import ToolRuntime
from langgraph.runtime import Runtime
from packaging.version import Version

from taintgate import ApprovalAction, BlockedAction, Guard, Policy, ToolMetadata, ToolPolicy
from taintgate.langchain import TaintGateToolMiddleware

_FAKE_SECRET = "sk-FAKELANGCHAIN1234567890"
_FAKE_PHONE = "(415) 555-2671"


class _BoundFakeMessagesListChatModel(FakeMessagesListChatModel):
    def bind_tools(
        self,
        tools: Any,
        *,
        tool_choice: Any = None,
        **kwargs: Any,
    ) -> _BoundFakeMessagesListChatModel:
        del tools, tool_choice, kwargs
        return self


def test_core_import_remains_independent_of_langchain_sdk() -> None:
    script = """
import builtins

real_import = builtins.__import__

def blocked(name, globals=None, locals=None, fromlist=(), level=0):
    if (
        name == "langchain"
        or name.startswith("langchain.")
        or name == "langgraph"
        or name.startswith("langgraph.")
    ):
        raise ImportError("blocked langchain for test")
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


def test_langchain_integration_missing_extra_error_is_clear() -> None:
    script = """
import builtins

real_import = builtins.__import__

def blocked(name, globals=None, locals=None, fromlist=(), level=0):
    if (
        name == "langchain"
        or name.startswith("langchain.")
        or name == "langgraph"
        or name.startswith("langgraph.")
    ):
        raise ImportError("blocked langchain for test")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = blocked

try:
    import taintgate.langchain  # noqa: F401
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
    assert 'pip install "taintgate[langgraph]"' in completed.stdout


def test_installed_langchain_api_versions_and_smoke_test() -> None:
    assert Version("1.3.15") <= Version(importlib.metadata.version("langchain")) < Version("1.4")
    assert Version("1.2.11") <= Version(importlib.metadata.version("langgraph")) < Version("1.3")

    create_agent_signature = str(inspect.signature(create_agent))
    wrap_signature = str(inspect.signature(AgentMiddleware.wrap_tool_call))
    awrap_signature = str(inspect.signature(AgentMiddleware.awrap_tool_call))
    tool_node_signature = str(inspect.signature(ToolNode))

    assert "middleware" in create_agent_signature
    assert "request:" in wrap_signature
    assert "handler:" in wrap_signature
    assert "Awaitable" in awrap_signature
    assert "wrap_tool_call" in tool_node_signature
    assert "handle_tool_errors" in tool_node_signature


def test_create_agent_middleware_allow_path_executes_once() -> None:
    calls = {"count": 0}

    @tool
    def search_docs(query: str) -> str:
        """Search local docs."""
        calls["count"] += 1
        return f"result:{query}"

    model = _BoundFakeMessagesListChatModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[{"name": "search_docs", "args": {"query": "docs"}, "id": "call_1"}],
            ),
            AIMessage(content="done"),
        ]
    )
    agent = create_agent(
        model,
        tools=[search_docs],
        middleware=[TaintGateToolMiddleware(Guard())],
    )

    result = agent.invoke({"messages": [{"role": "user", "content": "find docs"}]})
    tool_messages = [message for message in result["messages"] if isinstance(message, ToolMessage)]

    assert calls["count"] == 1
    assert len(tool_messages) == 1
    assert tool_messages[0].content == "result:docs"


def test_allow_path_uses_only_local_fake_components(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unexpected(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("langchain integration attempted a real network call")

    monkeypatch.setattr(socket, "create_connection", _unexpected)
    calls = {"count": 0}

    @tool
    def search_docs(query: str) -> str:
        """Search local docs."""
        calls["count"] += 1
        return query

    model = _BoundFakeMessagesListChatModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[{"name": "search_docs", "args": {"query": "offline"}, "id": "call_1"}],
            ),
            AIMessage(content="done"),
        ]
    )
    agent = create_agent(
        model,
        tools=[search_docs],
        middleware=[TaintGateToolMiddleware(Guard())],
    )

    result = agent.invoke({"messages": [{"role": "user", "content": "find docs"}]})

    assert calls["count"] == 1
    assert result["messages"][-1].content == "done"


def test_block_handler_invocation_count_zero_and_no_secret_leak() -> None:
    calls = {"count": 0}
    middleware = TaintGateToolMiddleware(
        Guard(),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )
    send_email = _send_email_tool(calls)
    request = _build_request(send_email, args={"to": "outside@example.net", "body": _FAKE_SECRET})

    result = middleware.wrap_tool_call(request, _sync_handler(calls))
    payload = json.dumps(result.model_dump())

    assert calls["count"] == 0
    assert result.status == "error"
    assert result.artifact["taintgate"]["action"] == "block"
    assert "secret.openai_api_key" in result.artifact["taintgate"]["finding_ids"]
    assert "flow.sensitive_to_external" in result.artifact["taintgate"]["finding_ids"]
    assert _FAKE_SECRET not in payload
    assert _FAKE_SECRET not in result.content


def test_review_without_approval_invocation_count_zero() -> None:
    calls = {"count": 0}
    middleware = TaintGateToolMiddleware(
        Guard(),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )
    send_email = _send_email_tool(calls)
    request = _build_request(
        send_email,
        args={"to": "outside@example.net", "body": f"Call {_FAKE_PHONE}."},
    )

    result = middleware.wrap_tool_call(request, _sync_handler(calls))

    assert calls["count"] == 0
    assert result.status == "error"
    assert result.artifact["taintgate"]["action"] == "review"


def test_review_with_explicit_approval_invocation_count_one() -> None:
    calls = {"count": 0}
    middleware = TaintGateToolMiddleware(
        Guard(approval_handler=lambda _request: ApprovalAction.APPROVE),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )
    send_email = _send_email_tool(calls)
    request = _build_request(
        send_email,
        args={"to": "outside@example.net", "body": f"Call {_FAKE_PHONE}."},
    )

    result = middleware.wrap_tool_call(request, _sync_handler(calls))

    assert calls["count"] == 1
    assert result.status == "success"
    assert result.content == "handled"


def test_async_review_with_explicit_approval_invocation_count_one() -> None:
    calls = {"count": 0}

    async def approval_handler(_request: object) -> ApprovalAction:
        await asyncio.sleep(0)
        return ApprovalAction.APPROVE

    middleware = TaintGateToolMiddleware(
        Guard(approval_handler=approval_handler),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )
    send_email = _send_email_tool(calls)
    request = _build_request(
        send_email,
        args={"to": "outside@example.net", "body": f"Call {_FAKE_PHONE}."},
    )

    result = asyncio.run(middleware.awrap_tool_call(request, _async_handler(calls)))

    assert calls["count"] == 1
    assert result.status == "success"
    assert result.content == "handled"


def test_tool_name_mismatch_fails_closed() -> None:
    calls = {"count": 0}
    middleware = TaintGateToolMiddleware(Guard())
    search_docs = _search_docs_tool(calls)
    request = _build_request(
        search_docs,
        call_name="other_tool",
        args={"query": "docs"},
    )

    result = middleware.wrap_tool_call(request, _sync_handler(calls))

    assert calls["count"] == 0
    assert result.status == "error"
    assert result.artifact["taintgate"]["finding_ids"] == ["runtime.tool_name_mismatch"]


@pytest.mark.parametrize("args", [[], "oops", 123, None])
def test_malformed_args_fail_closed(args: object) -> None:
    calls = {"count": 0}
    middleware = TaintGateToolMiddleware(Guard())
    search_docs = _search_docs_tool(calls)
    request = _build_request(search_docs, args=args)

    result = middleware.wrap_tool_call(request, _sync_handler(calls))

    assert calls["count"] == 0
    assert result.status == "error"
    assert result.artifact["taintgate"]["finding_ids"] == ["runtime.invalid_tool_arguments"]


def test_metadata_cannot_be_weakened_by_runtime_mapping() -> None:
    calls = {"count": 0}
    guard = Guard(
        policy=Policy(
            tools={
                "send_email": ToolPolicy(
                    side_effecting=True,
                    external_destination=True,
                )
            }
        )
    )
    middleware = TaintGateToolMiddleware(
        guard,
        metadata={"send_email": ToolMetadata()},
    )
    send_email = _send_email_tool(calls)
    request = _build_request(send_email, args={"to": "outside@example.net", "body": _FAKE_SECRET})

    result = middleware.wrap_tool_call(request, _sync_handler(calls))

    assert calls["count"] == 0
    assert result.status == "error"
    assert "flow.sensitive_to_external" in result.artifact["taintgate"]["finding_ids"]


def test_destructive_detector_drives_enforcement() -> None:
    calls = {"count": 0}
    middleware = TaintGateToolMiddleware(
        Guard(
            policy=Policy(
                tools={
                    "execute_shell": ToolPolicy(
                        default="review",
                        on_destructive="block",
                    )
                }
            )
        )
    )
    execute_shell = _execute_shell_tool(calls)
    request = _build_request(execute_shell, args={"command": "rm -rf /"})

    result = middleware.wrap_tool_call(request, _sync_handler(calls))

    assert calls["count"] == 0
    assert result.status == "error"
    assert result.artifact["taintgate"]["action"] == "block"
    assert "action.shell.destructive" in result.artifact["taintgate"]["finding_ids"]


def test_direct_tool_node_helper_allow_path_executes_once() -> None:
    calls = {"count": 0}
    middleware = TaintGateToolMiddleware(Guard())
    search_docs = _search_docs_tool(calls)
    node = middleware.tool_node([search_docs])

    result = node.invoke(
        [{"name": "search_docs", "args": {"query": "docs"}, "id": "call_1", "type": "tool_call"}],
        runtime=Runtime(context=None),
    )
    if isinstance(result, dict):
        messages = result.get("messages", [result])
    elif isinstance(result, list):
        messages = result
    else:
        messages = [result]
    first = messages[0]
    content = first["content"] if isinstance(first, dict) else first.content

    assert calls["count"] == 1
    assert len(messages) == 1
    assert content == "search:docs"


def test_tool_node_helper_does_not_swallow_taintgate_security_exceptions() -> None:
    calls = {"count": 0}
    middleware = TaintGateToolMiddleware(
        Guard(),
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )
    send_email = _send_email_tool(calls)
    node = middleware.tool_node([send_email])

    with pytest.raises(BlockedAction) as exc_info:
        node.invoke(
            [
                {
                    "name": "send_email",
                    "args": {"to": "outside@example.net", "body": _FAKE_SECRET},
                    "id": "call_1",
                    "type": "tool_call",
                }
            ],
            runtime=Runtime(context=None),
        )

    assert calls["count"] == 0
    assert exc_info.value.decision.action.value == "block"


def _build_request(
    registered_tool: BaseTool | None,
    *,
    args: object,
    call_name: str | None = None,
    tool_call_id: str = "call_1",
) -> ToolCallRequest:
    runtime = ToolRuntime(
        state={"messages": []},
        context=None,
        config={},
        stream_writer=_stream_writer,
        tool_call_id=tool_call_id,
        store=None,
        tools=[registered_tool] if registered_tool is not None else [],
    )
    tool_call = {
        "name": call_name or (registered_tool.name if registered_tool is not None else "unknown_tool"),
        "args": args,
        "id": tool_call_id,
        "type": "tool_call",
    }
    return ToolCallRequest(
        tool_call=tool_call,
        tool=registered_tool,
        state={"messages": []},
        runtime=runtime,
    )


def _stream_writer(_value: object) -> None:
    return None


def _sync_handler(calls: dict[str, int]) -> Any:
    def handler(request: ToolCallRequest) -> ToolMessage:
        calls["count"] += 1
        return ToolMessage(
            content="handled",
            name=request.tool.name if request.tool is not None else None,
            tool_call_id=cast(str, request.tool_call["id"]),
        )

    return handler


def _async_handler(calls: dict[str, int]) -> Any:
    async def handler(request: ToolCallRequest) -> ToolMessage:
        await asyncio.sleep(0)
        calls["count"] += 1
        return ToolMessage(
            content="handled",
            name=request.tool.name if request.tool is not None else None,
            tool_call_id=cast(str, request.tool_call["id"]),
        )

    return handler


def _search_docs_tool(calls: dict[str, int]) -> BaseTool:
    @tool
    def search_docs(query: str) -> str:
        """Search local docs."""
        calls["count"] += 1
        return f"search:{query}"

    return search_docs


def _send_email_tool(calls: dict[str, int]) -> BaseTool:
    @tool
    def send_email(to: str, body: str) -> str:
        """Send a fake email."""
        calls["count"] += 1
        return f"sent:{to}:{len(body)}"

    return send_email


def _execute_shell_tool(calls: dict[str, int]) -> BaseTool:
    @tool
    def execute_shell(command: str) -> str:
        """Execute a fake shell command."""
        calls["count"] += 1
        return f"ran:{len(command)}"

    return execute_shell
