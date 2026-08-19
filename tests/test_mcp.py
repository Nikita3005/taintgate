from __future__ import annotations

import asyncio
import importlib.metadata
import inspect
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import types

import taintgate.mcp as taintgate_mcp
from taintgate import (
    ApprovalAction,
    ApprovalRequired,
    BlockedAction,
    Guard,
    Policy,
    PostExecutionProvenanceError,
    TaintedString,
    ToolMetadata,
)
from taintgate.mcp import TaintGateMCPClient

_CANONICAL_TOOL = "mcp:filesystem/read_file"
_FAKE_SECRET = "token=demo-secret"
_SUPER_SECRET_MARKER = "SUPER_SECRET_MCP_PAYLOAD_123"


class _FakeSession:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
        progress_callback: Any | None = None,
        *,
        input_responses: Any | None = None,
        request_state: str | None = None,
        meta: Any | None = None,
        allow_input_required: bool = False,
        allow_claimed: bool = False,
    ) -> object:
        self.calls.append(
            {
                "name": name,
                "arguments": arguments,
                "read_timeout_seconds": read_timeout_seconds,
                "progress_callback": progress_callback,
                "input_responses": input_responses,
                "request_state": request_state,
                "meta": meta,
                "allow_input_required": allow_input_required,
                "allow_claimed": allow_claimed,
            }
        )
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class _MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def write(self, event: Any) -> None:
        self.events.append(event)


class _RemoteMCPError(RuntimeError):
    pass


class _LeakyStructuredValue:
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def __repr__(self) -> str:
        return f"_LeakyStructuredValue({self.secret})"


def _states(sink: _MemoryAuditSink) -> list[str]:
    return [event.execution_state.value for event in sink.events]


def _too_deep_structured_content(secret: str) -> Any:
    value: Any = secret
    for _ in range(10):
        value = {"child": value}
    return value


def _too_many_nodes_structured_content(secret: str) -> Any:
    return [secret] * 512


def _cyclic_structured_content(secret: str) -> Any:
    cycle: list[Any] = [secret]
    cycle.append(cycle)
    return cycle


def _unsupported_structured_content(secret: str) -> Any:
    return {"payload": _LeakyStructuredValue(secret)}


def _assert_deep_content_unmodified(value: Any) -> None:
    current = value
    while isinstance(current, dict):
        current = current["child"]
    assert current == _FAKE_SECRET
    assert not isinstance(current, TaintedString)


def _assert_node_budget_content_unmodified(value: Any) -> None:
    assert value[0] == _FAKE_SECRET
    assert value[-1] == _FAKE_SECRET
    assert not isinstance(value[0], TaintedString)


def _assert_cyclic_content_unmodified(value: Any) -> None:
    assert value[0] == _FAKE_SECRET
    assert not isinstance(value[0], TaintedString)
    assert value[1] is value


def _assert_unsupported_content_unmodified(value: Any) -> None:
    assert isinstance(value["payload"], _LeakyStructuredValue)
    assert value["payload"].secret == _FAKE_SECRET


def test_core_import_remains_independent_of_mcp_sdk() -> None:
    script = """
import builtins

real_import = builtins.__import__

def blocked(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "mcp" or name.startswith("mcp."):
        raise ImportError("blocked mcp for test")
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


def test_mcp_integration_missing_extra_error_is_clear() -> None:
    script = """
import builtins

real_import = builtins.__import__

def blocked(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "mcp" or name.startswith("mcp."):
        raise ImportError("blocked mcp for test")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = blocked

try:
    import taintgate.mcp  # noqa: F401
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
    assert 'pip install "taintgate[mcp]"' in completed.stdout


def test_installed_mcp_sdk_version_and_public_api_smoke_test() -> None:
    assert importlib.metadata.version("mcp") == "2.0.0"
    assert str(inspect.signature(types.CallToolResult)).startswith("(*, _meta:")
    assert "arguments:" in str(inspect.signature(TaintGateMCPClient.call_tool))
    assert "authorize_call_async" in dir(Guard)
    assert "record_execution_outcome" in dir(Guard)
    assert list(types.CallToolResult.model_fields.keys()) == [
        "meta",
        "content",
        "structured_content",
        "is_error",
        "result_type",
    ]
    assert list(types.InputRequiredResult.model_fields.keys()) == [
        "meta",
        "result_type",
        "input_requests",
        "request_state",
    ]
    assert list(types.TextContent.model_fields.keys()) == ["type", "text", "annotations", "meta"]
    assert list(types.EmbeddedResource.model_fields.keys()) == ["type", "resource", "annotations", "meta"]
    assert list(types.TextResourceContents.model_fields.keys()) == ["uri", "mime_type", "meta", "text"]


def test_allow_calls_underlying_session_once_and_taints_text_and_nested_structured_content() -> None:
    original = types.CallToolResult(
        content=[
            types.TextContent(text="readme body"),
            types.EmbeddedResource(
                resource=types.TextResourceContents(uri="memo://doc", text="embedded text")
            ),
        ],
        structuredContent={
            "title": "Project Docs",
            "meta": {"author": "Nikita", "count": 3, "ok": True, "missing": None},
            "items": ["first", 2],
        },
    )
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    result = asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    assert len(session.calls) == 1
    assert session.calls[0]["name"] == "read_file"
    assert session.calls[0]["arguments"] == {"path": "README.md"}
    text = result.content[0].text
    embedded_text = result.content[1].resource.text
    assert isinstance(text, TaintedString)
    assert text.trust.value == "untrusted"
    assert text.source_type == "mcp"
    assert text.origin == _CANONICAL_TOOL
    assert isinstance(embedded_text, TaintedString)
    assert embedded_text.origin == _CANONICAL_TOOL
    assert isinstance(result.structured_content["title"], TaintedString)
    assert isinstance(result.structured_content["meta"]["author"], TaintedString)
    assert isinstance(result.structured_content["items"][0], TaintedString)
    assert result.structured_content["meta"]["count"] == 3
    assert result.structured_content["meta"]["ok"] is True
    assert result.structured_content["meta"]["missing"] is None


def test_structured_content_top_level_string_is_tainted() -> None:
    session = _FakeSession(types.CallToolResult(content=[], structuredContent="plain text"))
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    result = asyncio.run(client.call_tool("read_file", None))

    assert isinstance(result.structured_content, TaintedString)
    assert result.structured_content.origin == _CANONICAL_TOOL


def test_original_sdk_result_object_is_not_mutated() -> None:
    original = types.CallToolResult(
        content=[types.TextContent(text="body")],
        structuredContent={"title": "Guide"},
    )
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    result = asyncio.run(client.call_tool("read_file", {"path": "guide.md"}))

    assert result is not original
    assert original.content[0].text == "body"
    assert not isinstance(original.content[0].text, TaintedString)
    assert original.structured_content["title"] == "Guide"
    assert not isinstance(original.structured_content["title"], TaintedString)


def test_arguments_none_is_accepted_and_preserved_for_underlying_call() -> None:
    session = _FakeSession(types.CallToolResult(content=[types.TextContent(text="ok")]))
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    asyncio.run(client.call_tool("read_file", None))

    assert len(session.calls) == 1
    assert session.calls[0]["arguments"] is None


@pytest.mark.parametrize("arguments", [[], (), "oops", 123, object()])
def test_invalid_arguments_fail_closed_without_underlying_call(arguments: object) -> None:
    session = _FakeSession(types.CallToolResult(content=[types.TextContent(text="ok")]))
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    with pytest.raises(TypeError, match="tool arguments"):
        asyncio.run(client.call_tool("read_file", arguments))

    assert session.calls == []


def test_review_without_approval_fails_closed_and_does_not_call_underlying_session() -> None:
    session = _FakeSession(types.CallToolResult(content=[types.TextContent(text="ok")]))
    guard = Guard(policy=Policy(review_tools={_CANONICAL_TOOL}))
    client = TaintGateMCPClient(session, guard, server_name="filesystem")

    with pytest.raises(ApprovalRequired) as exc_info:
        asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    assert exc_info.value.decision.tool == _CANONICAL_TOOL
    assert session.calls == []


def test_review_with_explicit_approval_calls_underlying_session_once() -> None:
    session = _FakeSession(types.CallToolResult(content=[types.TextContent(text="approved")]))
    guard = Guard(
        policy=Policy(review_tools={_CANONICAL_TOOL}),
        approval_handler=lambda _request: ApprovalAction.APPROVE,
    )
    client = TaintGateMCPClient(session, guard, server_name="filesystem")

    result = asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    assert len(session.calls) == 1
    assert isinstance(result.content[0].text, TaintedString)


def test_allow_successful_call_records_executed_audit_state() -> None:
    sink = _MemoryAuditSink()
    original = types.CallToolResult(content=[types.TextContent(text="ok")])
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(audit_sink=sink), server_name="filesystem")

    result = asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    assert len(session.calls) == 1
    assert isinstance(result.content[0].text, TaintedString)
    assert _states(sink) == ["allowed", "executed"]
    assert len({event.event_id for event in sink.events}) == 1


def test_block_does_not_call_underlying_session() -> None:
    session = _FakeSession(types.CallToolResult(content=[types.TextContent(text="blocked")]))
    guard = Guard()
    client = TaintGateMCPClient(
        session,
        guard,
        server_name="filesystem",
        metadata={"send_email": ToolMetadata(side_effecting=True, external_destination=True)},
    )

    with pytest.raises(BlockedAction) as exc_info:
        asyncio.run(
            client.call_tool(
                "send_email",
                {"to": "outside@example.net", "body": "sk-FAKEMCP1234567890"},
            )
        )

    assert exc_info.value.decision.tool == "mcp:filesystem/send_email"
    assert session.calls == []


def test_error_result_preserves_is_error_and_taints_error_text() -> None:
    original = types.CallToolResult(
        content=[types.TextContent(text="server error")],
        structuredContent={"message": "not authorized"},
        isError=True,
    )
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    result = asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    assert result.is_error is True
    assert isinstance(result.content[0].text, TaintedString)
    assert isinstance(result.structured_content["message"], TaintedString)


def test_underlying_mcp_exception_is_preserved_and_records_execution_failed() -> None:
    sink = _MemoryAuditSink()
    session = _FakeSession(_RemoteMCPError("remote boom"))
    client = TaintGateMCPClient(session, Guard(audit_sink=sink), server_name="filesystem")

    with pytest.raises(_RemoteMCPError, match="remote boom"):
        asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    assert len(session.calls) == 1
    assert _states(sink) == ["allowed", "execution_failed"]
    assert len({event.event_id for event in sink.events}) == 1


def test_input_required_result_is_preserved_unchanged() -> None:
    original = types.InputRequiredResult(requestState="state-1")
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    result = asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    assert result is original
    assert len(session.calls) == 1


def test_blob_resources_and_resource_links_are_preserved_while_text_resource_is_tainted() -> None:
    original = types.CallToolResult(
        content=[
            types.EmbeddedResource(
                resource=types.TextResourceContents(uri="memo://doc", text="hello")
            ),
            types.EmbeddedResource(
                resource=types.BlobResourceContents(uri="memo://blob", blob="ZmFrZQ==")
            ),
            types.ResourceLink(name="guide", uri="memo://guide"),
        ]
    )
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    result = asyncio.run(client.call_tool("read_file", {"path": "guide.md"}))

    assert isinstance(result.content[0].resource.text, TaintedString)
    assert result.content[1] is original.content[1]
    assert result.content[2] is original.content[2]


@pytest.mark.parametrize(
    ("structured_factory", "assert_unmodified"),
    [
        (_too_deep_structured_content, _assert_deep_content_unmodified),
        (_too_many_nodes_structured_content, _assert_node_budget_content_unmodified),
        (_cyclic_structured_content, _assert_cyclic_content_unmodified),
        (_unsupported_structured_content, _assert_unsupported_content_unmodified),
    ],
    ids=["max-depth", "max-nodes", "cycle", "unsupported"],
)
def test_post_execution_provenance_failures_raise_dedicated_error_exactly_once(
    structured_factory: Any,
    assert_unmodified: Any,
) -> None:
    original = types.CallToolResult(
        content=[types.TextContent(text="body")],
        structuredContent=structured_factory(_FAKE_SECRET),
    )
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    with pytest.raises(PostExecutionProvenanceError) as exc_info:
        asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    exc = exc_info.value
    assert len(session.calls) == 1
    assert exc.remote_executed is True
    assert exc.retry_safe is False
    assert exc.tool_id == _CANONICAL_TOOL
    assert "may already have executed" in str(exc)
    assert "must not blindly retry" in str(exc)
    assert _FAKE_SECRET not in str(exc)
    assert original.content[0].text == "body"
    assert not isinstance(original.content[0].text, TaintedString)
    assert_unmodified(original.structured_content)


def test_post_execution_provenance_failure_records_distinct_audit_state_with_same_event_id() -> None:
    sink = _MemoryAuditSink()
    original = types.CallToolResult(
        content=[types.TextContent(text="body")],
        structuredContent=_too_many_nodes_structured_content(_FAKE_SECRET),
    )
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(audit_sink=sink), server_name="filesystem")

    with pytest.raises(PostExecutionProvenanceError):
        asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    assert len(session.calls) == 1
    assert _states(sink) == ["allowed", "post_execution_provenance_failed"]
    assert len({event.event_id for event in sink.events}) == 1
    assert "execution_failed" not in _states(sink)


def test_post_execution_provenance_error_clears_sensitive_exception_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = types.CallToolResult(
        content=[types.TextContent(text="body")],
        structuredContent={"title": "Guide"},
    )
    session = _FakeSession(original)
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    def _raise_sensitive_provenance_error(*args: Any, **kwargs: Any) -> Any:
        raise ValueError(_SUPER_SECRET_MARKER)

    monkeypatch.setattr(taintgate_mcp, "_taint_result", _raise_sensitive_provenance_error)

    result: object | None = None
    with pytest.raises(PostExecutionProvenanceError) as exc_info:
        result = asyncio.run(client.call_tool("read_file", {"path": "README.md"}))

    exc = exc_info.value
    assert result is None
    assert len(session.calls) == 1
    assert exc.remote_executed is True
    assert exc.retry_safe is False
    assert exc.tool_id == _CANONICAL_TOOL
    assert _SUPER_SECRET_MARKER not in str(exc)
    assert _SUPER_SECRET_MARKER not in repr(exc)
    assert exc.__context__ is None
    assert exc.__cause__ is None
    assert original.content[0].text == "body"
    assert not isinstance(original.content[0].text, TaintedString)


def test_unsafe_server_name_is_rejected() -> None:
    session = _FakeSession(types.CallToolResult(content=[]))

    with pytest.raises(ValueError, match="server_name"):
        TaintGateMCPClient(session, Guard(), server_name="https://demo.example?token=abc")


def test_unsafe_tool_name_is_rejected_without_leaking_raw_value() -> None:
    session = _FakeSession(types.CallToolResult(content=[]))
    client = TaintGateMCPClient(session, Guard(), server_name="filesystem")

    with pytest.raises(ValueError) as exc_info:
        asyncio.run(client.call_tool(f"read_file?{_FAKE_SECRET}", None))

    assert _FAKE_SECRET not in str(exc_info.value)
    assert session.calls == []
