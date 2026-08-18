from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

try:
    from mcp import ClientSession, types
except ImportError as exc:  # pragma: no cover - exercised in subprocess test
    raise ImportError(
        'taintgate.mcp requires the MCP SDK. Install it with: pip install "taintgate[mcp]"'
    ) from exc

from .guard import Guard
from .models import TaintedString, ToolMetadata, Trust

_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]+\Z")
_STRUCTURED_MAX_DEPTH = 8
_STRUCTURED_MAX_NODES = 512


@dataclass
class _StructuredState:
    visited_ids: set[int]
    nodes_seen: int = 0


class TaintGateMCPClient:
    """Guard-backed MCP tool caller.

    This adapter protects MCP tool calls routed through this wrapper only.
    """

    def __init__(
        self,
        session: ClientSession,
        guard: Guard,
        *,
        server_name: str,
        metadata: Mapping[str, ToolMetadata] | None = None,
    ) -> None:
        if not isinstance(guard, Guard):
            raise TypeError("guard must be a Guard")
        if not hasattr(session, "call_tool") or not callable(session.call_tool):
            raise TypeError("session must provide an async call_tool(name, arguments=...) method")

        self._session = session
        self._guard = guard
        self._server_name = _validate_server_name(server_name)
        self._metadata = _normalize_metadata(metadata)

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
    ) -> types.CallToolResult | types.InputRequiredResult | types.Result:
        tool_name = _validate_tool_name(name)
        canonical_tool = _canonical_mcp_identity(self._server_name, tool_name)
        call_arguments, guard_arguments = _normalize_arguments(arguments)

        await self._guard.authorize_async(
            canonical_tool,
            guard_arguments,
            metadata=self._metadata.get(tool_name),
        )

        result = await self._session.call_tool(
            tool_name,
            call_arguments,
            read_timeout_seconds,
            progress_callback,
            input_responses=input_responses,
            request_state=request_state,
            meta=meta,
            allow_input_required=allow_input_required,
            allow_claimed=allow_claimed,
        )
        return _taint_result(result, origin=canonical_tool)


def _normalize_metadata(metadata: Mapping[str, ToolMetadata] | None) -> dict[str, ToolMetadata]:
    normalized: dict[str, ToolMetadata] = {}
    for tool_name, tool_metadata in dict(metadata or {}).items():
        normalized[_validate_tool_name(tool_name)] = _validate_tool_metadata(tool_metadata)
    return normalized


def _validate_tool_metadata(value: ToolMetadata) -> ToolMetadata:
    if not isinstance(value, ToolMetadata):
        raise TypeError("metadata values must be ToolMetadata instances")
    return value


def _validate_server_name(server_name: str) -> str:
    if not isinstance(server_name, str) or not server_name or not _SAFE_IDENTIFIER.fullmatch(server_name):
        raise ValueError(
            "server_name must be non-empty and use only letters, digits, underscore, hyphen, and dot"
        )
    return server_name


def _validate_tool_name(tool_name: str) -> str:
    if not isinstance(tool_name, str) or not tool_name or not _SAFE_IDENTIFIER.fullmatch(tool_name):
        raise ValueError(
            "tool name must be non-empty and use only letters, digits, underscore, hyphen, and dot"
        )
    return tool_name


def _canonical_mcp_identity(server_name: str, tool_name: str) -> str:
    return f"mcp:{server_name}/{tool_name}"


def _normalize_arguments(
    arguments: Mapping[str, Any] | dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if arguments is None:
        return None, {}
    if not isinstance(arguments, Mapping):
        raise TypeError("tool arguments must be a mapping with string keys or None")

    normalized: dict[str, Any] = {}
    for key, value in arguments.items():
        if not isinstance(key, str):
            raise TypeError("tool arguments must be a mapping with string keys or None")
        normalized[key] = value
    return normalized, normalized.copy()


def _taint_result(
    result: types.CallToolResult | types.InputRequiredResult | types.Result,
    *,
    origin: str,
) -> types.CallToolResult | types.InputRequiredResult | types.Result:
    if isinstance(result, types.InputRequiredResult):
        return result
    if not isinstance(result, types.CallToolResult):
        return result

    content = [_taint_content_item(item, origin=origin) for item in result.content]
    structured_content = result.structured_content
    if structured_content is not None:
        structured_content = _taint_structured_content(structured_content, origin=origin)
    return result.model_copy(
        update={
            "content": content,
            "structured_content": structured_content,
        }
    )


def _taint_content_item(
    item: (
        types.TextContent
        | types.ImageContent
        | types.AudioContent
        | types.ResourceLink
        | types.EmbeddedResource
    ),
    *,
    origin: str,
) -> (
    types.TextContent
    | types.ImageContent
    | types.AudioContent
    | types.ResourceLink
    | types.EmbeddedResource
):
    if isinstance(item, types.TextContent):
        return item.model_copy(update={"text": _taint_string(item.text, origin=origin)})
    if isinstance(item, types.EmbeddedResource) and isinstance(item.resource, types.TextResourceContents):
        resource = item.resource.model_copy(update={"text": _taint_string(item.resource.text, origin=origin)})
        return item.model_copy(update={"resource": resource})
    return item


def _taint_structured_content(value: Any, *, origin: str) -> Any:
    state = _StructuredState(visited_ids=set())
    return _taint_structured_value(value, origin=origin, depth=0, state=state)


def _taint_structured_value(
    value: Any,
    *,
    origin: str,
    depth: int,
    state: _StructuredState,
) -> Any:
    if state.nodes_seen >= _STRUCTURED_MAX_NODES or depth > _STRUCTURED_MAX_DEPTH:
        raise RuntimeError("MCP structured_content exceeded provenance traversal limits")
    state.nodes_seen += 1

    if isinstance(value, TaintedString):
        return _taint_string(str(value), origin=origin)
    if isinstance(value, str):
        return _taint_string(value, origin=origin)
    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, list):
        _mark_visited(value, state)
        return [
            _taint_structured_value(item, origin=origin, depth=depth + 1, state=state)
            for item in value
        ]

    if isinstance(value, dict):
        _mark_visited(value, state)
        tainted: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("MCP structured_content object keys must be strings")
            tainted[key] = _taint_structured_value(item, origin=origin, depth=depth + 1, state=state)
        return tainted

    raise TypeError("MCP structured_content must be JSON-compatible")


def _mark_visited(value: object, state: _StructuredState) -> None:
    marker = id(value)
    if marker in state.visited_ids:
        raise RuntimeError("MCP structured_content contains a cycle")
    state.visited_ids.add(marker)


def _taint_string(value: str, *, origin: str) -> TaintedString:
    return TaintedString(
        str(value),
        trust=Trust.UNTRUSTED,
        source_type="mcp",
        origin=origin,
    )


__all__ = ["TaintGateMCPClient"]
