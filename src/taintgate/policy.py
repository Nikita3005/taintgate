from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from .detectors import walk
from .exceptions import PolicyConfigurationError
from .models import Action, Decision, Finding, ToolMetadata, Trust

_TOP_LEVEL_KEYS = frozenset({"version", "default", "review_at", "block_at", "tools"})
_TOOL_KEYS = frozenset(
    {
        "default",
        "side_effecting",
        "external_destination",
        "destructive",
        "on_untrusted_side_effect",
        "on_untrusted_external",
        "on_destructive",
    }
)
_ACTION_SEVERITY = {
    Action.ALLOW: 0,
    Action.REVIEW: 1,
    Action.BLOCK: 2,
}


@dataclass(frozen=True)
class ToolPolicy:
    default: Action | str | None = None
    side_effecting: bool = False
    external_destination: bool = False
    destructive: bool = False
    on_untrusted_side_effect: Action | str | None = None
    on_untrusted_external: Action | str | None = None
    on_destructive: Action | str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "default", _normalize_optional_action(self.default, "default"))
        object.__setattr__(
            self,
            "on_untrusted_side_effect",
            _normalize_optional_action(
                self.on_untrusted_side_effect,
                "on_untrusted_side_effect",
            ),
        )
        object.__setattr__(
            self,
            "on_untrusted_external",
            _normalize_optional_action(
                self.on_untrusted_external,
                "on_untrusted_external",
            ),
        )
        object.__setattr__(
            self,
            "on_destructive",
            _normalize_optional_action(self.on_destructive, "on_destructive"),
        )
        for name in ("side_effecting", "external_destination", "destructive"):
            value = getattr(self, name)
            if not isinstance(value, bool):
                raise PolicyConfigurationError(f"{name} must be a bool")

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            side_effecting=self.side_effecting,
            external_destination=self.external_destination,
            destructive=self.destructive,
        )


@dataclass(frozen=True)
class Policy:
    block_at: int = 90
    review_at: int = 60
    denied_tools: frozenset[str] | set[str] | list[str] | tuple[str, ...] = field(default_factory=frozenset)
    review_tools: frozenset[str] | set[str] | list[str] | tuple[str, ...] = field(default_factory=frozenset)
    default: Action | str = Action.ALLOW
    tools: Mapping[str, ToolPolicy] | dict[str, ToolPolicy] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "block_at", _normalize_int(self.block_at, "block_at"))
        object.__setattr__(self, "review_at", _normalize_int(self.review_at, "review_at"))
        if not 0 <= self.review_at <= self.block_at <= 100:
            raise PolicyConfigurationError("thresholds must satisfy 0 <= review_at <= block_at <= 100")

        object.__setattr__(self, "default", _normalize_action(self.default, "default"))
        object.__setattr__(self, "denied_tools", _normalize_tool_names(self.denied_tools, "denied_tools"))
        object.__setattr__(self, "review_tools", _normalize_tool_names(self.review_tools, "review_tools"))
        object.__setattr__(self, "tools", MappingProxyType(_normalize_tools(self.tools)))

    @classmethod
    def from_toml(cls, path: str | Path) -> Policy:
        policy_path = Path(path)
        try:
            raw = tomllib.loads(policy_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise PolicyConfigurationError(f"Policy file not found: {policy_path}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise PolicyConfigurationError(f"Malformed TOML policy file {policy_path}: {exc}") from exc
        return cls._from_loaded_mapping(raw, source=str(policy_path))

    @classmethod
    def _from_loaded_mapping(cls, raw: Any, *, source: str) -> Policy:
        if not isinstance(raw, dict):
            raise PolicyConfigurationError(f"Policy file {source} must decode to a TOML table")

        _ensure_known_keys(raw, _TOP_LEVEL_KEYS, f"policy file {source}")
        if "version" not in raw:
            raise PolicyConfigurationError(f"Policy file {source} is missing required key 'version'")
        if "default" not in raw:
            raise PolicyConfigurationError(f"Policy file {source} is missing required key 'default'")

        version = _normalize_int(raw["version"], "version")
        if version != 1:
            raise PolicyConfigurationError(f"Unsupported policy version {version}; only version=1 is supported")

        tools = raw.get("tools", {})
        if not isinstance(tools, dict):
            raise PolicyConfigurationError("tools must be a TOML table")

        return cls(
            block_at=raw.get("block_at", 90),
            review_at=raw.get("review_at", 60),
            default=raw["default"],
            tools={tool_name: _tool_policy_from_mapping(tool_name, value) for tool_name, value in tools.items()},
        )

    def evaluate(
        self,
        tool: str,
        *,
        args: Mapping[str, Any],
        findings: Sequence[Finding],
        metadata: ToolMetadata | None = None,
    ) -> Decision:
        if not isinstance(tool, str) or not tool:
            raise PolicyConfigurationError("tool name must be a non-empty string")
        if metadata is not None and not isinstance(metadata, ToolMetadata):
            raise PolicyConfigurationError("metadata must be a ToolMetadata instance")

        tool_policy = self.tools.get(tool)
        effective_metadata = self._effective_metadata(tool_policy, metadata)
        observed = _observed_state(args, findings, effective_metadata)

        reasons = list(findings)
        matched_policies: list[str] = []
        candidates: list[Action] = []

        self._add_default_policy(tool, tool_policy, reasons, matched_policies, candidates)
        self._add_legacy_tool_policies(tool, reasons, matched_policies, candidates)
        self._add_tool_rules(tool, tool_policy, observed, reasons, matched_policies, candidates)

        detector_score = self._combine(findings)
        self._add_threshold_policy(detector_score, reasons, matched_policies, candidates)

        final_action = _maximum_action(candidates)
        final_score = self._combine(reasons)
        return Decision(
            action=final_action,
            score=final_score,
            tool=tool,
            findings=tuple(reasons),
            matched_policies=tuple(_dedupe(matched_policies)),
        )

    def _effective_metadata(
        self,
        tool_policy: ToolPolicy | None,
        runtime_metadata: ToolMetadata | None,
    ) -> ToolMetadata:
        configured = tool_policy.metadata if tool_policy is not None else ToolMetadata()
        return configured.merge(runtime_metadata)

    def _add_default_policy(
        self,
        tool: str,
        tool_policy: ToolPolicy | None,
        reasons: list[Finding],
        matched_policies: list[str],
        candidates: list[Action],
    ) -> None:
        if tool_policy is not None and tool_policy.default is not None:
            action = tool_policy.default
            rule_id = f"tools.{tool}.default"
            message = f"Tool policy default for {tool!r} is {action.value}"
        else:
            action = self.default
            rule_id = "policy.default"
            message = f"Global default policy for {tool!r} is {action.value}"
        self._add_policy_match(
            action=action,
            rule_id=rule_id,
            message=message,
            score=self._policy_score(action),
            reasons=reasons,
            matched_policies=matched_policies,
            candidates=candidates,
        )

    def _add_legacy_tool_policies(
        self,
        tool: str,
        reasons: list[Finding],
        matched_policies: list[str],
        candidates: list[Action],
    ) -> None:
        if tool in self.review_tools:
            self._add_policy_match(
                action=Action.REVIEW,
                rule_id="legacy.review_tools",
                message=f"Tool {tool!r} requires review via legacy review_tools policy",
                score=self._policy_score(Action.REVIEW),
                reasons=reasons,
                matched_policies=matched_policies,
                candidates=candidates,
            )
        if tool in self.denied_tools:
            self._add_policy_match(
                action=Action.BLOCK,
                rule_id="legacy.denied_tools",
                message=f"Tool {tool!r} is blocked via legacy denied_tools policy",
                score=self._policy_score(Action.BLOCK),
                reasons=reasons,
                matched_policies=matched_policies,
                candidates=candidates,
            )

    def _add_tool_rules(
        self,
        tool: str,
        tool_policy: ToolPolicy | None,
        observed: _ObservedState,
        reasons: list[Finding],
        matched_policies: list[str],
        candidates: list[Action],
    ) -> None:
        if tool_policy is None:
            return

        if observed.untrusted_side_effect and tool_policy.on_untrusted_side_effect is not None:
            action = tool_policy.on_untrusted_side_effect
            self._add_policy_match(
                action=action,
                rule_id=f"tools.{tool}.on_untrusted_side_effect",
                message=(
                    f"Tool policy for {tool!r} applies to untrusted input flowing into a "
                    f"side-effecting tool"
                ),
                score=self._policy_score(action),
                reasons=reasons,
                matched_policies=matched_policies,
                candidates=candidates,
            )

        if observed.untrusted_external and tool_policy.on_untrusted_external is not None:
            action = tool_policy.on_untrusted_external
            self._add_policy_match(
                action=action,
                rule_id=f"tools.{tool}.on_untrusted_external",
                message=(
                    f"Tool policy for {tool!r} applies to untrusted input flowing to an "
                    f"external destination"
                ),
                score=self._policy_score(action),
                reasons=reasons,
                matched_policies=matched_policies,
                candidates=candidates,
            )

        if observed.destructive and tool_policy.on_destructive is not None:
            action = tool_policy.on_destructive
            self._add_policy_match(
                action=action,
                rule_id=f"tools.{tool}.on_destructive",
                message=f"Tool policy for {tool!r} applies to destructive behavior",
                score=self._policy_score(action),
                reasons=reasons,
                matched_policies=matched_policies,
                candidates=candidates,
            )

    def _add_threshold_policy(
        self,
        detector_score: int,
        reasons: list[Finding],
        matched_policies: list[str],
        candidates: list[Action],
    ) -> None:
        if detector_score >= self.block_at:
            self._add_policy_match(
                action=Action.BLOCK,
                rule_id="threshold.block_at",
                message=f"Risk score {detector_score} meets block threshold {self.block_at}",
                score=0,
                reasons=reasons,
                matched_policies=matched_policies,
                candidates=candidates,
            )
            return
        if detector_score >= self.review_at:
            self._add_policy_match(
                action=Action.REVIEW,
                rule_id="threshold.review_at",
                message=f"Risk score {detector_score} meets review threshold {self.review_at}",
                score=0,
                reasons=reasons,
                matched_policies=matched_policies,
                candidates=candidates,
            )

    def _add_policy_match(
        self,
        *,
        action: Action,
        rule_id: str,
        message: str,
        score: int,
        reasons: list[Finding],
        matched_policies: list[str],
        candidates: list[Action],
    ) -> None:
        if not isinstance(action, Action):
            raise PolicyConfigurationError(f"Unknown policy action {action!r}")
        reasons.append(Finding(rule_id=rule_id, message=message, score=score))
        matched_policies.append(rule_id)
        candidates.append(action)

    def _policy_score(self, action: Action) -> int:
        if action == Action.ALLOW:
            return 0
        if action == Action.REVIEW:
            return self.review_at
        if action == Action.BLOCK:
            return 100
        raise PolicyConfigurationError(f"Unknown policy action {action!r}")

    @staticmethod
    def _combine(findings: Sequence[Finding]) -> int:
        if not findings:
            return 0
        remaining = 1.0
        for finding in findings:
            score = max(0, min(100, finding.score))
            remaining *= 1.0 - (score / 100.0)
        return min(100, round((1.0 - remaining) * 100))


@dataclass(frozen=True)
class _ObservedState:
    has_untrusted_input: bool
    destructive: bool
    untrusted_side_effect: bool
    untrusted_external: bool


def _observed_state(
    args: Mapping[str, Any],
    findings: Sequence[Finding],
    metadata: ToolMetadata,
) -> _ObservedState:
    has_untrusted_input = any(trust == Trust.UNTRUSTED for _path, _value, trust, _origin, _source in walk(args))
    destructive = metadata.destructive or any(finding.rule_id == "action.destructive" for finding in findings)
    return _ObservedState(
        has_untrusted_input=has_untrusted_input,
        destructive=destructive,
        untrusted_side_effect=has_untrusted_input and metadata.side_effecting,
        untrusted_external=has_untrusted_input and metadata.external_destination,
    )


def _normalize_action(value: Action | str, field_name: str) -> Action:
    if isinstance(value, Action):
        return value
    if not isinstance(value, str):
        raise PolicyConfigurationError(f"{field_name} must be one of: allow, review, block")
    try:
        return Action(value)
    except ValueError as exc:
        raise PolicyConfigurationError(f"{field_name} must be one of: allow, review, block") from exc


def _normalize_optional_action(value: Action | str | None, field_name: str) -> Action | None:
    if value is None:
        return None
    return _normalize_action(value, field_name)


def _normalize_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyConfigurationError(f"{field_name} must be an integer")
    return value


def _normalize_tool_names(
    value: frozenset[str] | set[str] | list[str] | tuple[str, ...],
    field_name: str,
) -> frozenset[str]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise PolicyConfigurationError(f"{field_name} must be an iterable of tool names")

    names: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise PolicyConfigurationError(f"{field_name} entries must be non-empty strings")
        names.append(item)
    return frozenset(names)


def _normalize_tools(value: Mapping[str, ToolPolicy] | dict[str, ToolPolicy]) -> dict[str, ToolPolicy]:
    if not isinstance(value, Mapping):
        raise PolicyConfigurationError("tools must be a mapping of tool names to ToolPolicy")

    tools: dict[str, ToolPolicy] = {}
    for tool_name, tool_policy in value.items():
        if not isinstance(tool_name, str) or not tool_name:
            raise PolicyConfigurationError("tool names must be non-empty strings")
        if isinstance(tool_policy, ToolPolicy):
            tools[tool_name] = tool_policy
            continue
        if isinstance(tool_policy, Mapping):
            tools[tool_name] = _tool_policy_from_mapping(tool_name, dict(tool_policy))
            continue
        raise PolicyConfigurationError(f"tools[{tool_name!r}] must be a ToolPolicy or mapping")
    return tools


def _tool_policy_from_mapping(tool_name: str, raw: Any) -> ToolPolicy:
    if not isinstance(tool_name, str) or not tool_name:
        raise PolicyConfigurationError("tool names must be non-empty strings")
    if not isinstance(raw, dict):
        raise PolicyConfigurationError(f"tools.{tool_name} must be a TOML table")

    _ensure_known_keys(raw, _TOOL_KEYS, f"tools.{tool_name}")
    return ToolPolicy(
        default=raw.get("default"),
        side_effecting=_require_bool(raw, "side_effecting", tool_name, default=False),
        external_destination=_require_bool(raw, "external_destination", tool_name, default=False),
        destructive=_require_bool(raw, "destructive", tool_name, default=False),
        on_untrusted_side_effect=raw.get("on_untrusted_side_effect"),
        on_untrusted_external=raw.get("on_untrusted_external"),
        on_destructive=raw.get("on_destructive"),
    )


def _require_bool(raw: dict[str, Any], key: str, tool_name: str, *, default: bool) -> bool:
    if key not in raw:
        return default
    value = raw[key]
    if not isinstance(value, bool):
        raise PolicyConfigurationError(f"tools.{tool_name}.{key} must be a bool")
    return value


def _ensure_known_keys(raw: Mapping[str, Any], allowed: frozenset[str], context: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PolicyConfigurationError(f"Unknown keys in {context}: {', '.join(unknown)}")


def _maximum_action(candidates: Sequence[Action]) -> Action:
    if not candidates:
        raise PolicyConfigurationError("No policy candidates were produced")
    return max(candidates, key=_ACTION_SEVERITY.__getitem__)


def _dedupe(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
