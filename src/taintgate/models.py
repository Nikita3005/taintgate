from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from typing import Self
else:
    Self = Any


class Action(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class ApprovalAction(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class ExecutionState(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_FAILED = "approval_failed"
    EXECUTED = "executed"
    EXECUTION_FAILED = "execution_failed"


class Trust(str, Enum):
    USER = "user"
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class TaintedString(str):
    """String subtype carrying provenance metadata.

    Normal string operations may produce a plain ``str`` and drop this metadata.
    """

    __slots__ = ("origin", "source_type", "trust")

    trust: Trust
    origin: str
    source_type: str

    def __new__(
        cls,
        value: str,
        *,
        trust: Trust = Trust.UNTRUSTED,
        origin: str = "unknown",
        source_type: str = "unknown",
    ) -> Self:
        instance = super().__new__(cls, value)
        object.__setattr__(instance, "trust", trust)
        object.__setattr__(instance, "origin", origin)
        object.__setattr__(instance, "source_type", source_type)
        return instance

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("TaintedString metadata is read-only")


@dataclass(frozen=True)
class TaintedValue:
    value: Any
    trust: Trust = Trust.UNTRUSTED
    origin: str = "unknown"
    source_type: str = "unknown"


@dataclass(frozen=True)
class ToolMetadata:
    side_effecting: bool = False
    external_destination: bool = False
    destructive: bool = False

    def __post_init__(self) -> None:
        for name in ("side_effecting", "external_destination", "destructive"):
            value = getattr(self, name)
            if not isinstance(value, bool):
                raise TypeError(f"{name} must be a bool")

    def merge(self, other: ToolMetadata | None) -> ToolMetadata:
        if other is None:
            return self
        return ToolMetadata(
            side_effecting=self.side_effecting or other.side_effecting,
            external_destination=self.external_destination or other.external_destination,
            destructive=self.destructive or other.destructive,
        )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    message: str
    score: int
    path: str | None = None


@dataclass(frozen=True)
class Decision:
    action: Action
    score: int
    tool: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    matched_policies: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.action == Action.ALLOW

    @property
    def risk_score(self) -> int:
        return self.score

    @property
    def reasons(self) -> tuple[Finding, ...]:
        return self.findings


@dataclass(frozen=True)
class CallContext:
    user_intent: str | None = None
    actor: str | None = None
    session_id: str | None = None


@dataclass(frozen=True)
class ArgumentSummary:
    path: str
    python_type: str
    string_length: int | None = None
    collection_size: int | None = None
    trust: Trust | None = None
    source_type: str | None = None
    origin: str | None = None
    truncated: bool = False


@dataclass(frozen=True)
class ProvenanceSummary:
    path: str
    trust: Trust
    source_type: str | None = None
    origin: str | None = None


@dataclass(frozen=True)
class ApprovalResult:
    action: ApprovalAction
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, ApprovalAction):
            raise TypeError("action must be an ApprovalAction")
        if self.reason is not None and not isinstance(self.reason, str):
            raise TypeError("reason must be a string or None")


@dataclass(frozen=True)
class ApprovalRequest:
    event_id: str
    tool: str
    decision: Decision
    argument_summary: tuple[ArgumentSummary, ...] = field(default_factory=tuple)
    provenance: tuple[ProvenanceSummary, ...] = field(default_factory=tuple)
    metadata: ToolMetadata = field(default_factory=ToolMetadata)
    context: CallContext | None = None

    @property
    def action(self) -> Action:
        return self.decision.action

    @property
    def score(self) -> int:
        return self.decision.score

    @property
    def risk_score(self) -> int:
        return self.decision.risk_score

    @property
    def findings(self) -> tuple[Finding, ...]:
        return self.decision.findings

    @property
    def matched_policies(self) -> tuple[str, ...]:
        return self.decision.matched_policies


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    event_id: str
    tool: str
    policy_action: Action
    risk_score: int
    execution_state: ExecutionState
    matched_policies: tuple[str, ...] = field(default_factory=tuple)
    finding_ids: tuple[str, ...] = field(default_factory=tuple)
    provenance: tuple[ProvenanceSummary, ...] = field(default_factory=tuple)
    argument_summary: tuple[ArgumentSummary, ...] = field(default_factory=tuple)
    tool_metadata: ToolMetadata = field(default_factory=ToolMetadata)
    approval_action: ApprovalAction | None = None
    error_type: str | None = None
    schema_version: int = 1
