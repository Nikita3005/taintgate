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
