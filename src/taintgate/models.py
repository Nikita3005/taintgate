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

    @property
    def allowed(self) -> bool:
        return self.action == Action.ALLOW


@dataclass(frozen=True)
class CallContext:
    user_intent: str | None = None
    actor: str | None = None
    session_id: str | None = None
