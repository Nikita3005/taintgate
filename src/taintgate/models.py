from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class Trust(str, Enum):
    USER = "user"
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class TaintedValue:
    value: Any
    trust: Trust = Trust.UNTRUSTED
    origin: str = "unknown"


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
