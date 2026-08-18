from .exceptions import ApprovalRequired, BlockedAction, TaintGateError
from .guard import Guard
from .models import Action, CallContext, Decision, Finding, TaintedValue, Trust
from .policy import Policy


def untrusted(value, *, origin: str = "unknown") -> TaintedValue:
    return TaintedValue(value=value, trust=Trust.UNTRUSTED, origin=origin)


def trusted(value, *, origin: str = "application") -> TaintedValue:
    return TaintedValue(value=value, trust=Trust.TRUSTED, origin=origin)


def user_value(value, *, origin: str = "user") -> TaintedValue:
    return TaintedValue(value=value, trust=Trust.USER, origin=origin)


__all__ = [
    "Action",
    "ApprovalRequired",
    "BlockedAction",
    "CallContext",
    "Decision",
    "Finding",
    "Guard",
    "Policy",
    "TaintGateError",
    "TaintedValue",
    "Trust",
    "trusted",
    "untrusted",
    "user_value",
]
