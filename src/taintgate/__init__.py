from .audit import AuditSink, JsonlAuditLog, JsonlAuditSink
from .exceptions import (
    ApprovalError,
    ApprovalRequired,
    AuditSinkError,
    BlockedAction,
    InvalidApprovalResult,
    PolicyConfigurationError,
    PostExecutionProvenanceError,
    TaintGateError,
)
from .guard import Guard
from .models import (
    Action,
    ApprovalAction,
    ApprovalRequest,
    ApprovalResult,
    ArgumentSummary,
    AuditEvent,
    CallAuthorization,
    CallContext,
    Decision,
    ExecutionState,
    Finding,
    ProvenanceSummary,
    TaintedString,
    TaintedValue,
    ToolMetadata,
    Trust,
)
from .policy import Policy, ToolPolicy


def untrusted(value, *, origin: str = "unknown") -> TaintedValue:
    return TaintedValue(value=value, trust=Trust.UNTRUSTED, origin=origin)


def trusted(value, *, origin: str = "application") -> TaintedValue:
    return TaintedValue(value=value, trust=Trust.TRUSTED, origin=origin)


def user_value(value, *, origin: str = "user") -> TaintedValue:
    return TaintedValue(value=value, trust=Trust.USER, origin=origin)


__all__ = [
    "Action",
    "ApprovalAction",
    "ApprovalError",
    "ApprovalRequest",
    "ApprovalRequired",
    "ApprovalResult",
    "ArgumentSummary",
    "AuditEvent",
    "AuditSink",
    "AuditSinkError",
    "BlockedAction",
    "CallAuthorization",
    "CallContext",
    "Decision",
    "ExecutionState",
    "Finding",
    "Guard",
    "InvalidApprovalResult",
    "JsonlAuditLog",
    "JsonlAuditSink",
    "Policy",
    "PolicyConfigurationError",
    "PostExecutionProvenanceError",
    "ProvenanceSummary",
    "TaintGateError",
    "TaintedString",
    "TaintedValue",
    "ToolMetadata",
    "ToolPolicy",
    "Trust",
    "trusted",
    "untrusted",
    "user_value",
]
