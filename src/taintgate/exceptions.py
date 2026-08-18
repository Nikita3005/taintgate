from __future__ import annotations

from .models import AuditEvent, Decision


class TaintGateError(RuntimeError):
    pass


class PolicyConfigurationError(TaintGateError):
    pass


class BlockedAction(TaintGateError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Blocked tool call {decision.tool!r} (risk={decision.score})")


class ApprovalRequired(TaintGateError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Approval required for {decision.tool!r} (risk={decision.score})")


class ApprovalError(TaintGateError):
    def __init__(self, message: str, *, decision: Decision):
        self.decision = decision
        super().__init__(message)


class InvalidApprovalResult(ApprovalError):
    def __init__(self, result: object, *, decision: Decision):
        self.result = result
        super().__init__(
            f"Approval handler returned invalid result of type {type(result).__name__}",
            decision=decision,
        )


class AuditSinkError(TaintGateError):
    def __init__(self, event: AuditEvent, cause: Exception):
        self.event = event
        self.cause = cause
        super().__init__(
            f"Audit sink failed while recording {event.execution_state.value} "
            f"for {event.tool!r} ({type(cause).__name__})"
        )
