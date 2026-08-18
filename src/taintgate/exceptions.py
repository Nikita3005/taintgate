from __future__ import annotations

from .models import Decision


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
