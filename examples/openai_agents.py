from __future__ import annotations

from agents import function_tool

from taintgate import Guard, ToolMetadata
from taintgate.openai_agents import TaintGateToolGuardrail

guard = Guard()
tg = TaintGateToolGuardrail(
    guard,
    metadata={
        "send_email": ToolMetadata(
            side_effecting=True,
            external_destination=True,
        )
    },
)


@function_tool(tool_input_guardrails=[tg.for_tool("send_email")])
def send_email(to: str, body: str) -> str:
    return "sent"


if __name__ == "__main__":
    print(
        "This example shows how to attach TaintGate to an OpenAI Agents "
        "custom function tool. No network call is required to understand the API."
    )
