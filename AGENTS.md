# TaintGate Engineering Guide

TaintGate is a provenance-aware runtime security layer for AI agents.

## Core principle

Untrusted text is data, not authority.

Values originating from webpages, email, retrieval systems, MCP servers,
external tools, or other untrusted sources must not silently gain authority
to execute privileged side effects.

## Engineering priorities

1. Security correctness
2. Simple developer API
3. Framework independence
4. Testability
5. Minimal dependencies
6. Explainable security decisions

## Python

- Python >= 3.10
- Use type hints
- Prefer standard library functionality
- Avoid unnecessary dependencies
- Keep public APIs small
- Preserve wrapped function behavior

## Security

Never silently fail open.

Every security decision must have structured, explainable reasons.

Never log raw secret values.

Treat externally sourced text as potentially hostile.

## Tests

Every feature must include tests.

Before completing work run:

pytest
ruff check .

Never weaken security behavior merely to make a test pass.

## Architecture

Core security logic must remain framework independent.

OpenAI Agents, LangGraph, CrewAI, MCP and other integrations belong
in dedicated adapters.

## Git

Keep changes focused.

Do not modify unrelated files.

Avoid broad refactors while implementing small features.