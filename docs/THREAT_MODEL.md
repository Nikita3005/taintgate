# Threat Model

TaintGate assumes an AI agent can be influenced by untrusted content and may propose tool calls with real-world side effects.

## Assets

- Credentials and API keys
- Local files and private configuration
- Databases and business records
- External communication channels
- Money-moving or irreversible actions
- Audit history

## Trust boundaries

TaintGate distinguishes three provenance classes:

- `user`: data supplied directly by the authorized user
- `trusted`: data supplied by application-controlled state
- `untrusted`: web pages, retrieved documents, third-party tool outputs, external messages, or other content that must not silently gain authority

## Initial attack classes

- Indirect prompt injection in retrieved/web content
- Secret leakage into side-effecting tools
- High-confidence PII leakage into external destinations
- Destructive shell and SQL actions
- Reads of sensitive paths
- Untrusted data flowing into network/write/execute sinks
- Sensitive content flowing into side-effecting external tools
- Policy-denied tools

## Non-goals for v0.1

- OS/container sandboxing
- Network-level isolation
- Perfect semantic prompt-injection detection
- Comprehensive PII classification
- Authentication or identity management
- Replacing least-privilege credentials
- Guaranteeing safety against a malicious host application that bypasses the guard

## Detector notes

- Prompt-injection detection is heuristic and deterministic, not semantic proof.
- Secret and PII findings must not expose raw matched values in messages.
- Bounded scans may return `runtime.scan_limit` when traversal stops early.

## Security invariant

A protected tool must not execute when the decision is `block`, and a `review` decision must not execute unless an approval handler explicitly approves it.
