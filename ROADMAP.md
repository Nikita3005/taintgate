# Roadmap

## v0.1 — enforcement core

- [x] Tool-call interception
- [x] Provenance tags
- [x] Risk findings and score
- [x] Allow / review / block
- [x] Human approval callback
- [x] JSONL audit log
- [x] Secret, destructive-action, sensitive-path, and injection signals
- [x] CLI demo
- [x] Tests

## v0.2 — provenance propagation

- [ ] Decorator for automatically tainting tool outputs
- [ ] Nested provenance propagation helpers
- [ ] Source categories for browser, RAG, email, MCP, filesystem, API
- [ ] Output sanitization hooks
- [ ] Policy config file

## v0.3 — framework adapters

- [ ] OpenAI Agents SDK tool guardrail adapter
- [ ] LangChain / LangGraph middleware adapter
- [ ] Generic MCP proxy adapter
- [ ] Async tool support

## v0.4 — developer-grade security testing

- [ ] `taintgate attack` scenario runner
- [ ] Built-in attack fixtures
- [ ] False-positive benchmark fixtures
- [ ] SARIF / JSON output for CI

## v1.0 — stable API

- [ ] Stable policy schema
- [ ] Versioned rule IDs
- [ ] Plugin interface for custom detectors
- [ ] Performance benchmark
- [ ] Security review and hardening
