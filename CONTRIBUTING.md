# Contributing

Thanks for helping improve TaintGate.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

Prefer small PRs with tests. New detection rules should include both a malicious/unsafe fixture and a benign near-match to control false positives.
