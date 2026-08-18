from __future__ import annotations

import json
import os
import socket
import subprocess

from taintgate import Action, ApprovalRequired, BlockedAction, Guard, cli
from taintgate.attack import (
    _FAKE_AWS_ACCESS_KEY,
    _FAKE_OPENAI_KEY,
    _FAKE_PHONE,
    _FAKE_POWERSHELL_COMMAND,
    _FAKE_PROMPT_INJECTION_PAGE,
    _FAKE_SHELL_COMMAND,
    _FAKE_SQL_DELETE,
    _FAKE_SQL_DROP,
    AttackResult,
    _build_demo_policy,
    list_attack_scenarios,
    run_attack_suite,
)


def test_attack_scenarios_have_stable_order_and_ids() -> None:
    assert [scenario.scenario_id for scenario in list_attack_scenarios()] == [
        "safe_docs_search",
        "indirect_prompt_injection_web",
        "openai_key_exfiltration",
        "aws_credential_exfiltration",
        "sensitive_ssh_path_access",
        "destructive_shell_rm_rf",
        "destructive_powershell_remove_item",
        "destructive_sql_drop",
        "dangerous_delete_without_where",
        "benign_sql_select",
        "pii_external_flow",
        "scan_limit_reached",
    ]


def test_attack_suite_matches_expected_outcomes_and_execution_flags() -> None:
    results = {result.scenario_id: result for result in run_attack_suite()}

    assert all(result.passed for result in results.values())
    assert results["safe_docs_search"].observed_action == Action.ALLOW
    assert results["safe_docs_search"].executed is True
    assert results["indirect_prompt_injection_web"].observed_action == Action.REVIEW
    assert results["indirect_prompt_injection_web"].executed is False
    assert "input.prompt_injection" in results["indirect_prompt_injection_web"].finding_ids
    assert "flow.untrusted_to_side_effect" in results["indirect_prompt_injection_web"].finding_ids
    assert results["benign_sql_select"].observed_action == Action.ALLOW
    assert results["benign_sql_select"].executed is True

    for scenario_id in (
        "openai_key_exfiltration",
        "aws_credential_exfiltration",
        "sensitive_ssh_path_access",
        "destructive_shell_rm_rf",
        "destructive_powershell_remove_item",
        "destructive_sql_drop",
        "dangerous_delete_without_where",
        "pii_external_flow",
        "scan_limit_reached",
    ):
        assert results[scenario_id].executed is False


def test_attack_suite_uses_structured_decisions_from_exceptions(
    monkeypatch,
) -> None:
    def _fail_on_stringify(self) -> str:
        raise AssertionError("attack harness should not stringify security exceptions")

    monkeypatch.setattr(BlockedAction, "__str__", _fail_on_stringify, raising=False)
    monkeypatch.setattr(ApprovalRequired, "__str__", _fail_on_stringify, raising=False)

    assert all(result.passed for result in run_attack_suite())


def test_attack_suite_never_calls_real_side_effect_apis(monkeypatch) -> None:
    def _unexpected(*_args, **_kwargs):
        raise AssertionError("attack simulator attempted a real side effect")

    monkeypatch.setattr(os, "system", _unexpected)
    monkeypatch.setattr(subprocess, "run", _unexpected)
    monkeypatch.setattr(subprocess, "Popen", _unexpected)
    monkeypatch.setattr(socket, "create_connection", _unexpected)
    monkeypatch.setattr(socket, "socket", _unexpected)

    assert all(result.passed for result in run_attack_suite())


def test_demo_policy_does_not_block_benign_versions_of_the_same_tool() -> None:
    guard = Guard(policy=_build_demo_policy())

    shell_decision = guard.check("execute_shell", {"command": "echo documentation"})
    sql_decision = guard.check("run_query", {"sql": "SELECT * FROM docs"})

    assert shell_decision.action == Action.REVIEW
    assert sql_decision.action == Action.ALLOW


def test_attack_suite_is_deterministic_across_repeated_runs() -> None:
    first = [result.to_dict() for result in run_attack_suite()]
    second = [result.to_dict() for result in run_attack_suite()]

    assert first == second


def test_attack_cli_returns_zero_and_sanitized_text_output(capsys) -> None:
    exit_code = cli.main(["attack"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "TaintGate Attack Suite" in output
    assert "12 / 12 expected protections passed" in output
    assert "Security demo score: 100%" in output
    assert "input.prompt_injection" in output

    for forbidden in (
        _FAKE_OPENAI_KEY,
        _FAKE_AWS_ACCESS_KEY,
        _FAKE_PHONE,
        _FAKE_PROMPT_INJECTION_PAGE,
        _FAKE_SHELL_COMMAND,
        _FAKE_POWERSHELL_COMMAND,
        _FAKE_SQL_DROP,
        _FAKE_SQL_DELETE,
    ):
        assert forbidden not in output


def test_attack_cli_json_output_is_valid_and_sanitized(capsys) -> None:
    exit_code = cli.main(["attack", "--json"])
    output = capsys.readouterr().out
    payload = json.loads(output)

    assert exit_code == 0
    assert payload["suite"] == "taintgate_attack"
    assert payload["passed"] is True
    assert payload["score_percent"] == 100
    assert [result["scenario_id"] for result in payload["results"]] == [
        scenario.scenario_id for scenario in list_attack_scenarios()
    ]

    for forbidden in (
        _FAKE_OPENAI_KEY,
        _FAKE_AWS_ACCESS_KEY,
        _FAKE_PHONE,
        _FAKE_PROMPT_INJECTION_PAGE,
        _FAKE_SHELL_COMMAND,
        _FAKE_POWERSHELL_COMMAND,
        _FAKE_SQL_DROP,
        _FAKE_SQL_DELETE,
    ):
        assert forbidden not in output


def test_attack_cli_returns_nonzero_on_mismatch(monkeypatch) -> None:
    mismatch = (
        AttackResult(
            scenario_id="safe_docs_search",
            title="Safe documentation search",
            expected_action=Action.ALLOW,
            observed_action=Action.BLOCK,
            risk_score=90,
            passed=False,
            finding_ids=("input.prompt_injection",),
            executed=False,
        ),
    )

    monkeypatch.setattr(cli, "run_attack_suite", lambda: mismatch)

    assert cli.main(["attack"]) == 1
