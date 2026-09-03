#!/usr/bin/env python3
from __future__ import annotations

import json
import runpy
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AGENT = ROOT / "clive.toml"
HOOK = ROOT / "clive_guard.py"


def check_agent() -> None:
    with AGENT.open("rb") as f:
        data = tomllib.load(f)

    assert data["name"] == "clive"
    assert data["model"] == "gpt-daybreak-blue-latest"
    assert data["model_reasoning_effort"] == "high"
    assert data["sandbox_mode"] == "read-only"
    assert data["approval_policy"] == "never"
    assert data["web_search"] == "disabled"
    assert "source-only security evaluator" in data["description"]

    instructions = data["developer_instructions"]

    required = (
        "Your governing mission is security.",
        "Do not treat Vulnerability, Logic, Integrity, Runtime, and Configuration as five equal missions.",
        "# Security-first finding admission",
        "A Logic, Integrity, Runtime, or Configuration defect is reportable by default only when CLIVE can establish",
        "Pure correctness, maintainability, performance, reliability, ergonomics, style, or developer-misuse issues",
        "## Explicit broader-correctness mode",
        "## 1. Exploitable vulnerabilities",
        "## 2. Security-control and trust-boundary integrity",
        "## 3. Security-relevant logic flaws",
        "## 4. Security-relevant runtime defects",
        "## 5. Security-relevant configuration and hardening",
        "Domains classify findings **after** they pass the security-relevance admission gate.",
        "A non-Vulnerability finding must satisfy the security-relevance admission gate before it is emitted.",
        "what concrete security property, trust boundary, attacker advantage",
        "External taxonomies are optional annotations, never audit boundaries.",
        "Finding Composition",
        "CLIVE-<SEQ>",
    )
    for phrase in required:
        assert phrase in instructions, phrase

    assert "## 2. Runtime bugs" not in instructions
    assert "## 3. Logic errors" not in instructions

    hook_cfg = data["hooks"]["PreToolUse"][0]["hooks"][0]
    assert "clive_guard.py" in hook_cfg["command"]
    assert "clive_guard.py" in hook_cfg["command_windows"]


def evaluator():
    return runpy.run_path(str(HOOK))["evaluate_event"]


def allow(evaluate, command: str) -> None:
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    assert evaluate(event) is None, command


def deny(evaluate, tool: str, tool_input: dict) -> None:
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
    }
    result = evaluate(event)
    assert result is not None, tool
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny", result


def check_hook() -> None:
    evaluate = evaluator()

    allow(evaluate, 'rg -n "CLIVE" README.md')
    allow(evaluate, 'cat README.md')
    allow(evaluate, 'git --no-pager rev-parse --show-toplevel')

    for command in (
        "pytest",
        "python app.py",
        "npm test",
        "curl https://example.com",
        "./script.sh",
        "cat README.md | sh",
        "rg --pre cat pattern .",
        "git status",
        "git --no-pager diff -- README.md",
    ):
        deny(evaluate, "Bash", {"command": command})

    deny(evaluate, "apply_patch", {"command": "*** Begin Patch"})
    deny(evaluate, "Agent", {"agent_type": "worker"})
    deny(evaluate, "mcp__filesystem__read_file", {"path": "README.md"})


def check_docs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "**security-first**" in readme
    assert "## Security-first doctrine" in readme
    assert "## Optional broader-correctness mode" in readme
    assert "## [1.1.0]" in changelog


def main() -> int:
    check_agent()
    check_hook()
    check_docs()
    print("PASS: CLIVE v1.1.0 security-first directives, native-domain model, and static-only guard validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
