#!/usr/bin/env python3
from __future__ import annotations

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
    assert data["description"].startswith("CLIVE — Code Logic, Integrity & Vulnerability Evaluator.")

    instructions = data["developer_instructions"]
    for phrase in (
        "You are CLIVE",
        "derive a provisional context",
        "Observed",
        "Inferred",
        "Unknown",
        "Do not write, create, or modify any repository file",
        "Do not automatically raise severity",
        "Finding Composition",
        "Finding Domains and External Taxonomies",
        "External taxonomies are optional annotations, never audit boundaries.",
        "A valid CLIVE finding does NOT require any external taxonomy mapping.",
        "Do not work through OWASP, CWE, or another taxonomy as a completeness checklist.",
        "`domains`",
        "`external_mappings`",
        "CLIVE-<SEQ>",
    ):
        assert phrase in instructions, phrase

    assert "`vulnerability_class`" not in instructions
    assert "**Classification**:" not in instructions
    assert "**Domain(s)**:" in instructions
    assert "**External Mappings**:" in instructions

    hook_cfg = data["hooks"]["PreToolUse"][0]["hooks"][0]
    assert "clive_guard.py" in hook_cfg["command"]
    assert "clive_guard.py" in hook_cfg["command_windows"]


def check_hook() -> None:
    evaluate = runpy.run_path(str(HOOK))["evaluate_event"]

    def allow(command: str) -> None:
        result = evaluate({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}})
        assert result is None, command

    def deny(tool: str, payload: dict) -> None:
        result = evaluate({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": payload})
        assert result is not None, tool
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny", result

    allow('rg -n "CLIVE" README.md')
    allow('cat README.md')
    allow('git --no-pager rev-parse --show-toplevel')

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
        deny("Bash", {"command": command})

    deny("apply_patch", {"command": "*** Begin Patch"})
    deny("Agent", {"agent_type": "worker"})
    deny("mcp__filesystem__read_file", {"path": "README.md"})


def check_release_hygiene() -> None:
    for path in ROOT.rglob("*"):
        assert "__pycache__" not in path.parts, path
        assert path.suffix != ".pyc", path
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        marker = "/mnt" + "/data/"
        assert marker not in text, path


def main() -> int:
    check_agent()
    check_hook()
    check_release_hygiene()
    print("PASS: CLIVE v1.0.1 agent configuration, native-domain taxonomy model, and static-only guard validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
