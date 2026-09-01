#!/usr/bin/env python3
"""PreToolUse guard for CLIVE, the source-only Code Logic, Integrity & Vulnerability Evaluator."""
from __future__ import annotations
import json
import shlex
import sys
from pathlib import Path
from typing import Any

SAFE_SIMPLE = {"pwd", "ls", "cat", "head", "tail", "nl", "wc", "stat", "file", "readlink", "realpath"}
SAFE_SEARCH = {"rg", "grep"}
SAFE_GIT_SUBCOMMANDS = {"diff", "show", "ls-files", "ls-tree", "cat-file", "rev-parse", "grep"}
DANGEROUS_SEARCH_FLAGS = {"--pre", "--pre-glob"}
DANGEROUS_GIT_FLAGS = {"--ext-diff", "--textconv", "--show-signature"}
SHELL_PUNCT = "|&;<>()"

def denial(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}

def shell_tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=SHELL_PUNCT)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)

def has_shell_composition(tokens: list[str], command: str) -> bool:
    if "\n" in command or "\r" in command or "`" in command or "$(" in command or "${" in command:
        return True
    return any(token and all(ch in SHELL_PUNCT for ch in token) for token in tokens)

def check_git(tokens: list[str]) -> tuple[bool, str]:
    if len(tokens) < 3 or tokens[1] != "--no-pager":
        return False, "Git inspection must use `git --no-pager <approved-subcommand>`."
    sub = tokens[2]
    if sub not in SAFE_GIT_SUBCOMMANDS:
        return False, f"Git subcommand `{sub}` is outside the static-audit allowlist."
    if any(flag in tokens for flag in DANGEROUS_GIT_FLAGS):
        return False, "External diff, text conversion, or signature execution is not allowed."
    if sub in {"diff", "show"} and ("--no-ext-diff" not in tokens or "--no-textconv" not in tokens):
        return False, f"`git {sub}` must include both --no-ext-diff and --no-textconv."
    return True, ""

def check_bash(command: Any) -> tuple[bool, str]:
    if not isinstance(command, str) or not command.strip():
        return False, "Malformed or empty Bash command."
    try:
        tokens = shell_tokens(command)
    except ValueError:
        return False, "Unable to parse Bash command safely."
    if not tokens:
        return False, "Empty Bash command."
    if has_shell_composition(tokens, command):
        return False, "Shell composition, redirection, substitution, and compound commands are blocked."
    exe = Path(tokens[0]).name
    if exe in SAFE_SIMPLE:
        if exe == "file" and any(arg == "-z" or arg.startswith("--uncompress") for arg in tokens[1:]):
            return False, "`file` decompression modes are not allowed."
        return True, ""
    if exe in SAFE_SEARCH:
        if exe == "rg":
            for arg in tokens[1:]:
                if arg in DANGEROUS_SEARCH_FLAGS or any(arg.startswith(flag + "=") for flag in DANGEROUS_SEARCH_FLAGS):
                    return False, "ripgrep preprocessor execution is not allowed."
        return True, ""
    if exe == "git":
        return check_git(tokens)
    return False, f"Executable `{exe}` is outside the static-inspection allowlist."

def evaluate_event(event: dict) -> dict | None:
    if event.get("hook_event_name") != "PreToolUse":
        return denial("CLIVE guard only permits evaluated PreToolUse calls.")
    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input")
    if tool_name != "Bash":
        return denial(f"Tool `{tool_name}` is not permitted for the static-only CLIVE evaluator.")
    if not isinstance(tool_input, dict):
        return denial("Malformed Bash tool input.")
    allowed, reason = check_bash(tool_input.get("command"))
    if not allowed:
        return denial(reason)
    return None

def main() -> int:
    try:
        event = json.load(sys.stdin)
    except Exception as exc:
        print(f"CLIVE guard: malformed hook input: {exc}", file=sys.stderr)
        return 2
    decision = evaluate_event(event)
    if decision is not None:
        print(json.dumps(decision, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
