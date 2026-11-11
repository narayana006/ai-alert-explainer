"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any, TextIO

from . import __version__
from .audit import AuditLog, read_audit_log, summarize_audit_log
from .explainer import Explainer
from .rules import rules_from_config
from .verdict import Verdict


class InputError(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-alert-explainer",
        description="Explain alerts as ACT, WATCH or IGNORE using your own rules.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    evaluate = commands.add_parser("evaluate", help="evaluate the alerts in a JSON payload")
    evaluate.add_argument(
        "file", nargs="?", default="-", help="alert payload (JSON), or - for standard input"
    )
    evaluate.add_argument("--rules", metavar="FILE", help="rules as JSON (default: built-in rules)")
    evaluate.add_argument("--audit-log", metavar="FILE", help="append every verdict to this file")
    evaluate.add_argument("--format", choices=("text", "json"), default="text")
    evaluate.add_argument(
        "--fail-on-act", action="store_true", help="exit with status 1 if any verdict is ACT"
    )

    audit = commands.add_parser("audit", help="summarise an audit log written by evaluate")
    audit.add_argument("file", help="audit log (JSON lines)")
    audit.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _load_json(path: str, stdin: TextIO, what: str) -> Any:
    try:
        if path == "-":
            text = stdin.read()
        else:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{what} is not valid JSON: {exc.msg}") from exc


def render_verdicts(verdicts: list[Verdict]) -> str:
    lines = []
    for verdict in verdicts:
        lines.append(f"{verdict.label:<6} {verdict.confidence:.2f}  {verdict.alert_name}")
        lines.append(f"       {verdict.reasoning}")
        for note in verdict.notes:
            lines.append(f"       note: {note}")
    counts = {
        label: sum(1 for v in verdicts if v.label == label) for label in ("ACT", "WATCH", "IGNORE")
    }
    lines.append("")
    lines.append(
        f"{len(verdicts)} alert(s): {counts['ACT']} ACT, {counts['WATCH']} WATCH, "
        f"{counts['IGNORE']} IGNORE"
    )
    return "\n".join(lines)


def render_audit(summary: dict[str, Any]) -> str:
    lines = [f"{summary['verdicts']} verdict(s) in the audit log"]
    for label, count in summary["by_label"].items():
        average = summary["average_confidence"].get(label)
        suffix = f", average confidence {average:.2f}" if average is not None else ""
        lines.append(f"  {label:<6} {count}{suffix}")
    disagreements = summary["model_disagreements"]
    if disagreements:
        lines.append(f"Model disagreed with the final label {len(disagreements)} time(s):")
        for item in disagreements:
            lines.append(
                f"  {item['time']}  {item['alert']}: final {item['label']}, "
                f"model {item['model_label']}"
            )
    return "\n".join(lines)


def _run(args: argparse.Namespace, stdin: TextIO, stdout: TextIO) -> int:
    if args.command == "audit":
        try:
            entries = read_audit_log(args.file)
        except OSError as exc:
            raise InputError(f"cannot read {args.file}: {exc.strerror or exc}") from exc
        except ValueError as exc:
            raise InputError(f"{args.file}: {exc}") from exc
        summary = summarize_audit_log(entries)
        print(json.dumps(summary, indent=2) if args.format == "json" else render_audit(summary),
              file=stdout)
        return 0

    rules = None
    if args.rules:
        try:
            rules = rules_from_config(_load_json(args.rules, stdin, "the rules file"))
        except ValueError as exc:
            raise InputError(f"{args.rules}: {exc}") from exc
    payload = _load_json(args.file, stdin, "the alert payload")
    explainer = Explainer(
        rules=rules, audit_log=AuditLog(args.audit_log) if args.audit_log else None
    )
    try:
        verdicts = explainer.evaluate_all(payload)
    except ValueError as exc:
        raise InputError(str(exc)) from exc
    except OSError as exc:
        raise InputError(f"cannot write {args.audit_log}: {exc.strerror or exc}") from exc
    if args.format == "json":
        print(json.dumps([v.to_dict() for v in verdicts], indent=2), file=stdout)
    else:
        print(render_verdicts(verdicts), file=stdout)
    if args.fail_on_act and any(v.label == "ACT" for v in verdicts):
        return 1
    return 0


def main(
    argv: Sequence[str] | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        return _run(args, stdin, stdout)
    except InputError as exc:
        print(f"error: {exc}", file=stderr)
        return 2
