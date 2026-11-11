"""Append-only audit log of verdicts, one JSON object per line."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .verdict import Verdict


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog:
    def __init__(self, path: str | Path, clock: Callable[[], datetime] = _utc_now):
        self.path = Path(path)
        self._clock = clock

    def record(self, verdict: Verdict) -> dict[str, Any]:
        entry = {"time": self._clock().isoformat(timespec="seconds"), **verdict.to_dict()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry


def read_audit_log(path: str | Path) -> list[dict[str, Any]]:
    """Read every entry; raises ValueError naming the first malformed line."""
    entries = []
    with Path(path).open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {number} is not valid JSON: {exc.msg}") from exc
            if not isinstance(entry, dict):
                raise ValueError(f"line {number} is not a JSON object")
            entries.append(entry)
    return entries


def summarize_audit_log(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts per label, average confidence per label and model disagreements."""
    labels = Counter(str(e.get("label")) for e in entries)
    confidence: dict[str, list[float]] = {}
    disagreements = []
    for entry in entries:
        value = entry.get("confidence")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            confidence.setdefault(str(entry.get("label")), []).append(float(value))
        model = entry.get("model")
        if isinstance(model, dict) and model.get("label") != entry.get("label"):
            disagreements.append(
                {
                    "time": entry.get("time"),
                    "alert": entry.get("alert"),
                    "label": entry.get("label"),
                    "model_label": model.get("label"),
                }
            )
    return {
        "verdicts": len(entries),
        "by_label": dict(sorted(labels.items())),
        "average_confidence": {
            label: round(sum(values) / len(values), 2) for label, values in sorted(confidence.items())
        },
        "model_disagreements": disagreements,
    }
