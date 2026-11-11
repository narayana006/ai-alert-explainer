"""Normalise incoming alert payloads into one shape.

Two payload shapes are recognised:

* A Prometheus Alertmanager webhook body: an object with an ``alerts`` list.
  Each entry becomes one Alert.
* Any other JSON object: treated as a single alert. Common field names are
  mapped (``title``/``name``, ``severity``/``priority``/``level``, ...); the
  whole object stays available to rules as ``raw``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_NAME_KEYS = ("name", "alertname", "title", "alert", "event", "rule")
_SEVERITY_KEYS = ("severity", "priority", "level")
_STATUS_KEYS = ("status", "state")
_SUMMARY_KEYS = ("summary", "message", "description", "text", "body")


@dataclass
class Alert:
    name: str = "unnamed alert"
    severity: str = ""
    status: str = "firing"
    summary: str = ""
    source: str = "generic"
    labels: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """The view that rule conditions and the model prompt look fields up in."""
        return {
            "name": self.name,
            "severity": self.severity,
            "status": self.status,
            "summary": self.summary,
            "source": self.source,
            "labels": self.labels,
            "annotations": self.annotations,
            "raw": self.raw,
        }

    def get(self, path: str) -> Any:
        """Look up a dotted path such as ``labels.env``; None when it is absent.

        Paths that do not start with a known field are looked up in the raw
        payload, so ``cpu.percent`` works for ``{"cpu": {"percent": 97}}``.
        """
        view = self.to_dict()
        first = path.split(".", 1)[0]
        node: Any = view if first in view else self.raw
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node


def _pick(obj: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = obj.get(key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool) and value != "":
            return str(value)
    return ""


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def from_generic(payload: dict[str, Any]) -> Alert:
    labels = _dict(payload.get("labels")) or _dict(payload.get("tags"))
    annotations = _dict(payload.get("annotations"))
    return Alert(
        name=_pick(payload, _NAME_KEYS) or _pick(labels, _NAME_KEYS) or "unnamed alert",
        severity=(_pick(payload, _SEVERITY_KEYS) or _pick(labels, _SEVERITY_KEYS)).lower(),
        status=(_pick(payload, _STATUS_KEYS) or "firing").lower(),
        summary=_pick(payload, _SUMMARY_KEYS) or _pick(annotations, _SUMMARY_KEYS),
        source="generic",
        labels=labels,
        annotations=annotations,
        raw=payload,
    )


def from_alertmanager(payload: dict[str, Any]) -> list[Alert]:
    """One Alert per entry of an Alertmanager webhook body."""
    alerts = []
    common_labels = _dict(payload.get("commonLabels"))
    for item in payload.get("alerts") or []:
        if not isinstance(item, dict):
            continue
        labels = {**common_labels, **_dict(item.get("labels"))}
        annotations = _dict(item.get("annotations"))
        alerts.append(
            Alert(
                name=_pick(labels, ("alertname",)) or "unnamed alert",
                severity=_pick(labels, _SEVERITY_KEYS).lower(),
                status=(_pick(item, ("status",)) or _pick(payload, ("status",)) or "firing").lower(),
                summary=_pick(annotations, _SUMMARY_KEYS),
                source="alertmanager",
                labels=labels,
                annotations=annotations,
                raw=item,
            )
        )
    return alerts


def parse_payload(payload: Any) -> list[Alert]:
    """Turn a decoded JSON payload into alerts.

    Accepts an Alertmanager webhook body, a single alert object, or a list of
    either. Raises ValueError for anything else.
    """
    if isinstance(payload, Alert):
        return [payload]
    if isinstance(payload, list):
        alerts: list[Alert] = []
        for item in payload:
            alerts.extend(parse_payload(item))
        return alerts
    if not isinstance(payload, dict):
        raise ValueError("an alert payload must be a JSON object or a list of objects")
    if isinstance(payload.get("alerts"), list):
        return from_alertmanager(payload)
    return [from_generic(payload)]
