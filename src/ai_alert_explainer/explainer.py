"""The Explainer ties rules, the optional model and the audit log together."""

from __future__ import annotations

from typing import Any

from .alert import Alert, parse_payload
from .audit import AuditLog
from .model import Model
from .rules import Rule, default_rules, run_rules
from .verdict import Verdict, combine


class Explainer:
    """Evaluate alerts against rules and, optionally, a model.

    ``rules`` defaults to ``default_rules()``. ``model`` is off unless you pass
    one. ``audit_log`` (an AuditLog) records every verdict when given.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        model: Model | None = None,
        audit_log: AuditLog | None = None,
        model_weight: float = 1.0,
    ):
        if model_weight < 0:
            raise ValueError("model_weight cannot be negative")
        self.rules = default_rules() if rules is None else list(rules)
        self.model = model
        self.audit_log = audit_log
        self.model_weight = model_weight

    def evaluate(self, alert_payload: Any) -> Verdict:
        """Evaluate a payload that holds exactly one alert."""
        alerts = parse_payload(alert_payload)
        if len(alerts) != 1:
            raise ValueError(
                f"the payload holds {len(alerts)} alerts; use evaluate_all for batches"
            )
        return self._evaluate_alert(alerts[0])

    def evaluate_all(self, alert_payload: Any) -> list[Verdict]:
        """Evaluate every alert in a payload, such as an Alertmanager webhook body."""
        return [self._evaluate_alert(alert) for alert in parse_payload(alert_payload)]

    def _evaluate_alert(self, alert: Alert) -> Verdict:
        rule_results, errors = run_rules(self.rules, alert)
        notes = [f"rule error: {error}" for error in errors]
        opinion = None
        if self.model is not None:
            try:
                opinion = self.model.assess(alert, rule_results)
            except Exception as exc:
                # The rules still give an answer when the model is unavailable.
                notes.append(f"model skipped: {exc}")
        verdict = combine(rule_results, opinion, self.model_weight)
        verdict.alert_name = alert.name
        verdict.notes = notes
        if self.audit_log is not None:
            self.audit_log.record(verdict)
        return verdict
