"""Explain an alert as ACT, WATCH or IGNORE with reasoning and a confidence score."""

from .alert import Alert, parse_payload
from .audit import AuditLog, read_audit_log, summarize_audit_log
from .explainer import Explainer
from .model import Model, ModelError, ModelOpinion, PromptModel
from .rules import ACT, IGNORE, WATCH, Rule, RuleResult, default_rules, match, rules_from_config
from .verdict import Verdict, combine

__version__ = "0.1.0"

__all__ = [
    "ACT",
    "IGNORE",
    "WATCH",
    "Alert",
    "AuditLog",
    "Explainer",
    "Model",
    "ModelError",
    "ModelOpinion",
    "PromptModel",
    "Rule",
    "RuleResult",
    "Verdict",
    "combine",
    "default_rules",
    "match",
    "parse_payload",
    "read_audit_log",
    "rules_from_config",
    "summarize_audit_log",
]
