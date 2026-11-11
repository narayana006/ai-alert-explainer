"""Combine rule results and an optional model opinion into one verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import ModelOpinion
from .rules import ACT, IGNORE, LABELS, WATCH, RuleResult

# When votes tie, prefer the more cautious label.
_CAUTION = {ACT: 2, WATCH: 1, IGNORE: 0}


@dataclass
class Verdict:
    label: str
    confidence: float
    reasoning: str
    alert_name: str = ""
    rule_results: list[RuleResult] = field(default_factory=list)
    model_opinion: ModelOpinion | None = None
    votes: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert": self.alert_name,
            "label": self.label,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "votes": self.votes,
            "rules": [
                {"rule": r.rule, "label": r.label, "weight": r.weight, "fact": r.fact}
                for r in self.rule_results
            ],
            "model": None
            if self.model_opinion is None
            else {
                "label": self.model_opinion.label,
                "confidence": self.model_opinion.confidence,
                "reasoning": self.model_opinion.reasoning,
            },
            "notes": self.notes,
        }


def combine(
    rule_results: list[RuleResult],
    model_opinion: ModelOpinion | None = None,
    model_weight: float = 1.0,
) -> Verdict:
    """Weigh the votes and return a verdict.

    Each rule adds its weight to the label it voted for. A model opinion adds
    ``model_weight * its confidence`` to its label. The label with the most
    weight wins; a tie goes to the more cautious label (ACT, then WATCH).

    confidence = (winner's share of the weight) * total / (total + 1)

    The second factor keeps confidence low when there is little evidence: one
    rule of weight 1 on its own gives 0.5, three agreeing rules give 0.75.
    With no evidence at all the verdict is WATCH with confidence 0.
    """
    votes = {label: 0.0 for label in LABELS}
    for result in rule_results:
        votes[result.label] += result.weight
    if model_opinion is not None:
        votes[model_opinion.label] += model_weight * model_opinion.confidence
    total = sum(votes.values())
    rounded = {label: round(value, 3) for label, value in votes.items()}

    if total <= 0:
        return Verdict(
            label=WATCH,
            confidence=0.0,
            reasoning="No rule matched, so there is no evidence either way. "
            "Look at it when you can.",
            rule_results=list(rule_results),
            model_opinion=model_opinion,
            votes=rounded,
        )

    winner = max(LABELS, key=lambda label: (votes[label], _CAUTION[label]))
    confidence = round(votes[winner] / total * total / (total + 1.0), 2)
    return Verdict(
        label=winner,
        confidence=confidence,
        reasoning=_reasoning(winner, rule_results, model_opinion),
        rule_results=list(rule_results),
        model_opinion=model_opinion,
        votes=rounded,
    )


def _reasoning(
    winner: str, rule_results: list[RuleResult], model_opinion: ModelOpinion | None
) -> str:
    supporting = [r.fact for r in rule_results if r.label == winner]
    opposing = [f"{r.fact} (points to {r.label})" for r in rule_results if r.label != winner]
    parts = []
    if supporting:
        parts.append(f"{winner} because " + "; ".join(supporting) + ".")
    else:
        parts.append(f"{winner} on the model's opinion alone; no rule voted for it.")
    if opposing:
        parts.append("Against: " + "; ".join(opposing) + ".")
    if model_opinion is not None:
        agrees = "agrees" if model_opinion.label == winner else f"says {model_opinion.label}"
        text = f"The model {agrees} (confidence {model_opinion.confidence:.2f})"
        if model_opinion.reasoning:
            text += f": {model_opinion.reasoning.rstrip('.')}"
        parts.append(text + ".")
    return " ".join(parts)
