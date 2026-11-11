"""Use the library directly, with Python rules and a stand-in model.

Run from the repository root:  python examples/library_usage.py

The "model" here is a local function so the example runs offline. In real use
you would replace `complete` with a call to whatever text-generation service
you have, for example any OpenAI-compatible HTTP endpoint.
"""

import json

from ai_alert_explainer import ACT, IGNORE, Explainer, PromptModel, Rule, RuleResult, default_rules


def batch_jobs_can_wait(alert):
    """A rule written as a plain function: batch jobs can wait."""
    if alert.labels.get("kind") == "batch":
        return RuleResult(rule="batch-job", label=IGNORE, weight=1.0, fact="it is a batch job")
    return None


def paying_customers(alert):
    if alert.get("affected_customers") and alert.get("affected_customers") > 100:
        return RuleResult(
            rule="customer-impact",
            label=ACT,
            weight=2.0,
            fact=f"{alert.get('affected_customers')} customers are affected",
        )
    return None


def complete(prompt: str) -> str:
    # Stand-in for a real model call. It receives the prompt and returns text.
    return json.dumps(
        {
            "label": "ACT",
            "confidence": 0.8,
            "reasoning": "Payment failures affect revenue directly and the count is rising",
        }
    )


explainer = Explainer(
    rules=[
        *default_rules(),
        Rule("batch-job", batch_jobs_can_wait),
        Rule("customer-impact", paying_customers),
    ],
    model=PromptModel(complete),
)

verdict = explainer.evaluate(
    {
        "title": "Payment failures above threshold",
        "severity": "critical",
        "message": "312 card payments failed in the last 10 minutes",
        "affected_customers": 290,
        "labels": {"service": "payments.example.com"},
    }
)

print(verdict.label, verdict.confidence)
print(verdict.reasoning)
