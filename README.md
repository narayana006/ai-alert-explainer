# ai-alert-explainer

Turn an alert into a plain-English verdict: **ACT**, **WATCH** or **IGNORE**, with the reasons and a confidence score. Your own rules establish the facts; a model's opinion can be added on top.

> **Status: first working version.** The rule engine, the confidence score, the audit log, a command-line tool and Alertmanager/generic JSON payload parsing work today, offline, with no API keys. The model step is an optional plug-in interface that is **off by default**: no model client ships with this package, so out of the box every verdict comes from rules alone. There is no webhook server and there are no Slack or email adapters yet.

## Install

Requires Python 3.10 or newer. No runtime dependencies.

```bash
pip install git+https://github.com/narayana006/ai-alert-explainer
```

## Quick start

Clone the repository for the sample files: an invented Alertmanager webhook body with five alerts, and a small rule set.

```bash
ai-alert-explainer evaluate examples/alertmanager_webhook.json --rules examples/rules.json --audit-log verdicts.jsonl
```

```
ACT    0.80  CheckoutHighErrorRate
       ACT because severity is critical; it is a critical alert in production; annotations.error_ratio is 0.12, above 0.05.
WATCH  0.67  DiskFillingUp
       WATCH because severity is warning; annotations.used_percent is 81, below 90.
IGNORE 0.50  HighCPU
       IGNORE because it comes from a non-production environment. Against: severity is critical (points to ACT).
IGNORE 0.50  PodRestarting
       IGNORE because the alert has already resolved. Against: severity is critical (points to ACT); it is a critical alert in production (points to ACT).
WATCH  0.50  CertificateExpiry
       WATCH because annotations.days_left is 20, at least 14.

5 alert(s): 1 ACT, 2 WATCH, 2 IGNORE
```

Every verdict was also appended to `verdicts.jsonl`. Review it later with:

```bash
ai-alert-explainer audit verdicts.jsonl
```

```
5 verdict(s) in the audit log
  ACT    1, average confidence 0.80
  IGNORE 2, average confidence 0.50
  WATCH  2, average confidence 0.58
```

## As a library

```python
from ai_alert_explainer import Explainer

explainer = Explainer()  # built-in rules, no model
verdict = explainer.evaluate(
    {"name": "DiskFull", "severity": "critical", "message": "/var is 97% full on db-1.example.com"}
)
print(verdict.label, verdict.confidence)
print(verdict.reasoning)
```

```
ACT 0.5
ACT because severity is critical.
```

`evaluate` takes a payload holding one alert and returns a `Verdict` with `label`, `confidence`, `reasoning`, `rule_results`, `model_opinion`, `votes` and `notes`. Use `evaluate_all` for a payload with several alerts, such as an Alertmanager webhook body.

### Your own rules in Python

A rule is a function that takes the alert and returns a `RuleResult`, or `None` when it has nothing to say.

```python
from ai_alert_explainer import ACT, AuditLog, Explainer, Rule, RuleResult, default_rules


def customer_impact(alert):
    affected = alert.get("affected_customers") or 0
    if affected > 100:
        return RuleResult(
            rule="customer-impact", label=ACT, weight=2.0, fact=f"{affected} customers are affected"
        )
    return None  # the rule has nothing to say about this alert


explainer = Explainer(
    rules=[*default_rules(), Rule("customer-impact", customer_impact)],
    audit_log=AuditLog("verdicts.jsonl"),
)
verdict = explainer.evaluate({"title": "Payment failures", "severity": "warning", "affected_customers": 290})
print(verdict.label, verdict.confidence, verdict.reasoning)
```

```
ACT 0.5 ACT because 290 customers are affected. Against: severity is warning (points to WATCH).
```

`alert.get("a.b.c")` looks up a dotted path in the normalised alert (`name`, `severity`, `status`, `summary`, `labels.*`, `annotations.*`) and falls back to the original payload. A rule that raises an exception is skipped and reported in `verdict.notes`; it does not lose the alert.

### Rules as JSON

The command line (and `rules_from_config`) reads rules like these from [`examples/rules.json`](examples/rules.json):

```json
[
  {
    "name": "not-production",
    "when": {"field": "labels.env", "in": ["staging", "dev", "test"]},
    "label": "IGNORE",
    "weight": 2,
    "fact": "it comes from a non-production environment"
  },
  {
    "name": "error-budget-burning",
    "when": {"field": "annotations.error_ratio", "gt": 0.05},
    "label": "ACT",
    "weight": 2
  }
]
```

- `when` is one condition or a list of conditions that must all hold.
- A condition names a `field` and exactly one operator: `equals`, `not_equals`, `in` (text, case-insensitive), `matches` (regular expression), `gt`, `gte`, `lt`, `lte` (numbers; numeric strings such as `"81"` or `"81%"` are accepted) or `exists` (`true`/`false`).
- `weight` defaults to 1. `fact` is the sentence used in the reasoning; without it one is generated from the condition.

With no `--rules`, four built-in rules apply: a resolved alert is IGNORE (weight 3), critical severity is ACT, warning is WATCH and info is IGNORE.

## How the verdict and confidence are worked out

No hidden scoring; you can check any verdict by hand from the `votes` it records.

1. Each rule that fires adds its weight to the label it voted for.
2. If a model is configured, its opinion adds `model_weight x its confidence` to its label (`model_weight` defaults to 1).
3. The label with the most weight wins. A tie goes to the more cautious label: ACT before WATCH before IGNORE.
4. `confidence = winner's share of the weight x total / (total + 1)`. The second factor keeps confidence low when evidence is thin: one rule of weight 1 gives 0.50, three agreeing rules give 0.75, and disagreement pulls it down. In the quick start, `PodRestarting` has 3 for IGNORE against 2 for ACT, so 3/5 x 5/6 = 0.50.
5. If nothing fires, the verdict is WATCH with confidence 0.

The confidence is a summary of how much evidence agrees. It is not a calibrated probability.

## Adding a model (optional, off by default)

A model is any object with an `assess(alert, rule_results)` method that returns a `ModelOpinion(label, confidence, reasoning)`. If you have a function that sends a prompt somewhere and returns text, `PromptModel` does the rest: it builds the prompt from the alert and the rule facts and parses a JSON reply.

```python
from ai_alert_explainer import Explainer, PromptModel


def complete(prompt: str) -> str:
    # Call whatever text-generation service you use, for example any
    # OpenAI-compatible HTTP endpoint, and return the reply text.
    ...


explainer = Explainer(model=PromptModel(complete))
```

[`examples/library_usage.py`](examples/library_usage.py) is a runnable version with a local stand-in for `complete`, so it needs no network:

```bash
python examples/library_usage.py
```

```
ACT 0.79
ACT because severity is critical; 290 customers are affected. The model agrees (confidence 0.80): Payment failures affect revenue directly and the count is rising.
```

If the model call fails or its reply cannot be parsed, the verdict falls back to the rules alone and `verdict.notes` says so. The alert, including its labels and annotations, is sent to whatever `complete` calls, so think about what your alerts contain before pointing it at an outside service.

## Command line

```
ai-alert-explainer evaluate [FILE] [--rules FILE] [--audit-log FILE] [--format text|json] [--fail-on-act]
ai-alert-explainer audit FILE [--format text|json]
```

`FILE` is a JSON payload; `-` or nothing reads standard input. `--fail-on-act` exits with status 1 when any verdict is ACT. Status 2 means an input could not be read or was invalid. The command line always runs rules only; the model step is available from Python.

**Payloads understood.** An Alertmanager webhook body (an object with an `alerts` list; `commonLabels` are merged into each alert), a single JSON object, or a list of either. For a plain object, the name is read from `name`, `alertname`, `title`, `alert`, `event` or `rule`; severity from `severity`, `priority` or `level`; status from `status` or `state`; the summary from `summary`, `message`, `description`, `text` or `body`.

**Audit log.** One JSON object per line with the time (UTC), alert name, label, confidence, reasoning, votes, every rule result and the model opinion if there was one. `audit` counts verdicts per label, averages confidence and lists the cases where the model disagreed with the final label.

## Feature checklist

- [x] Pluggable rules you define (thresholds, context checks), in Python or JSON
- [x] Verdict: ACT / WATCH / IGNORE with reasoning (from rules)
- [x] Confidence score combining rule and model signals
- [x] Audit log of every verdict for later review
- [x] Model opinion behind a provider-neutral interface (bring your own `complete` function; no model client is bundled)
- [x] Alertmanager webhook and generic JSON payload parsing (from a file or standard input)
- [ ] HTTP webhook receiver (a running service)
- [ ] Slack and email adapters
- [ ] Context checks that need history, such as flapping or repeat counts

## Limitations

- Without a model, this is a weighted rule engine with readable output. The "AI" part is only as good as the model you plug in, and none is included or tested against a real service.
- Rules see one alert at a time. There is no memory of earlier alerts, so no deduplication or flapping detection.
- The quality of a verdict depends on your rules. The built-in ones only look at severity and resolved status.
- The audit log is a local file with no rotation or locking; give each process its own file.
- Example data is invented.

## Development

```bash
git clone https://github.com/narayana006/ai-alert-explainer
cd ai-alert-explainer
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
pytest
```

## Contributing

Issues and pull requests are welcome. Sample payloads from other alert sources (with anything private removed) and rule ideas are especially useful.

## Author

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
