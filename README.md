# ai-alert-explainer

Explain any alert or signal in plain English: rule-based checks plus an LLM verdict with reasoning and confidence.

> **Project status: planning. There is no working code in this repository yet.**
> This README describes what the project will do. Nothing below can be installed or run today.
> Features are ticked off in the checklist as they are built.

## What it is

A Python library and service.

**The problem it solves:** Alerts from monitoring, CI and other automated systems say what fired but not what it means or whether to act.

## Who it is for

People who receive automated alerts (monitoring, CI, market signals) and want to know what each one means before acting.

## How it will work

1. An alert arrives by webhook, Slack or email.
2. Your own rules run first and record hard facts about it.
3. A model reads the alert and the rule results and returns a verdict (act, watch or ignore), its reasoning and a confidence score; every verdict is logged.

## Planned features

Unticked items are not built yet.

- [ ] Pluggable rules you define (thresholds, context checks)
- [ ] LLM verdict: ACT / WATCH / IGNORE with reasoning
- [ ] Confidence score combining rule and model signals
- [ ] Adapters for webhook, Slack and email alerts
- [ ] Audit log of every verdict for later review

## Planned usage

This is the intended interface, shown so you can judge the design. **It does not work yet**, and names may change before the first release.

```python
explainer.evaluate(alert_payload) -> Verdict(label, confidence, reasoning)
```

## Contributing

Feedback on the design is the most useful contribution right now. Open an issue to suggest a feature, question an approach or describe your use case. Code contributions are welcome once the first version lands.

## License

[MIT](LICENSE)
