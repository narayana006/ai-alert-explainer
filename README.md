# ai-alert-explainer

> Explain any alert or signal in plain English: rule-based checks plus an LLM verdict with reasoning and confidence.

**Status:** 🚧 Early stage — design and roadmap published, implementation in progress. Stars, issues and ideas welcome.

## Why

Alerts from trading systems, monitoring and CI say what fired but not what it means or whether to act.

## Planned features

- [ ] Pluggable rules you define (thresholds, context checks)
- [ ] LLM verdict: SUPPORT / CAUTION / MIXED with reasoning
- [ ] Confidence score combining rule and model signals
- [ ] Adapters for webhook, Slack and email alerts
- [ ] Audit log of every verdict for later review

## Intended usage

```
explainer.evaluate(alert_payload) -> Verdict(label, confidence, reasoning)
```

_The interface above is the target design and may change._

## Roadmap

1. Core implementation of the first feature set
2. Examples and tests
3. CI and first tagged release
4. Docs and integrations

## Contributing

Contributions are welcome. Open an issue to discuss an idea or pick an unchecked item from the feature list.

## License

[MIT](LICENSE)
