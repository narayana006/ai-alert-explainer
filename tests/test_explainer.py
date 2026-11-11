import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ai_alert_explainer import (
    ACT,
    IGNORE,
    WATCH,
    Alert,
    AuditLog,
    Explainer,
    ModelError,
    ModelOpinion,
    PromptModel,
    Rule,
    RuleResult,
    combine,
    default_rules,
    parse_payload,
    read_audit_log,
    rules_from_config,
    summarize_audit_log,
)
from ai_alert_explainer.cli import main
from ai_alert_explainer.model import build_prompt, parse_reply

EXAMPLES = Path(__file__).parent.parent / "examples"
WEBHOOK = EXAMPLES / "alertmanager_webhook.json"
RULES = EXAMPLES / "rules.json"


def run(argv, stdin_text=""):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin_text), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def result(label, weight=1.0, name="r"):
    return RuleResult(rule=name, label=label, weight=weight, fact=f"fact from {name}")


class FakeModel:
    def __init__(self, opinion=None, error=None):
        self.opinion, self.error, self.calls = opinion, error, []

    def assess(self, alert, rule_results):
        self.calls.append((alert, rule_results))
        if self.error:
            raise self.error
        return self.opinion


# --- payload normalisation -------------------------------------------------


def test_alertmanager_payload_becomes_one_alert_per_entry():
    alerts = parse_payload(json.loads(WEBHOOK.read_text()))
    assert [a.name for a in alerts][:2] == ["CheckoutHighErrorRate", "DiskFillingUp"]
    first, resolved = alerts[0], alerts[3]
    assert (first.severity, first.status, first.source) == ("critical", "firing", "alertmanager")
    assert first.labels["team"] == "shop"  # merged from commonLabels
    assert first.summary == "12% of checkout requests are failing"
    assert resolved.status == "resolved"


def test_generic_payload_maps_common_field_names():
    (alert,) = parse_payload(
        {"title": "Build failed", "priority": "P1", "state": "OPEN", "message": "main is red",
         "tags": {"repo": "shop"}}
    )
    assert (alert.name, alert.severity, alert.status) == ("Build failed", "p1", "open")
    assert alert.summary == "main is red" and alert.labels == {"repo": "shop"}


def test_generic_payload_defaults_and_lists():
    (alert,) = parse_payload({})
    assert (alert.name, alert.severity, alert.status) == ("unnamed alert", "", "firing")
    assert len(parse_payload([{"name": "a"}, {"alerts": [{"labels": {}}, {"labels": {}}]}])) == 3


@pytest.mark.parametrize("payload", ["text", 7, None])
def test_non_object_payload_is_rejected(payload):
    with pytest.raises(ValueError):
        parse_payload(payload)


def test_alert_get_follows_dotted_paths_and_falls_back_to_raw():
    alert = Alert(labels={"env": "prod"}, raw={"cpu": {"percent": 97}, "labels": "shadowed"})
    assert alert.get("labels.env") == "prod"
    assert alert.get("cpu.percent") == 97
    assert alert.get("labels.missing") is None and alert.get("nope.deeper") is None


# --- rules -----------------------------------------------------------------


def one_rule(when, label="ACT", **extra):
    return rules_from_config([{"name": "t", "when": when, "label": label, **extra}])[0]


@pytest.mark.parametrize(
    "when, payload, fires",
    [
        ({"field": "severity", "equals": "CRITICAL"}, {"severity": "critical"}, True),
        ({"field": "severity", "equals": "critical"}, {}, False),
        ({"field": "severity", "not_equals": "info"}, {}, True),
        ({"field": "labels.env", "in": ["staging", "dev"]}, {"labels": {"env": "dev"}}, True),
        ({"field": "labels.env", "in": ["staging", "dev"]}, {"labels": {"env": "prod"}}, False),
        ({"field": "summary", "matches": "disk .* full"}, {"message": "disk sda is full"}, True),
        ({"field": "value", "gt": 90}, {"value": 90.5}, True),
        ({"field": "value", "gt": 90}, {"value": "90"}, False),
        ({"field": "value", "gte": 90}, {"value": "90%"}, True),
        ({"field": "value", "lt": 5}, {"value": "n/a"}, False),
        ({"field": "value", "lte": 5}, {"value": 5}, True),
        ({"field": "value", "gt": 1}, {"value": True}, False),
        ({"field": "runbook", "exists": True}, {"runbook": "https://wiki.example.com/r"}, True),
        ({"field": "runbook", "exists": False}, {}, True),
    ],
)
def test_condition_operators(when, payload, fires):
    (alert,) = parse_payload(payload)
    assert (one_rule(when)(alert) is not None) is fires


def test_all_conditions_must_hold_and_fact_is_generated():
    rule = one_rule(
        [{"field": "labels.env", "equals": "prod"}, {"field": "value", "gt": 0.05}], weight=2
    )
    (hit,) = parse_payload({"labels": {"env": "prod"}, "value": 0.12})
    (miss,) = parse_payload({"labels": {"env": "prod"}, "value": 0.01})
    outcome = rule(hit)
    assert (outcome.label, outcome.weight) == (ACT, 2.0)
    assert outcome.fact == "labels.env is prod and value is 0.12, above 0.05"
    assert rule(miss) is None


def test_custom_fact_text_is_used():
    rule = one_rule({"field": "status", "equals": "resolved"}, "ignore", fact="already resolved")
    (alert,) = parse_payload({"status": "resolved"})
    assert (rule(alert).label, rule(alert).fact) == (IGNORE, "already resolved")


@pytest.mark.parametrize(
    "config",
    [
        {"not": "a list"},
        ["not an object"],
        [{"name": "x", "label": "ACT"}],
        [{"name": "x", "when": {"field": "a", "equals": 1}}],
        [{"name": "x", "when": {"field": "a", "equals": 1}, "label": "PANIC"}],
        [{"name": "x", "when": {"field": "a", "bigger": 1}, "label": "ACT"}],
        [{"name": "x", "when": {"field": "a", "gt": 1, "lt": 3}, "label": "ACT"}],
        [{"name": "x", "when": {"equals": 1}, "label": "ACT"}],
        [{"name": "x", "when": {"field": "a", "in": "abc"}, "label": "ACT"}],
        [{"name": "x", "when": {"field": "a", "matches": "("}, "label": "ACT"}],
        [{"name": "x", "when": {"field": "a", "equals": 1}, "label": "ACT", "weight": 0}],
        [{"name": "x", "when": [], "label": "ACT"}],
    ],
)
def test_bad_rule_config_is_rejected(config):
    with pytest.raises(ValueError):
        rules_from_config(config)


def test_default_rules_cover_severity_and_resolved():
    explainer = Explainer()
    assert explainer.evaluate({"name": "a", "severity": "critical"}).label == ACT
    assert explainer.evaluate({"name": "a", "severity": "warning"}).label == WATCH
    assert explainer.evaluate({"name": "a", "severity": "info"}).label == IGNORE
    assert explainer.evaluate({"name": "a", "severity": "critical", "status": "resolved"}).label == IGNORE
    assert len(default_rules()) == 4


# --- combining votes -------------------------------------------------------


def test_confidence_grows_with_agreeing_evidence():
    assert combine([result(ACT)]).confidence == 0.5
    assert combine([result(ACT), result(ACT)]).confidence == 0.67
    assert combine([result(ACT), result(ACT), result(ACT)]).confidence == 0.75


def test_disagreement_lowers_confidence_and_is_explained():
    verdict = combine([result(ACT, 2, "a"), result(IGNORE, 1, "b")])
    assert (verdict.label, verdict.confidence) == (ACT, 0.5)
    assert verdict.votes == {"ACT": 2.0, "WATCH": 0.0, "IGNORE": 1.0}
    assert "ACT because fact from a." in verdict.reasoning
    assert "Against: fact from b (points to IGNORE)." in verdict.reasoning


def test_tie_goes_to_the_more_cautious_label():
    assert combine([result(IGNORE), result(ACT)]).label == ACT
    assert combine([result(IGNORE), result(WATCH)]).label == WATCH


def test_no_evidence_is_watch_with_zero_confidence():
    verdict = combine([])
    assert (verdict.label, verdict.confidence) == (WATCH, 0.0)
    assert "No rule matched" in verdict.reasoning


def test_model_opinion_adds_weighted_vote():
    opinion = ModelOpinion(ACT, 0.8, "Errors are user facing.")
    verdict = combine([result(ACT)], opinion)
    assert verdict.votes["ACT"] == 1.8
    assert verdict.confidence == 0.64  # 1.8 / 2.8
    assert "The model agrees (confidence 0.80): Errors are user facing." in verdict.reasoning


def test_model_can_outvote_weak_rules_but_not_strong_ones():
    opinion = ModelOpinion(IGNORE, 0.9, "Known noisy check")
    weak = combine([result(WATCH, 0.5)], opinion)
    assert weak.label == IGNORE and "The model agrees" in weak.reasoning
    strong = combine([result(ACT, 3)], opinion)
    assert strong.label == ACT and "The model says IGNORE" in strong.reasoning
    assert combine([result(ACT, 3)], opinion, model_weight=0).votes["IGNORE"] == 0.0


def test_model_alone_is_reported_as_such():
    verdict = combine([], ModelOpinion(WATCH, 0.6, ""))
    assert verdict.label == WATCH and "model's opinion alone" in verdict.reasoning


# --- model interface -------------------------------------------------------


def test_model_is_off_by_default_and_fake_model_is_consulted_when_given():
    assert Explainer().model is None
    fake = FakeModel(ModelOpinion(ACT, 1.0, "It is on fire"))
    verdict = Explainer(model=fake).evaluate({"name": "Fire", "severity": "warning"})
    assert len(fake.calls) == 1
    alert, rule_results = fake.calls[0]
    assert alert.name == "Fire" and [r.label for r in rule_results] == [WATCH]
    assert verdict.label == ACT  # tie between WATCH 1.0 and ACT 1.0 goes to ACT
    assert verdict.model_opinion.reasoning == "It is on fire"


def test_model_failure_falls_back_to_rules_and_is_noted():
    fake = FakeModel(error=ModelError("timeout"))
    verdict = Explainer(model=fake).evaluate({"name": "a", "severity": "critical"})
    assert (verdict.label, verdict.confidence) == (ACT, 0.5)
    assert verdict.model_opinion is None
    assert verdict.notes == ["model skipped: timeout"]


def test_prompt_model_sends_alert_and_facts_and_parses_reply():
    prompts = []

    def complete(prompt):
        prompts.append(prompt)
        return 'Sure:\n```json\n{"label": "watch", "confidence": 1.7, "reasoning": "Trend is flat."}\n```'

    (alert,) = parse_payload({"name": "QueueDepth", "severity": "warning", "big": "x" * 10})
    opinion = PromptModel(complete).assess(alert, [result(WATCH, name="sev")])
    assert opinion == ModelOpinion(WATCH, 1.0, "Trend is flat.")
    assert '"name": "QueueDepth"' in prompts[0]
    assert "fact from sev (rule sev says WATCH)" in prompts[0]
    assert '"raw"' not in prompts[0]


def test_prompt_without_facts_says_none():
    assert "- none" in build_prompt(Alert(name="a"), [])


@pytest.mark.parametrize(
    "reply",
    ["no json here", "{broken", '{"label": "PANIC", "confidence": 1}', '{"label": "ACT"}',
     '{"label": "ACT", "confidence": "high"}', None],
)
def test_bad_model_replies_raise_model_error(reply):
    with pytest.raises(ModelError):
        parse_reply(reply)


def test_prompt_model_wraps_transport_errors():
    def complete(prompt):
        raise ConnectionError("unreachable")

    with pytest.raises(ModelError, match="unreachable"):
        PromptModel(complete).assess(Alert(), [])


# --- explainer -------------------------------------------------------------


def test_python_rules_and_broken_rules():
    def big_queue(alert):
        if (alert.get("queue_depth") or 0) > 1000:
            return RuleResult("big-queue", ACT, 2.0, "queue depth is over 1000")
        return None

    def broken(alert):
        raise RuntimeError("boom")

    def invalid(alert):
        return RuleResult("invalid", "MAYBE", 1.0, "x")

    explainer = Explainer(rules=[Rule("big-queue", big_queue), Rule("broken", broken),
                                 Rule("invalid", invalid)])
    verdict = explainer.evaluate({"name": "Queue", "queue_depth": 5000})
    assert (verdict.label, verdict.confidence, verdict.alert_name) == (ACT, 0.67, "Queue")
    assert verdict.notes == [
        "rule error: broken: boom",
        "rule error: invalid: returned an invalid label or weight",
    ]


def test_evaluate_requires_exactly_one_alert():
    explainer = Explainer()
    with pytest.raises(ValueError, match="evaluate_all"):
        explainer.evaluate(json.loads(WEBHOOK.read_text()))
    assert len(explainer.evaluate_all(json.loads(WEBHOOK.read_text()))) == 5
    with pytest.raises(ValueError):
        Explainer(model_weight=-1)


def test_example_rules_give_expected_verdicts():
    explainer = Explainer(rules=rules_from_config(json.loads(RULES.read_text())))
    verdicts = explainer.evaluate_all(json.loads(WEBHOOK.read_text()))
    assert [(v.alert_name, v.label, v.confidence) for v in verdicts] == [
        ("CheckoutHighErrorRate", ACT, 0.8),
        ("DiskFillingUp", WATCH, 0.67),
        ("HighCPU", IGNORE, 0.5),
        ("PodRestarting", IGNORE, 0.5),
        ("CertificateExpiry", WATCH, 0.5),
    ]


# --- audit log -------------------------------------------------------------


def test_audit_log_records_every_verdict_and_summarises(tmp_path):
    path = tmp_path / "logs" / "verdicts.jsonl"
    clock = lambda: datetime(2026, 11, 9, 14, 5, tzinfo=timezone.utc)  # noqa: E731
    fake = FakeModel(ModelOpinion(IGNORE, 0.4, "Probably noise"))
    explainer = Explainer(model=fake, audit_log=AuditLog(path, clock=clock))
    explainer.evaluate({"name": "A", "severity": "critical"})
    explainer.evaluate({"name": "B", "severity": "info"})
    entries = read_audit_log(path)
    assert [e["alert"] for e in entries] == ["A", "B"]
    assert entries[0]["time"] == "2026-11-09T14:05:00+00:00"
    assert entries[0]["rules"][0]["rule"] == "severity-critical"
    assert entries[0]["model"]["label"] == "IGNORE"
    summary = summarize_audit_log(entries)
    assert summary["verdicts"] == 2
    assert summary["by_label"] == {"ACT": 1, "IGNORE": 1}
    assert [d["alert"] for d in summary["model_disagreements"]] == ["A"]


def test_reading_a_corrupt_audit_log_names_the_line(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"label": "ACT"}\n\nnot json\n')
    with pytest.raises(ValueError, match="line 3"):
        read_audit_log(path)


# --- command line ----------------------------------------------------------


def test_cli_evaluate_text_and_audit(tmp_path):
    log = tmp_path / "verdicts.jsonl"
    code, out, _ = run(
        ["evaluate", str(WEBHOOK), "--rules", str(RULES), "--audit-log", str(log)]
    )
    assert code == 0
    assert out.splitlines()[0] == "ACT    0.80  CheckoutHighErrorRate"
    assert "5 alert(s): 1 ACT, 2 WATCH, 2 IGNORE" in out
    code, out, _ = run(["audit", str(log)])
    assert code == 0 and "5 verdict(s) in the audit log" in out
    code, out, _ = run(["audit", str(log), "--format", "json"])
    assert json.loads(out)["by_label"] == {"ACT": 1, "IGNORE": 2, "WATCH": 2}


def test_cli_json_from_stdin_with_default_rules_and_fail_on_act():
    payload = json.dumps({"name": "Disk", "severity": "critical"})
    code, out, _ = run(["evaluate", "--format", "json", "--fail-on-act"], payload)
    assert code == 1
    (verdict,) = json.loads(out)
    assert (verdict["label"], verdict["confidence"], verdict["model"]) == ("ACT", 0.5, None)


def test_cli_errors(tmp_path):
    bad_rules = tmp_path / "rules.json"
    bad_rules.write_text('[{"name": "x", "when": {"field": "a", "equals": 1}, "label": "PANIC"}]')
    code, _, err = run(["evaluate", str(WEBHOOK), "--rules", str(bad_rules)])
    assert code == 2 and "label must be one of" in err
    code, _, err = run(["evaluate", str(tmp_path / "missing.json")])
    assert code == 2 and "cannot read" in err
    code, _, err = run(["evaluate"], "not json")
    assert code == 2 and "not valid JSON" in err
    code, _, err = run(["evaluate"], '"just a string"')
    assert code == 2 and "JSON object" in err
    code, _, err = run(["audit", str(tmp_path / "missing.jsonl")])
    assert code == 2 and "cannot read" in err
