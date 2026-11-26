from __future__ import annotations

import csv
import json
from datetime import timedelta

import numpy as np
import pytest

from resilient_mis import workload
from resilient_mis.config import load_config
from resilient_mis.detection import (
    FEATURES,
    FeatureBuilder,
    IsolationDetector,
    RuleDetector,
    assert_features_safe,
    build_matrix,
    select_threshold,
)
from resilient_mis.errors import DataError
from resilient_mis.telemetry import REQUIRED, load_events, parse_ts, validate_events

SMALL = {"workload": {"days_train": 7, "days_dev": 7, "days_test": 7, "incidents_dev": 4, "incidents_test": 4, "managers_per_tenant": 1,
                      "analysts_per_tenant": 2, "burst_days_dev": [1], "burst_days_test": [1]}}


@pytest.fixture(scope="module")
def wl():
    cfg = load_config()
    cfg["workload"] = {**cfg["workload"], **SMALL["workload"]}
    return workload.generate(5, cfg)


def row(**kw):
    base = {"event_time": "2026-03-02T10:00:00Z", "arrival_time": "2026-03-02T10:00:01Z", "principal": "p-1", "tenant": "tenant-a",
            "operation": "read_order", "decision": "allow", "correlation_id": "c1"}
    return base | kw


@pytest.mark.parametrize("bad,msg", [(dict(event_time="yesterday"), "ISO 8601"), (dict(event_time="2026-03-02T10:00:00"), "UTC offset"),
                                     (dict(operation="drop_table"), "unknown operation"), (dict(decision="maybe"), "unknown decision"),
                                     (dict(principal=""), "empty principal"), (dict(arrival_time="2026-03-02T09:00:00Z"), "precedes")])
def test_malformed_rows_are_reported_with_row_numbers(bad, msg):
    with pytest.raises(DataError) as e:
        validate_events([row(), row(correlation_id="c2", **bad)])
    assert any("row 2" in p and msg in p for p in e.value.problems)


def test_malformed_import_structure():
    with pytest.raises(DataError):
        validate_events([])
    with pytest.raises(DataError, match="missing required"):
        validate_events([{"event_time": "x"}])
    with pytest.raises(DataError, match="forbidden|label"):
        validate_events([row() | {"incident_label": "attack"}])
    with pytest.raises(DataError) as e:
        validate_events([row(), row()])
    assert any("duplicate correlation_id" in p for p in e.value.problems)


def test_load_csv_and_jsonl_and_malformed_files(tmp_path):
    rows = [row(correlation_id=f"c{i}", arrival_time=f"2026-03-02T10:00:{10 - i:02d}Z", event_time=f"2026-03-02T10:00:{5 - i % 5:02d}Z") for i in range(3)]
    p = tmp_path / "e.csv"
    with p.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader(), w.writerows(rows)
    assert [e["correlation_id"] for e in load_events(p)] == ["c2", "c1", "c0"]  # replay order is arrival order
    q = tmp_path / "e.jsonl"
    q.write_text("\n".join(json.dumps(r) for r in rows))
    assert len(load_events(q)) == 3
    q.write_text('{"a": 1}\n{not json')
    with pytest.raises(DataError, match="malformed JSONL"):
        load_events(q)
    with pytest.raises(DataError):
        load_events(tmp_path / "absent.csv")


def test_workload_events_never_carry_labels(wl):
    assert set(wl["events"][0]) == set(REQUIRED)
    text = json.dumps(wl["events"])
    assert "INC-" not in text and "credential_stuffing" not in text and "bulk_export" not in text
    assert all(set(lab) >= {"incident_id", "kind", "principal", "onset", "end"} for lab in wl["labels"])


def test_workload_is_reproducible_and_chronological(wl):
    cfg = load_config()
    cfg["workload"] = {**cfg["workload"], **SMALL["workload"]}
    again = workload.generate(5, cfg)
    assert again["events"][:50] == wl["events"][:50] and again["labels"] == wl["labels"]
    assert workload.generate(6, cfg)["events"][:5] != wl["events"][:5]
    t = [parse_ts(e["event_time"]) for e in wl["events"]]
    assert t == sorted(t)


def test_incidents_stay_whole_inside_one_split(wl):
    sp = {k: parse_ts(wl["split"][k]) for k in ("t0", "train_end", "dev_end", "test_end")}
    for lab in wl["labels"]:
        on, end = parse_ts(lab["onset"]), parse_ts(lab["end"])
        side = [sp["t0"] <= on < sp["train_end"], sp["train_end"] <= on < sp["dev_end"], sp["dev_end"] <= on < sp["test_end"]]
        assert side[1] or side[2], "no incident in the training split (training is normal activity only)"
        bounds = (sp["train_end"], sp["dev_end"]) if side[1] else (sp["dev_end"], sp["test_end"])
        assert bounds[0] <= on and end < bounds[1]


def test_month_end_bursts_exist_in_dev_and_test_but_not_train(wl):
    days = {}
    for e in wl["events"]:
        d = (parse_ts(e["event_time"]) - parse_ts(wl["split"]["t0"])).days
        days[d] = days.get(d, 0) + 1
    burst, normal = [days[d] for d in wl["split"]["burst_days"]], [v for d, v in days.items() if d not in wl["split"]["burst_days"] and d % 7 < 5]
    assert min(burst) > 1.5 * float(np.median(normal))
    assert all(d >= 7 for d in wl["split"]["burst_days"])


def test_feature_names_cannot_look_like_labels():
    assert_features_safe(FEATURES)
    for bad in ("incident_id", "is_attack", "scenario_kind", "label", "anomaly_flag"):
        with pytest.raises(ValueError):
            assert_features_safe([*FEATURES, bad])


def test_features_use_only_information_available_at_decision_time(tmp_path, wl):
    p = tmp_path / "e.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in wl["events"][:3000]))
    events = load_events(p)
    n = 1500
    full = build_matrix(events, 300.0)
    prefix = build_matrix(events[:n], 300.0)
    assert np.array_equal(full[:n], prefix)  # adding LATER events never changes earlier rows


def test_feature_builder_window_hand_example():
    fb = FeatureBuilder(window_s=300)
    t0 = parse_ts("2026-03-02T10:00:00Z")
    rows = [fb.push("p", "tenant-a", op, dec, t0 + timedelta(seconds=s), t0 + timedelta(seconds=s))
            for s, op, dec in [(0, "read_order", "allow"), (60, "export_report", "deny"), (120, "export_report", "allow"), (500, "read_order", "allow")]]
    i = {n: k for k, n in enumerate(FEATURES)}
    assert rows[2][i["n_req"]] == 3 and rows[2][i["n_deny"]] == 1 and rows[2][i["n_export"]] == 2
    assert rows[3][i["n_req"]] == 1  # first three fell out of the 300 s window


def test_rule_detector_reports_which_limit_was_crossed():
    r = RuleDetector({"deny_per_window": 5, "export_per_window": 10, "requests_per_window": 60, "tenant_hops": 2})
    x = np.zeros((2, len(FEATURES)))
    x[1, FEATURES.index("n_deny")] = 6
    assert list(r.alerts(x)) == [False, True] and r.reasons(x[1]) == ["n_deny=6 >= 5"]


def test_isolation_detector_is_seeded_and_fitted_on_normal_only():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(400, len(FEATURES)))
    a, b = IsolationDetector(3).fit(X), IsolationDetector(3).fit(X)
    assert np.array_equal(a.score(X), b.score(X))
    outlier = np.full((1, len(FEATURES)), 12.0)
    assert a.score(outlier)[0] > np.median(a.score(X))
    with pytest.raises(ValueError):
        IsolationDetector(1).fit(X[:5])


def test_threshold_is_chosen_from_development_normal_scores_only():
    scores = np.arange(1000, dtype=float)
    is_inc = np.zeros(1000, dtype=bool)
    is_inc[990:] = True  # incident events (high scores) must not influence calibration
    thr = select_threshold(scores, is_inc, target_rate=0.01)
    assert thr == 990 - 9 or 980 <= thr <= 990
    assert np.sum(scores[~is_inc] >= thr) <= 11
    with pytest.raises(ValueError):
        select_threshold(scores, np.ones(1000, dtype=bool), 0.01)
