from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from resilient_mis import metrics as m

T = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)


def at(minutes: float) -> datetime:
    return T + timedelta(minutes=minutes)


def test_zero_denominators_are_undefined_not_zero():
    assert m.ratio(1, 0) is None and m.wilson(0, 0) is None and m.percentile([], 50) is None
    assert m.prf(0, 0, 0) == {"precision": None, "recall": None, "f1": None}
    assert m.event_metrics([], [])["precision"] is None
    assert m.availability(0, [], 0.25)["availability"] is None
    assert m.paired_overhead([], [])["rel_change_p50"] is None


def test_wilson_hand_calculation():
    lo, hi = m.wilson(5, 10)
    assert (round(lo, 4), round(hi, 4)) == (0.2366, 0.7634)
    lo, hi = m.wilson(0, 10)
    assert lo == 0.0 and round(hi, 4) == 0.2775
    lo, hi = m.wilson(10, 10)
    assert hi == pytest.approx(1.0) and round(lo, 4) == 0.7225


def test_percentile_linear_interpolation():
    xs = [1, 2, 3, 4]
    assert m.percentile(xs, 50) == 2.5 and m.percentile(xs, 0) == 1 and m.percentile(xs, 100) == 4
    assert m.percentile([7], 95) == 7
    assert m.percentile(list(range(1, 101)), 95) == pytest.approx(95.05)


def test_prf_hand_example():
    r = m.prf(tp=6, fp=2, fn=4)
    assert r["precision"] == 0.75 and r["recall"] == 0.6 and r["f1"] == pytest.approx(2 * 0.75 * 0.6 / 1.35)


def test_event_metrics_counts():
    pos = [True, True, False, False, True]
    alert = [True, False, True, False, True]
    e = m.event_metrics(pos, alert)
    assert (e["tp"], e["fp"], e["fn"], e["tn"]) == (2, 1, 1, 1)


def test_alert_groups_merge_by_principal_and_gap():
    alerts = [("a", at(0)), ("a", at(5)), ("a", at(20)), ("b", at(1))]
    g = m.alert_groups(alerts, merge_s=600)
    assert [(x["principal"], x["n_alerts"]) for x in g] == [("a", 2), ("b", 1), ("a", 1)]


def test_incident_metrics_hand_example():
    inc = [{"incident_id": "I1", "principal": "a", "onset": at(0), "end": at(10)},
           {"incident_id": "I2", "principal": "b", "onset": at(30), "end": at(40)},
           {"incident_id": "I3", "principal": "c", "onset": at(60), "end": at(70)}]
    groups = [{"principal": "a", "start": at(2), "end": at(3), "n_alerts": 2},     # TP for I1
              {"principal": "a", "start": at(5), "end": at(6), "n_alerts": 1},     # duplicate inside I1
              {"principal": "b", "start": at(45), "end": at(46), "n_alerts": 1},   # inside end + 10 min grace -> TP for I2
              {"principal": "z", "start": at(15), "end": at(16), "n_alerts": 3},   # false alert
              {"principal": "c", "start": at(95), "end": at(96), "n_alerts": 1}]   # after grace -> false alert; I3 missed
    r = m.incident_metrics(inc, groups, grace_s=600, monitored_hours=10)
    assert (r["eligible_incidents"], r["detected"], r["false_alert_groups"], r["duplicate_groups"]) == (3, 2, 2, 1)
    assert r["missed"] == ["I3"] and r["recall"] == pytest.approx(2 / 3) and r["precision"] == 0.5
    assert r["false_alerts_per_hour"] == 0.2 and r["detection_delays_s"] == [120.0, 900.0]


def test_incident_metrics_no_incidents_gives_undefined_recall_but_counts_false_alerts():
    r = m.incident_metrics([], [{"principal": "a", "start": at(0), "end": at(1), "n_alerts": 1}], 600, 2.0)
    assert r["recall"] is None and r["false_alert_groups"] == 1 and r["false_alerts_per_hour"] == 0.5 and r["precision"] == 0.0


def test_one_group_matches_at_most_one_incident():
    inc = [{"incident_id": "I1", "principal": "a", "onset": at(0), "end": at(10)}, {"incident_id": "I2", "principal": "a", "onset": at(5), "end": at(20)}]
    r = m.incident_metrics(inc, [{"principal": "a", "start": at(7), "end": at(8), "n_alerts": 1}], 0, 1.0)
    assert r["detected"] == 1 and r["missed"] == ["I2"]


def test_availability_counts_missing_probe_records_as_failures():
    recs = [{"ok": True}] * 7 + [{"ok": False}] * 1
    a = m.availability(scheduled=10, records=recs, cadence_s=0.5)
    assert (a["successful"], a["missing"], a["availability"]) == (7, 2, 0.7)
    assert a["estimated_healthy_s"] == 3.5 and a["observed_s"] == 5.0


def test_paired_overhead_denominator_is_baseline():
    o = m.paired_overhead([10, 10, 10], [15, 15, 15])
    assert o["abs_change_p50"] == 5 and o["rel_change_p50"] == 0.5
    z = m.paired_overhead([0, 0], [1, 1])
    assert z["rel_change_p50"] is None  # zero baseline: undefined, not infinite
