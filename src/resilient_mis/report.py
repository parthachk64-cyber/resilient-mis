"""Build results.md, figures and machine-readable metrics from SAVED trial records only (no re-running of experiments)."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from resilient_mis import metrics  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
BLUE, ORANGE, GREEN, GREY, RED = "#1b6ca8", "#c4511d", "#2a7f3f", "#888888", "#b22222"


def _f(x: Any, n: int = 3) -> str:
    return "undefined" if x is None else (f"{x:.{n}f}" if isinstance(x, float) else str(x))


def _ci(t: tuple[float, float] | None) -> str:
    return "n/a" if t is None else f"[{t[0]:.3f}, {t[1]:.3f}]"


def _load(run: Path) -> dict[str, Any]:
    det = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((run / "detection").glob("trial-*.json"))]
    rec = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((run / "recovery").glob("trial-*.json"))]
    probes = [json.loads(line) for line in (run / "probes" / "probes.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()] if (run / "probes" / "probes.jsonl").exists() else []
    lat_path = run / "latency" / "samples.json"
    lat = json.loads(lat_path.read_text(encoding="utf-8")) if lat_path.exists() else None
    return {"manifest": json.loads((run / "manifest.json").read_text(encoding="utf-8")), "detection": det, "recovery": rec, "probes": probes, "latency": lat}


def _bootstrap_ci(values: list[float], seed: int = 5, n: int = 2000) -> tuple[float, float] | None:
    if len(values) < 2:
        return None
    rng = np.random.default_rng(seed)
    means = [float(np.mean(rng.choice(values, len(values)))) for _ in range(n)]
    return float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def detection_summary(trials: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"trials": len(trials)}
    for det in ("rules", "iforest"):
        rows = [t["detectors"][det] for t in trials]
        elig, tp = sum(r["eligible_incidents"] for r in rows), sum(r["detected"] for r in rows)
        fp, hours = sum(r["false_alert_groups"] for r in rows), sum(r["monitored_hours"] for r in rows)
        ev = {k: sum(r["event"][k] for r in rows) for k in ("tp", "fp", "fn", "tn")}
        per_trial = [r["recall"] for r in rows if r["recall"] is not None]
        delays = [d for r in rows for d in r["detection_delays_s"]]
        kinds: dict[str, Any] = {}
        for kind in rows[0]["recall_by_kind"] if rows else []:
            n_k = sum(t["incidents"]["by_kind_test"][kind] for t in trials)
            hit = sum(round((r["recall_by_kind"][kind] or 0) * t["incidents"]["by_kind_test"][kind]) for r, t in zip(rows, trials))
            kinds[kind] = {"detected": hit, "eligible": n_k, "recall": metrics.ratio(hit, n_k)}
        out[det] = {"eligible_incidents": elig, "detected": tp, "recall": metrics.ratio(tp, elig), "recall_wilson95_pooled": metrics.wilson(tp, elig),
                    "recall_per_trial_mean": float(np.mean(per_trial)) if per_trial else None, "recall_per_trial_bootstrap95": _bootstrap_ci(per_trial),
                    "recall_per_trial_min_max": [min(per_trial), max(per_trial)] if per_trial else None, "false_alert_groups": fp, "monitored_hours": hours,
                    "false_alerts_per_hour": metrics.ratio(fp, hours), "precision": metrics.ratio(tp, tp + fp), "event": {**ev, **metrics.prf(ev["tp"], ev["fp"], ev["fn"])},
                    "median_delay_s": metrics.percentile(delays, 50), "missed_incidents": elig - tp, "recall_by_kind": kinds}
    return out


def recovery_summary(trials: list[dict[str, Any]]) -> dict[str, Any]:
    def grp(rows: list[dict[str, Any]]) -> dict[str, Any]:
        ok = [r for r in rows if r["ready"]]
        f2r = [r["durations"]["fault_to_ready_s"] for r in ok]
        s2r = [r["durations"]["restore_start_to_ready_s"] for r in ok]
        av = [r["availability"] for r in rows]
        sched, succ = sum(a["scheduled"] for a in av), sum(a["successful"] for a in av)
        per = [a["availability"] for a in av if a["availability"] is not None]
        return {"trials": len(rows), "ready": len(ok), "failed_or_timeout": len(rows) - len(ok), "fault_to_ready_s_each": f2r, "restore_start_to_ready_s_each": s2r,
                "fault_to_ready_median_s": metrics.percentile(f2r, 50), "restore_start_to_ready_median_s": metrics.percentile(s2r, 50),
                "fault_to_ready_p95_s": metrics.percentile(f2r, 95) if len(f2r) >= 20 else None, "min_max_fault_to_ready_s": [min(f2r), max(f2r)] if f2r else None,
                "snapshot_bytes": sorted({r["snapshot_bytes"] for r in rows}), "lost_confirmed_writes_each": [r["lost_confirmed_writes"] for r in rows],
                "availability_pooled": metrics.ratio(succ, sched), "availability_wilson95_pooled": metrics.wilson(succ, sched), "scheduled": sched, "successful": succ,
                "missing_records": sum(a["missing"] for a in av), "availability_per_trial": per, "availability_min_median_max": [min(per), float(np.median(per)), max(per)] if per else None,
                "observed_s_each": [r["probe_window"]["observation_s"] for r in rows],
                "phase_medians_s": {k: metrics.percentile([r["durations"][k] for r in ok if r["durations"][k] is not None], 50) for k in
                                    ("fault_to_detected_s", "manifest_verification_s", "decrypt_and_verify_s", "journal_replay_s", "cutover_s", "cutover_to_ready_s")}}

    return {"with_journal": grp([t for t in trials if t["with_journal"]]), "snapshot_only": grp([t for t in trials if not t["with_journal"]]) if any(not t["with_journal"] for t in trials) else None}


def latency_summary(lat: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"ops": {}}
    for op, by in lat["samples_ms"].items():
        full, base = by["full"], by["baseline_all_off"]
        per_control = {name: metrics.paired_overhead(by[name], full) for name in by if name not in ("full", "baseline_all_off")}
        pair = [f - b for f, b in zip(full, base)]
        out["ops"][op] = {"full_vs_baseline": metrics.paired_overhead(base, full), "paired_diff_ms_p50": metrics.percentile(pair, 50),
                          "paired_diff_ms_p95": metrics.percentile(pair, 95), "cost_of_control_vs_full": per_control, "n": len(full)}
    s = lat["snapshot_samples_ms"]
    out["snapshot"] = metrics.paired_overhead(s["baseline"], s["protected"])
    k = lat["first_use_key_load_ms"]
    out["first_use_key_load"] = {"cold_p50_ms": metrics.percentile(k["cold_first_read"], 50), "warm_p50_ms": metrics.percentile(k["warm_second_read"], 50), "n": len(k["cold_first_read"])}
    return out


# ---------------------------------------------------------------------------------------------------------------------- figures
def _save_csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def fig_detection(trials: list[dict[str, Any]], out: Path) -> Path:
    q = [c["quantile"] for c in trials[0]["iforest_curve"]]
    rows = []
    for k, qq in enumerate(q):
        pts = [t["iforest_curve"][k] for t in trials]
        rows.append([qq, float(np.mean([p["false_alerts_per_hour"] for p in pts])), float(np.mean([p["recall"] if p["recall"] is not None else 0 for p in pts]))])
    s = detection_summary(trials)
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    ax.plot([r[1] for r in rows], [r[2] for r in rows], "-o", ms=3, color=ORANGE, label="Isolation Forest, threshold sweep (mean over trials)")
    for det, col, mk in (("iforest", ORANGE, "s"), ("rules", BLUE, "D")):
        ax.scatter([s[det]["false_alerts_per_hour"]], [s[det]["recall"]], s=70, color=col, marker=mk, edgecolor="k", zorder=5, label=f"{det} operating point (pooled)")
    ax.set_xlabel("false alert groups per monitored hour (test split)"), ax.set_ylabel("incident recall (detected / eligible)")
    ax.set_ylim(-0.02, 1.02), ax.set_title(f"Detection versus false-alert burden, {len(trials)} synthetic trials", fontsize=9), ax.legend(fontsize=7)
    p = out / "fig_detection_vs_false_alerts.png"
    fig.savefig(p, dpi=150, bbox_inches="tight"), plt.close(fig)
    _save_csv(out / "fig_detection_vs_false_alerts.csv", ["dev_quantile", "mean_false_alerts_per_hour", "mean_recall"], rows)
    return p


def fig_availability(trials: list[dict[str, Any]], probes: list[dict[str, Any]], out: Path, bin_s: float = 0.25) -> Path:
    jt = {t["trial"]: t for t in trials if t["with_journal"]}
    edges = np.arange(-2.0, 8.0 + bin_s, bin_s)
    ok_sum, n_sum = np.zeros(len(edges) - 1), np.zeros(len(edges) - 1)
    ready_rel = []
    for p in probes:
        t = jt.get(p["trial"])
        if t is None:
            continue
        rel = p["scheduled_s"] - t["timeline_s"]["fault_onset"]
        i = int(np.searchsorted(edges, rel, side="right") - 1)
        if 0 <= i < len(ok_sum):
            n_sum[i] += 1
            ok_sum[i] += 1 if p["ok"] else 0
    for t in jt.values():
        if t["ready"]:
            ready_rel.append(t["timeline_s"]["ready"] - t["timeline_s"]["fault_onset"])
    frac = np.divide(ok_sum, n_sum, out=np.full_like(ok_sum, np.nan), where=n_sum > 0)
    fig, ax = plt.subplots(figsize=(7, 3.8))
    ax.step(edges[:-1], frac, where="post", color=BLUE)
    ax.axvline(0, color=RED, ls="--", label="fault onset")
    if ready_rel:
        ax.axvline(float(np.median(ready_rel)), color=GREEN, ls="--", label="median verified-ready")
    ax.set_xlabel("seconds from fault onset"), ax.set_ylabel("share of scheduled probes that succeeded"), ax.set_ylim(-0.02, 1.05)
    ax.set_title("Business-probe success across the fault window (journal trials, all probes pooled)", fontsize=9), ax.legend(fontsize=7)
    p = out / "fig_availability_over_fault_window.png"
    fig.savefig(p, dpi=150, bbox_inches="tight"), plt.close(fig)
    _save_csv(out / "fig_availability_over_fault_window.csv", ["bin_start_s_from_fault", "scheduled", "successful"], [[float(e), int(n), int(k)] for e, n, k in zip(edges[:-1], n_sum, ok_sum)])
    return p


def fig_phases(trials: list[dict[str, Any]], out: Path) -> Path:
    keys = ["fault_to_detected_s", "detected_to_restore_start_s", "manifest_verification_s", "decrypt_and_verify_s", "journal_replay_s", "cutover_s", "cutover_to_ready_s"]
    cols = [GREY, "#bbbbbb", BLUE, ORANGE, "#d9a441", RED, GREEN]
    rows = [t for t in trials if t["ready"]]
    fig, ax = plt.subplots(figsize=(7.5, 4))
    bottom = np.zeros(len(rows))
    for k, c in zip(keys, cols):
        v = np.array([r["durations"][k] or 0.0 for r in rows])
        ax.bar(range(len(rows)), v, bottom=bottom, color=c, label=k.replace("_s", "").replace("_", " "))
        bottom += v
    ax.set_xticks(range(len(rows))), ax.set_xticklabels([r["trial"].replace("recovery-", "t") + ("" if r["with_journal"] else "*") for r in rows], fontsize=7)
    ax.set_ylabel("seconds from fault onset"), ax.set_title("Recovery phases per trial (* = snapshot only, no journal)", fontsize=9), ax.legend(fontsize=6, ncol=2)
    p = out / "fig_recovery_phase_durations.png"
    fig.savefig(p, dpi=150, bbox_inches="tight"), plt.close(fig)
    _save_csv(out / "fig_recovery_phase_durations.csv", ["trial", "with_journal", *keys], [[r["trial"], r["with_journal"], *[r["durations"][k] for k in keys]] for r in rows])
    return p


def fig_latency(lat: dict[str, Any], out: Path) -> Path:
    fig, axes = plt.subplots(1, 3, figsize=(11, 3.8))
    rows: list[list[Any]] = []
    for ax, (op, by) in zip(axes, lat["samples_ms"].items()):
        names = list(by)
        ax.boxplot([by[n] for n in names], showfliers=False, orientation="horizontal"), ax.set_yticks(range(1, len(names) + 1)), ax.set_yticklabels(names, fontsize=6)
        ax.set_xlabel("milliseconds per call"), ax.set_title(op, fontsize=9)
        rows += [[op, n, v] for n in names for v in by[n]]
    fig.suptitle("Paired latency distributions (interleaved, matched local fixtures)", fontsize=9)
    p = out / "fig_paired_latency_distributions.png"
    fig.savefig(p, dpi=150, bbox_inches="tight"), plt.close(fig)
    _save_csv(out / "fig_paired_latency_distributions.csv", ["operation", "profile", "ms"], rows)
    return p


# ---------------------------------------------------------------------------------------------------------------------- markdown
def build(run: Path, out_md: Path, fig_dir: Path | None = None) -> Path:
    run = Path(run)
    d = _load(run)
    for part in ("detection", "recovery"):
        if not d[part]:
            raise ValueError(f"no saved {part} trial records under {run}; the report is built only from saved records and will not run experiments")
    if not any(t["with_journal"] for t in d["recovery"]):
        raise ValueError("no saved snapshot+journal recovery trials to report")
    rid = d["manifest"]["run_id"]
    fig_dir = Path(fig_dir) if fig_dir else out_md.parent / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    ds, rs, ls = detection_summary(d["detection"]), recovery_summary(d["recovery"]), latency_summary(d["latency"]) if d["latency"] else None
    summary = {"run_id": rid, "detection": ds, "recovery": rs, "latency": ls}
    (run / "metrics.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    figs = [fig_detection(d["detection"], fig_dir), fig_availability(d["recovery"], d["probes"], fig_dir), fig_phases(d["recovery"], fig_dir)]
    if d["latency"]:
        figs.append(fig_latency(d["latency"], fig_dir))
    m = d["manifest"]
    L = ["# Results", "",
         "Three origins are kept apart. **Section A is what the chapter publicly states (not measured here). Sections B and C were measured by this repository on invented data on one laptop.** "
         "Nothing in C is a reproduction of the chapter's experiment, and none of it is evidence of enterprise or cloud performance.", "",
         "## A. Chapter-reported (Ansar et al., ICICC 2026, LNNS 2037, pp. 317-331, DOI 10.1007/978-3-032-30008-9_24)", "",
         "The full chapter was not supplied and the Springer page redirected to a login, so only the public-abstract claims below are recorded, with their qualifiers intact "
         "(`references/reported/chapter_claims.csv`). Definitions, data, hardware and trial counts are NOT established.", "",
         "| Claim | As published | Value status | Not established |", "|---|---|---|---|"]
    for r in csv.DictReader(open(REPO_ROOT / "references" / "reported" / "chapter_claims.csv", encoding="utf-8")):
        L.append(f"| {r['published_claim']} | {r['qualifier_preserved']} | {r['value_status']} | {r['what_is_not_established']} |")
    L += ["", "## B. Independent measurement on a named external dataset", "", "**Not run.** No authorised external dataset was supplied. The importer accepts one (`resilient-mis data-validate`); see `docs/data.md`.", "",
          f"## C. Local synthetic measurements (run `{rid}`)", "",
          f"Environment: {m['platform']}, Python {m['python']}, cryptography {m['cryptography']}, scikit-learn {m['scikit_learn']}, RSA-{m['rsa_bits']}, commit `{m['git_commit'][:12]}`, "
          f"config sha256 `{m['config_sha256'][:12]}`. {m['scope_note']}.", ""]
    # C1 detection
    L += ["### C1. Detection (chapter claim: \"over 93%\", definition unverified)", "",
          f"Dataset: synthetic telemetry, {ds['trials']} independent trials (workload seeds), chronological train/dev/test split, incidents kept whole inside one split, normal month-end bursts in dev and test. "
          "Unit = labelled incident. **Incident recall = detected incidents / eligible labelled incidents**; an alert group matches an incident if same principal and it starts between onset and end + grace; at most one true positive per incident; "
          "groups inside an already-detected incident are duplicates (neither TP nor false alert). Never overall accuracy. Zero denominators print `undefined`.", "",
          "| Detector | Eligible incidents | Detected | Recall (pooled) | Wilson 95% | Per-trial recall mean [bootstrap 95%] | Per-trial min..max | False alert groups | Monitored h | False alerts / h | Precision | Median delay (s) |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for det, label in (("rules", "fixed rules (comparator)"), ("iforest", "Isolation Forest (seeded)")):
        x = ds[det]
        L.append(f"| {label} | {x['eligible_incidents']} | {x['detected']} | {_f(x['recall'])} | {_ci(x['recall_wilson95_pooled'])} | {_f(x['recall_per_trial_mean'])} {_ci(x['recall_per_trial_bootstrap95'])} | "
                 f"{_f(x['recall_per_trial_min_max'][0]) + '..' + _f(x['recall_per_trial_min_max'][1]) if x['recall_per_trial_min_max'] else 'n/a'} | {x['false_alert_groups']} | {x['monitored_hours']:.0f} | "
                 f"{_f(x['false_alerts_per_hour'], 4)} | {_f(x['precision'])} | {_f(x['median_delay_s'], 0)} |")
    L += ["", "Recall by incident kind (detected / eligible, pooled over trials) shows which behaviours are missed:", "", "| Kind | rules | Isolation Forest |", "|---|---|---|"]
    for k in ds["rules"]["recall_by_kind"]:
        a, b = ds["rules"]["recall_by_kind"][k], ds["iforest"]["recall_by_kind"][k]
        L.append(f"| {k} | {a['detected']}/{a['eligible']} | {b['detected']}/{b['eligible']} |")
    L += ["", "Event-level (separate from incident-level): an event is positive when its principal is inside a labelled incident interval.", "",
          "| Detector | TP | FP | FN | TN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|---|"]
    for det in ("rules", "iforest"):
        e = ds[det]["event"]
        L.append(f"| {det} | {e['tp']} | {e['fp']} | {e['fn']} | {e['tn']} | {_f(e['precision'])} | {_f(e['recall'])} | {_f(e['f1'])} |")
    L += ["", "Limitations: the incident generator and the rule thresholds were written by the same author, so rule recall on this synthetic workload says little about real traffic; "
          "the Isolation Forest threshold is calibrated on development data to match the rules' development false-alert rate (equal budget, not tuned for recall). A comparison with the chapter's detector is impossible: its estimator and data are unknown.", "",
          f"Figure: `{figs[0].name}` (data: `{figs[0].with_suffix('.csv').name}`).", ""]
    # C2 recovery
    j, so = rs["with_journal"], rs["snapshot_only"]
    L += ["### C2. Recovery time (chapter claim: \"under 22 seconds\", start/stop definition unverified)", "",
          "Definition used here: **fault-to-ready** = monotonic time from fault onset (store file deleted or corrupted in a disposable fixture) to the first moment the authorised manager receives the CORRECT report, "
          "the revoked analyst is STILL denied and a NEW valid write commits. **Restore-start-to-ready** excludes detection delay. A restart or successful decryption alone does not stop the timer. "
          "Failed trials are counted, never excluded. No duration is hard-coded and nothing here asserts the chapter's limit as a pass criterion.", "",
          "| Configuration | Trials | Ready | Failed / timeout | Fault-to-ready each (s) | Median fault-to-ready (s) | Median restore-start-to-ready (s) | p95 | Lost confirmed writes (each) | Snapshot bytes |", "|---|---|---|---|---|---|---|---|---|---|"]
    for name, g in (("snapshot + journal", j), ("snapshot only (no journal)", so)):
        if g:
            L.append(f"| {name} | {g['trials']} | {g['ready']} | {g['failed_or_timeout']} | {', '.join(f'{v:.2f}' for v in g['fault_to_ready_s_each'])} | {_f(g['fault_to_ready_median_s'], 2)} | "
                     f"{_f(g['restore_start_to_ready_median_s'], 2)} | {'n<20: not reported' if g['fault_to_ready_p95_s'] is None else _f(g['fault_to_ready_p95_s'], 2)} | {g['lost_confirmed_writes_each']} | {g['snapshot_bytes']} |")
    L += ["", "Median phase durations, journal trials (s): " + ", ".join(f"{k.replace('_s', '')}={_f(v, 3)}" for k, v in j["phase_medians_s"].items()) + ". "
          "Key availability: private wrapping keys were present in every trial; key loss is a refusal case covered by tests, not a timed scenario. Storage: local file system with SQLite `synchronous=FULL`.", "",
          "Limitations: tiny store (a few dozen records), warm in-process key cache, single machine, fault injection limited to deleting or overwriting one file. These times say nothing about a 22 second claim at enterprise scale.", "",
          f"Figure: `{figs[2].name}`.", ""]
    # C3 availability
    L += ["### C3. Availability (chapter claim: \"up to 99%\", observation window unverified)", "",
          "Probe = authorised manager reads the departmental report; success = report equals the client ledger's expected value within the deadline. Intentional access denials are NOT outages (tested separately). "
          "Scheduled probes with no record count as failures. Observation window = each trial's probe run (see the observed seconds in `metrics.json`; one fault per trial). **This is availability during a deliberately injected fault, not an annual uptime figure.**", "",
          "| Configuration | Scheduled | Successful | Missing records | Availability (pooled) | Wilson 95% | Per-trial min / median / max | Cadence / deadline |", "|---|---|---|---|---|---|---|---|"]
    pc = d["recovery"][0]["probe_window"] if d["recovery"] else {"cadence_s": "?", "deadline_s": "?"}
    for name, g in (("snapshot + journal", j), ("snapshot only", so)):
        if g:
            mm = g["availability_min_median_max"]
            L.append(f"| {name} | {g['scheduled']} | {g['successful']} | {g['missing_records']} | {_f(g['availability_pooled'], 4)} | {_ci(g['availability_wilson95_pooled'])} | "
                     f"{'/'.join(_f(v, 3) for v in mm) if mm else 'n/a'} | {pc['cadence_s']} s / {pc['deadline_s']} s |")
    L += ["", "A best trial cannot support an uptime promise; the per-trial spread is shown for that reason. The Wilson interval treats probes as independent, which they are not (outage probes are consecutive), so it is optimistic.", "",
          f"Figure: `{figs[1].name}`.", ""]
    # C4 latency
    if ls:
        L += ["### C4. Latency overhead (chapter: \"moderate\", no number)", "",
              f"Paired, interleaved timings on matched fixtures, {ls['ops']['read']['n']} repetitions per operation and profile, concurrency 1, {d['latency']['orders_per_department']} orders per department. "
              "Timer = `perf_counter_ns` around the service call; it INCLUDES authorization, encryption/decryption, telemetry write and journal fsync when enabled, and EXCLUDES session setup and first-use key loading (reported separately). "
              "Relative change denominator = the baseline percentile. Reduced-protection profiles exist only in the benchmark harness and cannot serve requests.", "",
              "| Operation | Baseline p50 / p95 (ms) | Protected p50 / p95 (ms) | Absolute change p50 / p95 (ms) | Relative change p50 / p95 |", "|---|---|---|---|---|"]
        for op, x in ls["ops"].items():
            o = x["full_vs_baseline"]
            L.append(f"| {op} | {_f(o['baseline_p50'], 2)} / {_f(o['baseline_p95'], 2)} | {_f(o['protected_p50'], 2)} / {_f(o['protected_p95'], 2)} | {_f(o['abs_change_p50'], 2)} / {_f(o['abs_change_p95'], 2)} | "
                     f"{_f(None if o['rel_change_p50'] is None else o['rel_change_p50'] * 100, 0)}% / {_f(None if o['rel_change_p95'] is None else o['rel_change_p95'] * 100, 0)}% |")
        s = ls["snapshot"]
        L.append(f"| snapshot (protected = backup + verify + encrypt + sign; baseline = SQLite backup only), n={s['n_baseline']} | {_f(s['baseline_p50'], 2)} / {_f(s['baseline_p95'], 2)} | {_f(s['protected_p50'], 2)} / {_f(s['protected_p95'], 2)} | "
                 f"{_f(s['abs_change_p50'], 2)} / {_f(s['abs_change_p95'], 2)} | {_f(None if s['rel_change_p50'] is None else s['rel_change_p50'] * 100, 0)}% / {_f(None if s['rel_change_p95'] is None else s['rel_change_p95'] * 100, 0)}% |")
        k = ls["first_use_key_load"]
        L += ["", f"First-use key loading (read, p50, n={k['n']}): cold {_f(k['cold_p50_ms'], 2)} ms versus warm {_f(k['warm_p50_ms'], 2)} ms.", "",
              "Which control costs what (p50 ms the full profile pays over the profile with that one control OFF; positive = the control adds time):", "",
              "| Operation | no_encryption | no_authorization | no_telemetry | no_journal |", "|---|---|---|---|---|"]
        for op, x in ls["ops"].items():
            c = x["cost_of_control_vs_full"]
            L.append(f"| {op} | " + " | ".join(_f(c[n]["abs_change_p50"], 2) for n in ("no_encryption", "no_authorization", "no_telemetry", "no_journal")) + " |")
        L += ["", "The finding is reported as measured even where overhead is large in relative terms: the baseline is an unprotected in-process SQLite call, so percentages are large while absolute times stay small. "
              f"Figure: `{figs[3].name}`.", ""]
    L += ["## Provenance", "", f"All numbers above are computed by `resilient-mis report-build` from the saved per-trial records in `runs/{rid}/` (`detection/`, `recovery/`, `probes/probes.jsonl`, `latency/samples.json`). "
          f"Machine-readable summary: `runs/{rid}/metrics.json`; figure data: `docs/figures/*.csv`.", ""]
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out_md
