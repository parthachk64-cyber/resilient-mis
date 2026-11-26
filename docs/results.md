# Results

Three origins are kept apart. **Section A is what the chapter publicly states (not measured here). Sections B and C were measured by this repository on invented data on one laptop.** Nothing in C is a reproduction of the chapter's experiment, and none of it is evidence of enterprise or cloud performance.

## A. Chapter-reported (Ansar et al., ICICC 2026, LNNS 2037, pp. 317-331, DOI 10.1007/978-3-032-30008-9_24)

The full chapter was not supplied and the Springer page redirected to a login, so only the public-abstract claims below are recorded, with their qualifiers intact (`references/reported/chapter_claims.csv`). Definitions, data, hardware and trial counts are NOT established.

| Claim | As published | Value status | Not established |
|---|---|---|---|
| detection rate | over 93% | sourced-qualitative-bound | unit, definition, estimator, dataset, labels, time window and trial count are not in the public preview |
| availability | up to 99% | sourced-upper-bound | observation window, probe cadence, success criterion and uptime definition are not in the public preview; 'up to' is a best case, not a promise |
| recovery time | under 22 seconds | sourced-upper-bound | definition of start and stop, data size, hardware and trial count are not in the public preview |
| latency overhead | moderate (qualitative) | sourced-qualitative | no numeric overhead, baseline, workload or percentile is given |
| techniques | symmetric and asymmetric encryption; role- and context-dependent authorization; continuous anomaly detection; integrity-checked recovery | sourced-qualitative | the cryptographic algorithms, key sizes, anomaly estimator, benchmark data and comparison systems are not in the public preview |

## B. Independent measurement on a named external dataset

**Not run.** No authorised external dataset was supplied. The importer accepts one (`resilient-mis data-validate`); see `docs/data.md`.

## C. Local synthetic measurements (run `demo`)

Environment: Windows-10-10.0.26300-SP0, Python 3.10.11, cryptography 50.0.2, scikit-learn 1.7.2, RSA-3072, commit `023490ea578e`, config sha256 `13db1b9a2b9d`. single laptop, CPU only, local SQLite, synthetic invented data; not enterprise or cloud performance.

### C1. Detection (chapter claim: "over 93%", definition unverified)

Dataset: synthetic telemetry, 10 independent trials (workload seeds), chronological train/dev/test split, incidents kept whole inside one split, normal month-end bursts in dev and test. Unit = labelled incident. **Incident recall = detected incidents / eligible labelled incidents**; an alert group matches an incident if same principal and it starts between onset and end + grace; at most one true positive per incident; groups inside an already-detected incident are duplicates (neither TP nor false alert). Never overall accuracy. Zero denominators print `undefined`.

| Detector | Eligible incidents | Detected | Recall (pooled) | Wilson 95% | Per-trial recall mean [bootstrap 95%] | Per-trial min..max | False alert groups | Monitored h | False alerts / h | Precision | Median delay (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| fixed rules (comparator) | 120 | 104 | 0.867 | [0.794, 0.916] | 0.867 [0.833, 0.900] | 0.833..1.000 | 0 | 2880 | 0.0000 | 1.000 | 51 |
| Isolation Forest (seeded) | 120 | 9 | 0.075 | [0.040, 0.136] | 0.075 [0.000, 0.183] | 0.000..0.417 | 26 | 2880 | 0.0090 | 0.257 | 113 |

Recall by incident kind (detected / eligible, pooled over trials) shows which behaviours are missed:

| Kind | rules | Isolation Forest |
|---|---|---|
| credential_stuffing | 30/30 | 4/30 |
| bulk_export | 30/30 | 0/30 |
| tenant_probe | 30/30 | 5/30 |
| low_and_slow_export | 14/30 | 0/30 |

Event-level (separate from incident-level): an event is positive when its principal is inside a labelled incident interval.

| Detector | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| rules | 5957 | 45 | 1349 | 296518 | 0.993 | 0.815 | 0.895 |
| iforest | 164 | 51 | 7142 | 296512 | 0.763 | 0.022 | 0.044 |

Limitations: the incident generator and the rule thresholds were written by the same author, so rule recall on this synthetic workload says little about real traffic; the Isolation Forest threshold is calibrated on development data to match the rules' development false-alert rate (equal budget, not tuned for recall). A comparison with the chapter's detector is impossible: its estimator and data are unknown.

Figure: `fig_detection_vs_false_alerts.png` (data: `fig_detection_vs_false_alerts.csv`).

### C2. Recovery time (chapter claim: "under 22 seconds", start/stop definition unverified)

Definition used here: **fault-to-ready** = monotonic time from fault onset (store file deleted or corrupted in a disposable fixture) to the first moment the authorised manager receives the CORRECT report, the revoked analyst is STILL denied and a NEW valid write commits. **Restore-start-to-ready** excludes detection delay. A restart or successful decryption alone does not stop the timer. Failed trials are counted, never excluded. No duration is hard-coded and nothing here asserts the chapter's limit as a pass criterion.

| Configuration | Trials | Ready | Failed / timeout | Fault-to-ready each (s) | Median fault-to-ready (s) | Median restore-start-to-ready (s) | p95 | Lost confirmed writes (each) | Snapshot bytes |
|---|---|---|---|---|---|---|---|---|---|
| snapshot + journal | 10 | 10 | 0 | 0.75, 0.83, 0.91, 5.86, 5.84, 0.86, 0.88, 0.97, 0.86, 1.01 | 0.89 | 0.88 | n<20: not reported | [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] | [82579] |
| snapshot only (no journal) | 5 | 5 | 0 | 0.72, 0.64, 0.70, 0.70, 0.59 | 0.70 | 0.69 | n<20: not reported | [2, 2, 2, 2, 2] | [82579] |

Median phase durations, journal trials (s): fault_to_detected=0.015, manifest_verification=0.031, decrypt_and_verify=0.414, journal_replay=0.289, cutover=0.015, cutover_to_ready=0.133. Key availability: private wrapping keys were present in every trial; key loss is a refusal case covered by tests, not a timed scenario. Storage: local file system with SQLite `synchronous=FULL`.

Limitations: tiny store (a few dozen records), warm in-process key cache, single machine, fault injection limited to deleting or overwriting one file. These times say nothing about a 22 second claim at enterprise scale.

Figure: `fig_recovery_phase_durations.png`.

### C3. Availability (chapter claim: "up to 99%", observation window unverified)

Probe = authorised manager reads the departmental report; success = report equals the client ledger's expected value within the deadline. Intentional access denials are NOT outages (tested separately). Scheduled probes with no record count as failures. Observation window = each trial's probe run (see the observed seconds in `metrics.json`; one fault per trial). **This is availability during a deliberately injected fault, not an annual uptime figure.**

| Configuration | Scheduled | Successful | Missing records | Availability (pooled) | Wilson 95% | Per-trial min / median / max | Cadence / deadline |
|---|---|---|---|---|---|---|---|
| snapshot + journal | 367 | 269 | 59 | 0.7330 | [0.685, 0.776] | 0.128/0.931/0.972 | 0.25 s / 1.0 s |
| snapshot only | 182 | 148 | 23 | 0.8132 | [0.750, 0.863] | 0.263/0.944/0.972 | 0.25 s / 1.0 s |

A best trial cannot support an uptime promise; the per-trial spread is shown for that reason. The Wilson interval treats probes as independent, which they are not (outage probes are consecutive), so it is optimistic.

Figure: `fig_availability_over_fault_window.png`.

### C4. Latency overhead (chapter: "moderate", no number)

Paired, interleaved timings on matched fixtures, 200 repetitions per operation and profile, concurrency 1, 12 orders per department. Timer = `perf_counter_ns` around the service call; it INCLUDES authorization, encryption/decryption, telemetry write and journal fsync when enabled, and EXCLUDES session setup and first-use key loading (reported separately). Relative change denominator = the baseline percentile. Reduced-protection profiles exist only in the benchmark harness and cannot serve requests.

| Operation | Baseline p50 / p95 (ms) | Protected p50 / p95 (ms) | Absolute change p50 / p95 (ms) | Relative change p50 / p95 |
|---|---|---|---|---|
| create | 9.92 / 14.52 | 52.03 / 62.28 | 42.11 / 47.76 | 425% / 329% |
| read | 6.17 / 9.46 | 11.86 / 14.86 | 5.69 / 5.41 | 92% / 57% |
| report | 4.97 / 7.12 | 89.83 / 106.30 | 84.85 / 99.18 | 1706% / 1394% |
| snapshot (protected = backup + verify + encrypt + sign; baseline = SQLite backup only), n=20 | 18.69 / 21.92 | 926.80 / 1190.96 | 908.11 / 1169.04 | 4859% / 5334% |

First-use key loading (read, p50, n=40): cold 183.90 ms versus warm 7.10 ms.

Which control costs what (p50 ms the full profile pays over the profile with that one control OFF; positive = the control adds time):

| Operation | no_encryption | no_authorization | no_telemetry | no_journal |
|---|---|---|---|---|
| create | 0.29 | 1.94 | 0.54 | 36.55 |
| read | 5.74 | 2.46 | 2.10 | -3.77 |
| report | 81.24 | 2.83 | 4.19 | 0.97 |

The finding is reported as measured even where overhead is large in relative terms: the baseline is an unprotected in-process SQLite call, so percentages are large while absolute times stay small. Figure: `fig_paired_latency_distributions.png`.

## Provenance

All numbers above are computed by `resilient-mis report-build` from the saved per-trial records in `runs/demo/` (`detection/`, `recovery/`, `probes/probes.jsonl`, `latency/samples.json`). Machine-readable summary: `runs/demo/metrics.json`; figure data: `docs/figures/*.csv`.

