# Data

## What the chapter used

**Unverified.** The chapter's benchmark data, workload, hardware, comparison systems and trial counts are not in the public abstract, and the full text was not supplied (the Springer page redirects to a login for an unauthenticated client). Nothing in this repository attributes an algorithm or dataset to the chapter.

If you have licensed access, record here what the full text states and how the data can be obtained, then run it through the importer below.

## Source registry

| ID | File | Provider / URL | Access | Version | Rows | Time span | Labels | Split | Checksum | Provenance |
|---|---|---|---|---|---|---|---|---|---|---|
| D0 | `workload.generate(seed)` output (`events.jsonl`, `labels.jsonl`, `split.json`) | this repository, `src/resilient_mis/workload.py` | none, generated locally | package 0.1.0 | depends on config; per-seed counts are in `runs/<id>/detection/trial-*.json` under `events` | 30 simulated days from 2026-03-02T00:00Z | separate file `labels.jsonl`: incident id, kind, principal, onset, end | chronological: 12 train / 6 dev / 12 test days; incidents whole inside one split | `runs/<id>/detection/trial-*.json` records seed and split; regenerate with the same seed to reproduce | **invented**; no real traffic, people or organisations |
| D1 | purchase-order fixtures from `scenario.populate` | this repository | none | package 0.1.0 | about 30 records, two tenants | n/a | n/a | n/a | rebuilt per run | **invented** vendors (public placeholder names) and amounts |
| D2 | `src/resilient_mis/data/invalid_snapshot/*` | this repository | none | fixed bytes | 1 snapshot | n/a | n/a | n/a | `store.db.enc` sha256 is in its manifest | fixed invalid fixture signed by a throwaway key |
| D3 | any authorised telemetry export you supply | yours | yours | yours | yours | yours | yours (keep separate) | you choose chronological boundaries | record `sha256sum` here | yours |

No external dataset was used for any reported number.

## Importing an authorised, de-identified export

Format: CSV (header row) or JSONL, one event per row. Required columns:

| Column | Meaning |
|---|---|
| `event_time` | ISO 8601 with UTC offset, when the operation happened |
| `arrival_time` | ISO 8601 with UTC offset, when the event reached the detector (not earlier than `event_time`); replay is in this order |
| `principal` | pseudonymous id, never a name, e-mail or token |
| `tenant` | tenant id |
| `operation` | one of `read_order, spending_report, create_order, update_order, export_report, validate_restore, restore, checkpoint` |
| `decision` | `allow`, `deny` or `error` |
| `correlation_id` | unique per event |

Columns whose names look like labels, scenarios, secrets or business values (`label`, `incident`, `scenario`, `attack`, `anomal*`, `token`, `secret`, `password`, `plaintext`, `key`, `amount`, `record_id`) are REJECTED so a label cannot be smuggled in as a feature.

```bash
resilient-mis data-validate --events my_export.csv      # exit 0 = valid, 2 = invalid with row-numbered problems
```

Keep incident annotations in a separate `labels.jsonl` (`incident_id, kind, principal, onset, end, tenant`) that only the evaluation code reads, and a `split.json` with `t0, train_end, dev_end, test_end` UTC timestamps. Use chronological boundaries and keep every incident wholly inside one split. Fit only on earlier normal activity, pick thresholds on the development split, and touch the test split once.

```bash
resilient-mis generate-workload --out work/wl --seed 1          # or supply your own events.jsonl/labels.jsonl/split.json
resilient-mis train  --workload work/wl --run runs/mine --seed 1   # fit on train, calibrate on dev
resilient-mis replay --run runs/mine --events work/wl/events.jsonl --after 2026-03-20T00:00:00Z
```

## Normal month-end reporting bursts

Dev and test each contain burst days where managers and analysts run about 4x the normal request rate, mostly reports and exports, all allowed. They are normal activity and act as the false-alarm control: any alert group that starts there is a false alert.

## What the telemetry contains

pseudonymous principal, tenant, operation, decision, event time, arrival time, correlation id. Never plaintext, keys, tokens, record ids, amounts or labels.
