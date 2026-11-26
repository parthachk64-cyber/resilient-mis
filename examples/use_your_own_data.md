# Using your own authorised telemetry

1. Export de-identified events to CSV or JSONL with the columns in `docs/data.md` (pseudonymous principals only).
2. Validate: `resilient-mis data-validate --events my_export.csv` (see `examples/sample_events.csv`). Exit 2 lists every problem with row numbers.
3. Put incident annotations in a separate `labels.jsonl` and chronological boundaries in `split.json` next to `events.jsonl`, then:

```bash
resilient-mis train  --workload my_dir --run runs/mine --seed 1
resilient-mis replay --run runs/mine --events my_dir/events.jsonl --after <test-start-UTC>
```

Keep real identifiers, keys and exports out of Git (`.gitignore` already excludes `keys/`, `*.pem`, `*.db`).
