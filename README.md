# resilient-mis

**Companion to:** Md Talha Bin Ansar, Mohammad Somon Sikder, Md Kazi Tuhin, Niropam Das, Partha Chakraborty and Habiba Rahman, *Resilient MIS Design Using Cryptographic and Cyber-Security Techniques*, in *Innovative Computing and Communications (ICICC 2026)*, Lecture Notes in Networks and Systems, vol. 2037, pp. 317-331. DOI [10.1007/978-3-032-30008-9_24](https://doi.org/10.1007/978-3-032-30008-9_24). Publisher page: <https://link.springer.com/chapter/10.1007/978-3-032-30008-9_24>.

An installable, offline Python demonstration of one idea: **an enterprise MIS recovers a trustworthy spending report after a storage failure while still enforcing today's access policy.** It is an independent companion implementation, **not** the authors' code and **not** a reproduction of the chapter's experiments (the full chapter was not available when this was built; see [docs/chapter-map.md](docs/chapter-map.md)).

It answers four questions with evidence you can rerun: which records were restored, who can read them, when the service became usable again, and how much time the protections add to an ordinary request.

## Quick start (tested on a clean CPU-only virtualenv, Python 3.10)

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install .
resilient-mis walkthrough --fast                  # fresh temp directory, ~15 s, offline
```

`--fast` uses 2048-bit RSA for quicker key generation; omit it for the 3072-bit default. Nothing outside the temporary directory is touched. Developer install: `pip install -e ".[dev]" && pytest`.

## The spending-report walkthrough

`resilient-mis walkthrough` runs the real service on invented data and prints a trace ([docs/recovery_trace.md](docs/recovery_trace.md) is one saved run):

1. **Two tenants, different orders.** A manager reads one department's report: expected total (from an independent client ledger), the exact contributing record versions and transaction ids, totals re-verified against the committed transactions, and a redacted allow decision (pseudonymous principal only). The same manager asking for the other tenant is refused.
2. **Checkpoint, revoke, update.** A verified checkpoint is taken, the analyst's access is revoked, an ordinary business update is committed. The analyst is denied; the manager's valid read still works.
3. **Detector replay.** Recorded unusual activity goes through a rules baseline and a seeded Isolation Forest; the alert evidence is retained (`alert_evidence.jsonl`).
4. **Outage and an invalid candidate.** The local store is deleted (disposable fixture only). A prebuilt invalid snapshot is offered for restore and rejected at the signature check; the active state is byte-for-byte untouched and the invalid candidate never becomes active.
5. **Recovery.** Restore from the approved checkpoint plus the signed journal. The timer stops only when **the manager gets the correct report, the revoked analyst is still denied, and a new valid write commits.** Reported: last restored transaction, lost committed updates, elapsed times per phase, validation receipts. A recovery operator can validate the restore but receives no business report.
6. **Retry and interruption.** Re-running restore on a healthy store is a no-op that keeps later writes; a restore interrupted before cutover leaves the previous state untouched; the retry duplicates no order and reactivates no privilege.

(In the saved trace "detected-to-restore-start" includes the rejected-candidate attempt of step 4.)

## Commands

| Purpose | Command |
|---|---|
| validate an authorised export | `resilient-mis data-validate --events export.csv` |
| generate workload + labels | `resilient-mis generate-workload --out work/wl --seed 1` |
| train detectors (train split) + calibrate (dev split) | `resilient-mis train --workload work/wl --run runs/mine` |
| replay in arrival order | `resilient-mis replay --run runs/mine --events work/wl/events.jsonl --after <UTC>` |
| provision / grant / login | `resilient-mis init --home H --disposable`, `grant`, `login` |
| orders and report | `resilient-mis order create\|update\|read ...`, `resilient-mis report ...` |
| checkpoint | `resilient-mis checkpoint --home H --token T` |
| verify a snapshot | `resilient-mis verify --home H --snapshot backups/<id>` |
| inject a fault (disposable fixtures only) | `resilient-mis fault --home H --kind delete\|corrupt` |
| recover | `resilient-mis recover --home H --token T [--no-journal] [--interrupt-before-cutover]` |
| benchmark all | `resilient-mis benchmark --run runs/<id>` (`--smoke` for CI size; `--only detection\|recovery\|latency`) |
| build results from saved records | `resilient-mis report-build --run runs/<id> --out docs/results.md` |
| optional local HTTP adapter | `resilient-mis serve --home H --port 8765` |

The HTTP adapter calls the same `MisService` methods as the CLI. Details: [docs/architecture.md](docs/architecture.md) (with the key-boundary diagram), [docs/data.md](docs/data.md), [docs/results.md](docs/results.md), [docs/chapter-map.md](docs/chapter-map.md).

## What the chapter says versus what was measured here

Chapter values are only the public-abstract statements, with their qualifiers; definitions, data, hardware and trial counts are **not established**. Measured values are from run `demo` (commit recorded in `runs/demo/manifest.json`): one laptop, CPU only, local SQLite, invented data, RSA-3072. **None of this reproduces the chapter or says anything about enterprise or cloud deployment.** Every figure below is computed from saved per-trial records ([docs/results.md](docs/results.md) has definitions, denominators and limitations).

| Item | Chapter claim (public abstract) | Measured here (synthetic, local) | Comparable? |
|---|---|---|---|
| Detection | "over 93%" detection; unit and definition unverified | **Incident recall** over 10 independent trials, 120 eligible incidents: fixed rules **104/120 = 0.867** (Wilson 95% 0.794-0.916), 0 false alert groups in 2880 monitored hours; seeded Isolation Forest at the same alert budget **9/120 = 0.075**, 26 false alert groups (0.009 / h). Bulk-export and low-and-slow incidents are missed by the Isolation Forest | No. Different data, definition and estimator; the incident generator and the rule thresholds share an author |
| Availability | "up to 99%" | Business-probe availability **during one injected fault per trial**: 0.733 pooled (Wilson 0.685-0.776) with journal; per-trial min 0.128, median 0.931, max 0.972; 59 of 367 scheduled probes had no record | No. Not an uptime figure; a best trial supports no promise |
| Recovery | "under 22 seconds"; start/stop unverified | **Fault-to-ready** (correct report + revoked analyst still denied + new write commits): 10/10 ready, median **0.89 s**, range 0.75-5.86 s (slowest trials coincide with a slow decrypt-and-verify phase on a shared machine; kept, not excluded). Snapshot-only: 5/5 ready, median 0.70 s, **2 confirmed writes lost in every trial**; with the journal 0 lost | No. Tiny store (about 24 record versions), warm key cache |
| Latency overhead | "moderate", no number | Protected vs all-controls-off, p50: create 9.9 to 52.0 ms (+42.1 ms), read 6.2 to 11.9 ms (+5.7 ms), report 5.0 to 89.8 ms (+84.9 ms; decrypting 16 records); snapshot 18.7 to 926.8 ms. First-use key load 184 ms vs 7.1 ms warm | No number in the chapter to compare with |

## Cryptography and trust (summary)

Per record version a fresh AES-256-GCM key and 96-bit nonce encrypt the payload; the key is wrapped with RSA-OAEP (SHA-256) under a per-tenant key. Tenant, record id, schema and version are bound as length-prefixed associated data (and as the OAEP label). Keys and nonces come from the OS CSPRNG through the `cryptography` library (pinned 50.0.2; [AEAD docs](https://cryptography.io/en/stable/hazmat/primitives/aead/), [RSA docs](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/)); no benchmark seed ever feeds a key or nonce. Snapshot manifests and the approved-checkpoint chain are signed with an independent Ed25519 key checked against a pinned anchor. Private keys live only in `keys/`. Custody, rotation, recovery-key retention and the limits of this trust model are in [docs/architecture.md](docs/architecture.md).

## Tests

`pytest` runs unit, integration and end-to-end tests (crypto round trips, wrong context/key/tag, key rotation across a retained backup, per-tenant/role/department access, trusted-context change, label leakage and causality of features, malformed imports, invalid/stale/unapproved/tampered snapshots, revocation surviving restore, restart and retry, concurrent writers, missing probe records, every metric against a hand calculation incl. zero denominators). Last clean-install run (fresh venv, non-editable install, Python 3.10, Windows): **128 passed, 1 skipped** (a POSIX-only file-permission check), **93% line coverage** of `src/resilient_mis`. Least covered: `cli.py` 83% and key-custody error branches 87%; the optional HTTP adapter is covered at 80%. CI (`.github/workflows/ci.yml`) is read-only (`contents: read`) and also runs the walkthrough and the CI-size benchmark.

## Maintainer and credit

Maintainer: Partha Chakraborty ([@parthachk64-cyber](https://github.com/parthachk64-cyber)), sole code owner (`.github/CODEOWNERS`). All six chapter authors are credited, in published order, in [CITATION.cff](CITATION.cff). Third-party notices: [NOTICE.md](NOTICE.md). Licence for the new code: MIT (see `LICENSE`; confirm the copyright holder line before release).
