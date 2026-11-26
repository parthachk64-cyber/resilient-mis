# Chapter map

Chapter: Md Talha Bin Ansar, Mohammad Somon Sikder, Md Kazi Tuhin, Niropam Das, Partha Chakraborty and Habiba Rahman, *Resilient MIS Design Using Cryptographic and Cyber-Security Techniques*, in *Innovative Computing and Communications (ICICC 2026)*, Lecture Notes in Networks and Systems, vol. 2037, pp. 317-331. DOI <https://doi.org/10.1007/978-3-032-30008-9_24>. Publisher page: <https://link.springer.com/chapter/10.1007/978-3-032-30008-9_24> (first online 2 August 2026, per the task brief).

## Verification status of this map

**The full chapter was not available to this build.** No licensed copy was supplied, and an unauthenticated fetch of the Springer page was redirected to a login, so no section, equation, figure, table, dataset, hardware description, comparison system, workload, timing boundary or trial count of the chapter was inspected. The chapter's body is therefore NOT mapped. This file lists only the four public-abstract statements plus the techniques the abstract names, and says what this repository does about each. Any row marked *unverified* must be re-checked by someone with the full text. The licensed chapter is not in the repository.

| # | Chapter item (public abstract) | Source location | Implementation here | Command | Reproduction status |
|---|---|---|---|---|---|
| 1 | Symmetric and asymmetric encryption | abstract | AES-256-GCM payload + RSA-OAEP-SHA256 key wrap, per-record data key and nonce, AAD binding (`crypto.py`, `keys.py`). **The chapter's actual algorithms are not established**; this is a documented companion default. | `pytest tests/test_crypto_keys.py` | companion design choice, not a reproduction |
| 2 | Role- and context-dependent authorization | abstract | roles, tenant/department scope, purpose, trusted device; checked fresh on every call (`policy.py`, `identity.py`) | `resilient-mis grant / login / order / report` | companion design choice |
| 3 | Continuous anomaly detection, "over 93%" | abstract | rules baseline + seeded Isolation Forest over rolling telemetry (`detection.py`); incident recall defined in `metrics.py`. **Chapter's estimator, data and detection-rate definition: unverified.** | `resilient-mis benchmark --only detection` | measured locally on synthetic data; NOT a reproduction; result in `docs/results.md` C1 |
| 4 | Integrity-checked recovery, "under 22 seconds" | abstract | signed manifest, approved-checkpoint chain, staging verification, journal replay, atomic cutover (`snapshots.py`, `recovery.py`). **Start/stop definition of the 22 s: unverified.** | `resilient-mis walkthrough`; `benchmark --only recovery` | measured locally; NOT a reproduction; `docs/results.md` C2 |
| 5 | Availability "up to 99%" | abstract | independent business probes with a client-side ledger (`probes.py`) | `benchmark --only recovery` | measured locally during an injected fault; NOT an uptime figure; `docs/results.md` C3 |
| 6 | Moderate latency overhead | abstract | paired interleaved timings with controls individually disabled (`evaluate.py`, test-only profiles) | `benchmark --only latency` | measured locally; the chapter gives no number; `docs/results.md` C4 |
| 7 | Chapter diagrams, tables, datasets, comparison systems, hardware, workload | full text | not inspected | n/a | **unverified** |

`references/reported/chapter_claims.csv` stores the qualifiers exactly as given (`over 93%`, `up to 99%`, `under 22 seconds`, `moderate`).

## How to extend this map

With the full text in hand, add one row per verified component, table and figure: source location (section/page), what the chapter reports, which module implements it (or "not implemented"), the exact command, and one of `reproduced`, `approximated (state how)`, `not reproducible (state why)`. Do not copy chapter text or figures into the repository.
