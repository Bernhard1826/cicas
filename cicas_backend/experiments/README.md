# Experiments

One subdirectory per **paper experiment**. Each is self-contained:
`run.py` (the experiment script) + `inputs/` (input data) + `outputs/` (results) + `README.md`.

## Paper ↔ directory map

| Paper (`Paper_Unified_PKI_E2E.md`) | directory | what it produces |
|---|---|---|
| **§8.2** lint coverage analysis (Table 2) | [`coverage_analysis/`](coverage_analysis/) | zlint same-source coverage of the 336 lint-able rules → 132 full / 204 codegen domain |
| **§8.4** lintability external validation (TABLE III) | [`external_validation/`](external_validation/) | CICAS vs zlint-maintainer CABF BR sheets (1.4.8 / 2.0.2) → recall / κ / P / F1 |
| **§8.5** certificate detection as a SAIV gate | [`cert_detection/`](cert_detection/) | 31 shipped synonymous lints over 1128 zlint testdata certs → 108/108 genuine detections, 0 false positives (independently audited per finding, cross-checked by 3 parsers) |

Run an experiment with `python experiments/<dir>/run.py`.

## Conventions (must follow)
1. **One directory per paper experiment.** The directory name maps to a paper section via the table above.
2. **Inside each directory:** `run.py`, `inputs/`, `outputs/`, `README.md`. Nothing else.
3. **Changing the experiment strategy updates `run.py` in place — never add a new script.**
   (No `run_v2.py`, no `analyze_*_strict.py` siblings. Version history lives in git.)
4. **System metrics are NOT experiments.** The recall funnel, lint coverage split, **code-generation
   rate** and **synonymy rate** are pipeline outputs and live in
   [`../scripts/system_metrics/`](../scripts/system_metrics/) — do not duplicate that data here.
5. The whole pipeline (crawl → IR → lintability → DSL tree → synonymy → Go codegen → SAIV) lives in
   `app/`; experiment `run.py` scripts only orchestrate / report — they never re-implement pipeline logic.
