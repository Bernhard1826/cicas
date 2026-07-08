# Experiments

One subdirectory per paper experiment or report-only experiment. Standard
experiment directories are self-contained: script entry point, `inputs/`,
`outputs/`, and `README.md`.

## Current Figures Of Record

| Paper (`Paper_Unified_PKI_E2E.md`) | directory | what it produces |
|---|---|---|
| **§8.2** lint coverage analysis (Table 2) | [`coverage_analysis/`](coverage_analysis/) | native zlint coverage over 249 lint-able rules -> 158 full / 91 codegen domain / 0 pending |
| **system metric** code generation + synonymy | [`codegen_metrics/`](codegen_metrics/) | over the 91 uncovered rules -> 91 generated / 91 final-shipping strict synonymous |
| **§8.4** lintability external validation (TABLE III) | [`external_validation/`](external_validation/) | CICAS vs zlint-maintainer CABF BR sheets (1.4.8 / 2.0.2) → recall / κ / P / F1 |
| **§8.5** certificate detection as a SAIV gate | [`cert_detection/`](cert_detection/) | retained outputs are stale relative to the current 91-lint strict shipping manifest; rerun before using detection numbers |

`results/` is not a paper experiment. It stores shared backend reference
snapshots, including `lint_ir_summaries.json`, which the zlint coverage service
loads.

Run a standard experiment with
`python3 cicas_backend/experiments/<dir>/run.py`.

## Conventions (must follow)
1. **One directory per paper experiment.** The directory name maps to a paper section via the table above.
2. **Inside standard experiment directories:** a script entry point, `inputs/`, `outputs/`, and `README.md`.
3. **Changing the experiment strategy updates `run.py` in place — never add a new script.**
   (No `run_v2.py`, no `analyze_*_strict.py` siblings. Version history lives in git.)
4. Targeted maintenance scripts are allowed only when they are not paper entry
   points, for example `coverage_analysis/recompute_coverage.py` and corpus
   collection scripts under `new_lint_corpus_scan/`.
5. **System metrics are kept separate from paper validation experiments.** Code-generation
   and synonymy are in [`codegen_metrics/`](codegen_metrics/) because they are used
   directly by the paper and need a stable ledger.
6. The whole pipeline (crawl → IR → lintability → DSL tree → synonymy → Go codegen → SAIV) lives in
   `app/`; experiment `run.py` scripts only orchestrate / report — they never re-implement pipeline logic.
