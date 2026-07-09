# Experiments

One subdirectory per paper experiment or report-only experiment. Standard
experiment directories are self-contained: script entry point, `inputs/`,
`outputs/`, and `README.md`.

## Current Figures Of Record

| Paper (`Paper_Unified_PKI_E2E.md`) | directory | what it produces |
|---|---|---|
| **§8.2** lint coverage analysis (Table 2) | [`coverage_analysis/`](coverage_analysis/) | native zlint coverage over 248 lint-able rules -> 158 full / 90 codegen domain / 0 pending |
| **system metric** code generation + synonymy | [`codegen_metrics/`](codegen_metrics/) | over the 90 uncovered rules -> 90 generated / 90 final-shipping strict EXPRESS / 0 residuals |
| **§8.3** lintability external validation (TABLE III) | [`external_validation/`](external_validation/) | CICAS vs zlint-maintainer CABF BR sheets (1.4.8 / 2.0.2) -> recall / kappa / P / F1 |
| **§8.4** certificate detection gate | [`cert_detection/`](cert_detection/) | zlint testdata gate over 90 shipped lints -> 299 independently confirmed fixture findings / 0 strict reportable testdata findings |
| **§8.4** external certificate corpus scan | [`new_lint_corpus_scan/`](new_lint_corpus_scan/) | Tranco / CT report-only scans -> 6 Tranco and 1 CT strict confirmed no-upstream findings |

Coverage-specific backend reference snapshots live with the coverage experiment
inputs. For example, the zlint coverage service loads
`coverage_analysis/inputs/lint_ir_summaries.json`.

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
