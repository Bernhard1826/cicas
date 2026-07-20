#!/usr/bin/env python3
"""SAIV residual dashboard + operator runbook (read-only).

Lives with the zlint coverage experiment because two of the three SAIV residuals
(G1 recall conservation and G3 N_viol) are coverage-side quantities. It reads and
aggregates artifacts the existing experiments already produce; it NEVER re-runs
extraction, codegen, or judging, writes nothing, and calls no LLM.

Residuals (paper Appendix F):
  L_recall (G1) <- rule labels in the DB (is_noise / lintable / lint_covered),
                   Eq (recall-res). Structurally 0 for a clean partition, so it
                   doubles as a label-integrity check.
  L_code   (G2) <- codegen_metrics summary (shipping synonymy rate over the
                   uncovered domain R_L^unc): L_code = 1 - rate.
  N_viol   (G3) <- ./outputs/n_viol_summary.json, produced by
                     recompute_coverage.py --lintable-scope false --dry-run
                   (reverse coverage check over the not-lintable set R_U).
  L_total = w_R*L_recall + w_C*L_code            (default w_R = w_C = 0.5)

===================  SAIV operator runbook (manual loop)  =====================
SAIV has no autonomous controller. One round, driven by the operator:

  measure residuals -> route to a stage (Eq. route) -> apply that stage's repair
  (re-extraction / re-judge; never patch outputs) -> re-measure -> stop when
  L_total < theta (0.05), after K=10 rounds, or no residual decreased.

1. Measure
     L_recall : python experiments/coverage_analysis/run.py
     L_code   : python experiments/codegen_metrics/run_codegen_synonymy.py --summary-only
     N_viol   : python experiments/coverage_analysis/recompute_coverage.py \
                       --lintable-scope false --dry-run          (read-only)
     dashboard: python experiments/coverage_analysis/saiv_residuals.py

2. Route (Eq. route; tau_R, tau_C are the operator's thresholds)
     L_recall > tau_R                       -> repair phi_R
     else p_fail > tau_C                    -> repair phi_C
     else L_code > tau_C and s_struct < 1   -> repair phi_G   (s_struct == 1 in
                                                               the fixed shell, so
                                                               this is a no-op
                                                               safeguard)
     else                                   -> repair phi_V

3. Repair (never patch the generated Go or the stored lintable flag)
     P_R / P_C : python scripts/reextract_specific_rules.py --rule-ids <ids> --commit
     P_G       : python experiments/codegen_metrics/run_codegen_synonymy.py \
                        --rule-id <id> --force-rule-id
     P_V       : python experiments/codegen_metrics/run_codegen_synonymy.py \
                        --rejudge   (or --rejudge-shipping)
     P_A       : hand-author the atom in app/services/certificate/codegen/dsl.py,
                 certify with atom_oracle.py, then it may enter A       (manual)

4. Adjudicate each N_viol hit (verdict full/partial while not-lintable)
     FLIP     : phi_C false negative -> re-derive lintability via P_R/P_C
                (moves the rule R_U -> R_L; if uncovered it needs a lint via P_G)
     SPURIOUS : coverage match was a false positive -> keep not-lintable
     (a committed FLIP shifts |R_L| and the codegen domain; do it deliberately,
      not in the read-only measurement pass.)
==============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import psycopg2

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent.parent
DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")

DEFAULT_NVIOL_SUMMARY = HERE / "outputs" / "n_viol_summary.json"
DEFAULT_CODEGEN_SUMMARY = (
    BACKEND / "experiments" / "codegen_metrics" / "outputs" / "full_current_db"
    / "codegen_synonymy_summary.json"
)


def recall_counts() -> dict:
    """|R_kw|, |R_N|, |R_L|, |R_U|, |R_L^cov|, |R_L^unc| from the rules table."""
    q = """
        select
          count(*)                                                            as r_kw,
          count(*) filter (where coalesce(is_noise, false))                   as r_n,
          count(*) filter (where lintable and not coalesce(is_noise, false))  as r_l,
          count(*) filter (where not coalesce(is_noise, false)
                             and not coalesce(lintable, false))               as r_u,
          count(*) filter (where lintable and coalesce(lint_covered, false))  as r_l_cov,
          count(*) filter (where lintable
                             and not coalesce(lint_covered, false))           as r_l_unc
        from rules
        where standard_id in (1, 19)
    """
    with psycopg2.connect(DB_URL, connect_timeout=5) as conn:
        cur = conn.cursor()
        cur.execute(q)
        row = cur.fetchone()
    keys = ["r_kw", "r_n", "r_l", "r_u", "r_l_cov", "r_l_unc"]
    return dict(zip(keys, (int(x) for x in row)))


def l_recall(c: dict) -> float:
    total = c["r_n"] + c["r_l"] + c["r_u"]
    hi = max(c["r_kw"], total)
    return 0.0 if hi == 0 else 1.0 - min(c["r_kw"], total) / hi


def l_code(summary_path: Path):
    if not summary_path.exists():
        return None, {"error": f"missing {summary_path}; run codegen_metrics first"}
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    rate = data.get("paper_synonymy_rate_over_domain")
    if rate is None:
        rate = data.get("final_shipping_unanimous_rate_over_domain")
    info = {
        "domain_total": data.get("domain_total"),
        "paper_synonymy_expresses": data.get("paper_synonymy_expresses"),
        "rate_over_domain": rate,
    }
    return (None if rate is None else 1.0 - float(rate)), info


def read_n_viol(summary_path: Path):
    if not summary_path.exists():
        return None, {"error": f"missing {summary_path}; run "
                               f"recompute_coverage.py --lintable-scope false --dry-run first"}
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    if data.get("lintable_scope") != "false":
        return None, {"error": f"n_viol_summary produced with lintable_scope="
                               f"{data.get('lintable_scope')!r}; need 'false' for N_viol",
                      "verdict_counts": data.get("verdict_counts")}
    return int(data.get("n_viol", 0)), data


def main() -> int:
    ap = argparse.ArgumentParser(description="SAIV residual dashboard (read-only)")
    ap.add_argument("--codegen-summary", default=str(DEFAULT_CODEGEN_SUMMARY))
    ap.add_argument("--nviol-summary", default=str(DEFAULT_NVIOL_SUMMARY))
    ap.add_argument("--w-recall", type=float, default=0.5)
    ap.add_argument("--w-code", type=float, default=0.5)
    ap.add_argument("--theta", type=float, default=0.05)
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args()

    counts = recall_counts()
    lrec = l_recall(counts)
    lcode, lcode_info = l_code(Path(args.codegen_summary))
    nviol, nviol_info = read_n_viol(Path(args.nviol_summary))

    ltotal = None if lcode is None else args.w_recall * lrec + args.w_code * lcode
    closed = (
        abs(lrec) < 1e-9
        and ltotal is not None and ltotal < args.theta
        and nviol == 0
    )

    result = {
        "recall_counts": counts,
        "L_recall": lrec,
        "L_code": lcode,
        "L_code_info": lcode_info,
        "N_viol": nviol,
        "N_viol_info": nviol_info,
        "L_total": ltotal,
        "weights": {"w_recall": args.w_recall, "w_code": args.w_code},
        "theta": args.theta,
        "closed": closed,
    }
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    print("== SAIV residuals (Appendix F) ==")
    print(f"  |R_kw|={counts['r_kw']}  |R_N|={counts['r_n']}  |R_L|={counts['r_l']}  "
          f"|R_U|={counts['r_u']}   (|R_L^cov|={counts['r_l_cov']} "
          f"|R_L^unc|={counts['r_l_unc']})")
    print(f"  G1  L_recall = {lrec:.4f}")
    if lcode is None:
        print(f"  G2  L_code   = NA    ({lcode_info.get('error')})")
    else:
        print(f"  G2  L_code   = {lcode:.4f}  (ship rate {lcode_info.get('rate_over_domain')} "
              f"over R_L^unc={lcode_info.get('domain_total')})")
    if nviol is None:
        print(f"  G3  N_viol   = NA    ({nviol_info.get('error')})")
    else:
        print(f"  G3  N_viol   = {nviol}")
    if ltotal is None:
        print("      L_total  = NA")
    else:
        print(f"      L_total  = {ltotal:.4f}  (w_R={args.w_recall}, w_C={args.w_code}; "
              f"theta={args.theta})")
    print(f"  closed = {closed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
