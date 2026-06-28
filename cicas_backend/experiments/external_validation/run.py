#!/usr/bin/env python3
"""
Paper §8.4 — lintability external validation (TABLE III).

Validates CICAS lint-ability verdicts against the zlint maintainers' public
CABF BR mapping sheets, for two BR versions: 1.4.8 and 2.0.2. For each sheet row
the maintainer marks whether the clause is in lint scope (Yes/No); CICAS marks
whether its extracted backend rule for the same clause is lint-able. Agreement is
reported as a confusion matrix + Cohen's κ over the matched rows.

Reproducibility note. The raw third-party inputs are NOT retained in-repo:
  - the maintainer sheets (zlint_cabf_br_*.csv), and
  - the two version-specific backends (CABF-Server-1.4.8 = 422 rules,
    CABF-Server-2.0.2 = 1024 rules) that lived in the now-retired pki_standards DB.
What IS retained — and what this script consumes — is the per-row judgment ledger
(sheet label + matched-backend lint-ability label) recovered into inputs/. This
makes TABLE III deterministically reproducible without the external artifacts.
The matched-only confusion / κ is the figure of record in the paper.

Inputs (inputs/):
  br148_judgments.jsonl   122 rows: {row, section, sheet, backend, note}
  br202_judgments.jsonl   250 rows: same schema
    sheet:   1 = maintainer "Yes/in-scope", 0 = "No/out-of-scope"
    backend: 1 = CICAS lint-able, 0 = non-lint-able, null = no backend match

Outputs (outputs/):
  br148_validation.json, br202_validation.json   per-version metrics
  table3.md                                       TABLE III rendered

Run:
  python experiments/external_validation/run.py

Expected (current paper snapshot):
  BR 1.4.8: recall 86.9%  TP/FN/FP/TN 60/9/0/37   κ 0.823  P 1.000  F1 0.930
  BR 2.0.2: recall 86.8%  TP/FN/FP/TN  6/6/1/204  κ 0.616  P 0.857  F1 0.632
"""
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
INPUTS = HERE / "inputs"
OUTPUTS = HERE / "outputs"

# Version-specific backend sizes (retired pki_standards DB; recorded constants).
BACKEND_SIZE = {"BR 1.4.8": 422, "BR 2.0.2": 1024}


def load(name):
    return [json.loads(l) for l in (INPUTS / name).read_text().splitlines() if l.strip()]


def evaluate(judgments, label):
    total = len(judgments)
    yes = sum(1 for j in judgments if j["sheet"] == 1)
    no = total - yes
    matched = [(j["sheet"], j["backend"]) for j in judgments if j["backend"] is not None]

    c = Counter(matched)
    tp, fn, fp, tn = c[(1, 1)], c[(1, 0)], c[(0, 1)], c[(0, 0)]
    n = tp + fn + fp + tn
    po = (tp + tn) / n if n else 0.0
    p_s, p_c = (tp + fn) / n, (tp + fp) / n
    pe = p_s * p_c + (1 - p_s) * (1 - p_c)
    kappa = (po - pe) / (1 - pe) if pe < 1 else 1.0
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else None

    return {
        "version": label,
        "backend_size": BACKEND_SIZE.get(label),
        "sheet_rows": total, "sheet_yes": yes, "sheet_no": no,
        "matched": len(matched),
        "matching_recall": round(len(matched) / total, 4) if total else 0.0,
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "agreement": round(po, 4), "kappa": round(kappa, 4),
        "yes_precision": round(prec, 4) if prec is not None else None,
        "yes_recall": round(rec, 4) if rec is not None else None,
        "yes_f1": round(f1, 4) if f1 is not None else None,
    }


def render_table3(rows):
    L = ["# TABLE III — BR 1.4.8 / BR 2.0.2 external validation\n",
         "| 版本 | Sheet 行数 (Yes/No) | 后端规则数 | 召回率 | TP/FN/FP/TN | 一致率 | Cohen's κ | 精确率 | F1 |",
         "|---|---:|---:|---:|:--:|---:|---:|---:|---:|"]
    for r in rows:
        L.append(
            f"| **{r['version']}** | {r['sheet_rows']} ({r['sheet_yes']}/{r['sheet_no']}) | "
            f"{r['backend_size']} | **{r['matching_recall']*100:.1f}%** | "
            f"{r['TP']}/{r['FN']}/{r['FP']}/{r['TN']} | {r['agreement']*100:.1f}% | "
            f"**{r['kappa']:.3f}** | {r['yes_precision']:.3f} | {r['yes_f1']:.3f} |")
    return "\n".join(L) + "\n"


def main():
    OUTPUTS.mkdir(exist_ok=True)
    rows = []
    for name, label, fname in [
        ("br148_judgments.jsonl", "BR 1.4.8", "br148_validation.json"),
        ("br202_judgments.jsonl", "BR 2.0.2", "br202_validation.json"),
    ]:
        r = evaluate(load(name), label)
        (OUTPUTS / fname).write_text(json.dumps(r, indent=2, ensure_ascii=False))
        rows.append(r)
        print(f"{label}: recall {r['matching_recall']*100:.1f}%  "
              f"TP/FN/FP/TN {r['TP']}/{r['FN']}/{r['FP']}/{r['TN']}  "
              f"κ {r['kappa']:.3f}  P {r['yes_precision']:.3f}  F1 {r['yes_f1']:.3f}")

    md = render_table3(rows)
    (OUTPUTS / "table3.md").write_text(md)
    print("\n" + md)

    # guard the figures of record
    by = {r["version"]: r for r in rows}
    assert by["BR 1.4.8"]["kappa"] == 0.8231, by["BR 1.4.8"]["kappa"]
    assert by["BR 2.0.2"]["kappa"] == 0.6159, by["BR 2.0.2"]["kappa"]
    print(f"[ok] wrote outputs/ -> {OUTPUTS}")


if __name__ == "__main__":
    main()
