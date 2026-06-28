"""codegen/detection/triage.py — label each cicasgen_ finding REAL / SPURIOUS /
UNCERTAIN, with no LLM and no human.

Two oracle signals (testdata naming + upstream consensus):
  1. upstream consensus (runtime, from scan.py) — did any UPSTREAM zlint lint also
     report a problem on this cert in the same run? If yes, the cert is
     demonstrably defective.
  2. testdata intent (static, testdata_oracle.py) — is the cert a KNOWN-BAD
     fixture (some lint expects Error/Warn on it) or a POSITIVE fixture (only ever
     expected to Pass)?

Verdict:
  REAL       cert is defective (upstream consensus OR known-bad fixture).
  SPURIOUS   cert is a positive fixture AND nobody upstream complains, yet we
             fire: textbook over-strictness.
  UNCERTAIN  unnamed cert / no upstream signal — EITHER a genuine NEW lint
             catching what upstream misses OR a false positive; disambiguated by
             the lint's corpus-wide firing fraction.

The per-lint firing fraction is the same over-strictness signal as
atom_oracle.sentinel (default flag threshold 0.30), computed here from the binary
scan instead of the throwaway-workspace driver.
"""
from __future__ import annotations

from collections import Counter, defaultdict

OVERSTRICT_FRAC = 0.30   # == atom_oracle.sentinel flag_frac default


def _lint_corpus_stats(detections: list[dict]) -> tuple[Counter, Counter]:
    """(applies, fires): per lint, # certs where CheckApplies held (status != NA)
    and # certs where it reported non-pass."""
    applies, fires = Counter(), Counter()
    for d in detections:
        for lint, res in d["ours_all"].items():
            if (res or "").lower() != "na":
                applies[lint] += 1
        for lint in d["ours"]:
            fires[lint] += 1
    return applies, fires


def triage(detections: list[dict], intent: dict,
           overstrict_frac: float = OVERSTRICT_FRAC) -> dict:
    """Return {"findings": [...], "by_lint": [...], "summary": {...}}."""
    applies, fires = _lint_corpus_stats(detections)

    def error_frac(lint):
        a = applies.get(lint, 0)
        return (fires.get(lint, 0) / a) if a else 0.0

    findings = []
    per_lint_verdicts = defaultdict(Counter)
    for d in detections:
        cert = d["cert"]
        upstream_hit = len(d["upstream"]) > 0
        cinfo = intent.get(cert, {})
        known_bad = bool(cinfo.get("nonpass"))
        positive_fixture = (not known_bad) and bool(cinfo.get("pass"))
        for lint, res in d["ours"].items():
            ef = error_frac(lint)
            if upstream_hit or known_bad:
                verdict, reason = "REAL", ("upstream_consensus" if upstream_hit
                                           else "known_bad_fixture")
            elif positive_fixture:
                verdict, reason = "SPURIOUS", "fires_on_positive_fixture_no_upstream"
            elif ef >= overstrict_frac:
                verdict, reason = "SPURIOUS", f"unnamed_but_overstrict_frac={ef:.2f}"
            else:
                verdict, reason = "UNCERTAIN", "unnamed_no_upstream_narrow_firing"
            per_lint_verdicts[lint][verdict] += 1
            findings.append({
                "cert": cert, "lint": lint, "result": res,
                "verdict": verdict, "reason": reason,
                "error_frac": round(ef, 3),
                "upstream_hit": upstream_hit,
                "upstream_lints": list(d["upstream"].keys())[:6],
                "cert_known_bad": known_bad,
                "cert_positive_fixture": positive_fixture,
                "cert_named": cert in intent,
            })

    by_lint = []
    for lint in sorted(set(list(fires) + list(per_lint_verdicts))):
        v = per_lint_verdicts[lint]
        by_lint.append({
            "lint": lint, "fires": fires.get(lint, 0),
            "applies": applies.get(lint, 0), "error_frac": round(error_frac(lint), 3),
            "REAL": v["REAL"], "SPURIOUS": v["SPURIOUS"], "UNCERTAIN": v["UNCERTAIN"],
            "suspect": v["SPURIOUS"] > 0 or error_frac(lint) >= overstrict_frac,
        })
    by_lint.sort(key=lambda r: (-r["SPURIOUS"], -r["error_frac"]))

    tot = Counter(f["verdict"] for f in findings)
    return {"findings": findings, "by_lint": by_lint,
            "summary": {"total": len(findings), "REAL": tot["REAL"],
                        "SPURIOUS": tot["SPURIOUS"], "UNCERTAIN": tot["UNCERTAIN"]}}
