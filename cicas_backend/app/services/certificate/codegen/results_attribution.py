"""codegen/results_attribution.py — partition zlint findings into upstream vs
CICAS-generated.

zlint emits a JSON object keyed by lint name:

    {"e_basic_constr_not_critical": {"result": "pass"},
     "cicasgen_subject_org_len_4821": {"result": "error"}, ...}

Every CICAS-generated lint is registered with a Name starting `cicasgen_` (see
intree_emitter.py); no upstream zlint lint uses that prefix. So attribution is a
pure prefix test, optionally cross-checked against the emission manifest written
by inject_and_build.py so a finding can be traced back to its source rule.

This module is pure stdlib so it can run anywhere (CI, the user's cert host)
without importing the rest of the backend.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


CICAS_PREFIX = "cicasgen_"
# zlint non-pass result codes (anything other than these is "clean")
_NONPASS = {"error", "warn", "fatal", "info", "notice"}


def is_generated(lint_name: str) -> bool:
    """True iff `lint_name` is a CICAS-generated lint (not upstream zlint)."""
    return (lint_name or "").startswith(CICAS_PREFIX)


def load_manifest(manifest_path) -> dict:
    """Load the emission manifest (lint_name -> {rule_id, source, section,...})
    written by inject_and_build.py. Returns {} if absent."""
    p = Path(manifest_path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text())
    lints = data.get("lints", data) if isinstance(data, dict) else data
    by_name = {}
    for rec in lints:
        nm = rec.get("lint_name")
        if nm:
            by_name[nm] = rec
    return by_name


def split_findings(zlint_json: dict, *, only_nonpass: bool = True,
                   manifest: Optional[dict] = None) -> dict:
    """Partition one certificate's zlint result object.

    zlint_json: the dict zlint prints for a single cert (lint_name -> {result,...}).
    only_nonpass: keep only findings whose result is a non-pass code (the actual
                  problems); when False, every lint outcome is kept.
    manifest: optional {lint_name -> rule record} to annotate generated findings
              with their source rule.

    Returns:
        {
          "upstream":  [{"lint": str, "result": str, "details": ...}, ...],
          "generated": [{"lint": str, "result": str, "rule_id": int|None,
                         "source": str|None, "section": str|None,
                         "rule_text": str|None}, ...],
        }
    """
    manifest = manifest or {}
    upstream, generated = [], []
    for lint_name, outcome in (zlint_json or {}).items():
        result = (outcome or {}).get("result") if isinstance(outcome, dict) else outcome
        result = (result or "").lower()
        if only_nonpass and result not in _NONPASS:
            continue
        details = outcome.get("details") if isinstance(outcome, dict) else None
        if is_generated(lint_name):
            rec = manifest.get(lint_name, {})
            generated.append({
                "lint": lint_name, "result": result, "details": details,
                "rule_id": rec.get("rule_id"),
                "source": rec.get("source"),
                "section": rec.get("section"),
                "rule_text": rec.get("rule_text"),
            })
        else:
            upstream.append({"lint": lint_name, "result": result, "details": details})
    return {"upstream": upstream, "generated": generated}


def classify_zlint_file(path, *, only_nonpass: bool = True,
                        manifest_path=None) -> dict:
    """Classify a zlint output file.

    Supports two shapes:
      - one JSON object  (single cert, e.g. `zlint -pretty cert.pem`)
      - JSON-lines       (one object per cert, e.g. piped many certs)

    Returns a roll-up:
        {
          "n_certs": int,
          "upstream_findings": int,
          "generated_findings": int,
          "per_cert": [ {index, upstream:[...], generated:[...]} ... ],
          "generated_by_lint": { lint_name: count, ... },
        }
    """
    manifest = load_manifest(manifest_path) if manifest_path else {}
    text = Path(path).read_text().strip()
    objs = []
    if not text:
        objs = []
    elif text[0] == "[":
        objs = json.loads(text)
    else:
        # try single object first, else JSON-lines
        try:
            objs = [json.loads(text)]
        except json.JSONDecodeError:
            objs = [json.loads(ln) for ln in text.splitlines() if ln.strip()]

    per_cert = []
    up_total = gen_total = 0
    gen_by_lint: dict = {}
    for i, obj in enumerate(objs):
        # a cert result may be wrapped, e.g. {"lints": {...}} — unwrap if needed
        result_map = obj.get("lints") if isinstance(obj, dict) and "lints" in obj else obj
        split = split_findings(result_map, only_nonpass=only_nonpass, manifest=manifest)
        up_total += len(split["upstream"])
        gen_total += len(split["generated"])
        for g in split["generated"]:
            gen_by_lint[g["lint"]] = gen_by_lint.get(g["lint"], 0) + 1
        per_cert.append({"index": i, **split})

    return {
        "n_certs": len(objs),
        "upstream_findings": up_total,
        "generated_findings": gen_total,
        "per_cert": per_cert,
        "generated_by_lint": gen_by_lint,
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(
        description="Partition zlint findings into upstream vs CICAS-generated.")
    ap.add_argument("zlint_output", help="zlint JSON or JSON-lines output file")
    ap.add_argument("--manifest", default=None,
                    help="emission manifest from inject_and_build.py")
    ap.add_argument("--all", action="store_true",
                    help="include pass results, not just problems")
    args = ap.parse_args()
    summary = classify_zlint_file(args.zlint_output,
                                  only_nonpass=not args.all,
                                  manifest_path=args.manifest)
    print(json.dumps({k: v for k, v in summary.items() if k != "per_cert"},
                     indent=2, ensure_ascii=False))
    print(f"\n=== {summary['generated_findings']} findings from CICAS lints "
          f"across {summary['n_certs']} cert(s) ===")
    for cert in summary["per_cert"]:
        for g in cert["generated"]:
            tag = f"rule {g['rule_id']}" if g.get("rule_id") else "?"
            print(f"  [cert {cert['index']}] {g['result'].upper():6} {g['lint']} "
                  f"({tag}: {g.get('source')} {g.get('section')})")
