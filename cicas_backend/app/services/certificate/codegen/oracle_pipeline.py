"""templates_v2 / oracle_pipeline.py — Phase 2.

Route every deterministically-reducible target rule through the CERTIFIED
deterministic path and re-ground acceptance on the cert oracle instead of the
single-vote LLM judge.

A rule is SYNONYMY-GUARANTEED (code == IR) iff:
  - det_codegen.deterministic_tree reduces it (no LLM), AND
  - every atom in the tree is certified faithful (certify_atoms batches), AND
  - the rendered Go compiles.
Such a rule's generated lint provably implements its IR predicate, by structural
composition over per-atom-verified emitters — no judge involved.

Separately (a weaker, IR!=rule signal) the over-strictness sentinel flags
guaranteed lints that still fire on many valid certs (missing-scope / dropped
precondition in EXTRACTION, upstream of codegen). Reported, not counted.
"""
from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "cicas_backend"))  # det_codegen -> app.services... (before import)

from . import det_codegen, tree_codegen, dsl, runner, atom_oracle as O

RES = ROOT / "experiments/results"

# Atoms certified faithful by certify_atoms.py (batches 1-4) + trivial combinators.
CERTIFIED = {
    "And", "Or", "Not", "When", "Compound",
    "IsCA", "KeyUsageHas", "ExtKeyUsageHas",
    "FieldNonEmpty", "FieldEmpty", "ExtPresent", "ExtNotCritical", "ExtCritical",
    "FieldEq", "FieldInSet", "FieldNotInSet", "FieldLenInRange",
    "FieldNumericInRange", "FieldCount", "OidListContains", "IPListAllOctetCount",
    "RSAModulusBitsInRange", "RSAPublicExponentInRange",
    "ExtHasAnyGeneralNameOfTag",
    "SigAlgMatchesTBSSignature",
    "IsSubscriberCert", "IsEndEntity", "IsRootCA", "IsServerCert",
    "CommonNameFromSAN",
    "AIAHasMethodOtherThan",
    "OidListCountInSet",
}
DN_HOLDERS = {"Subject", "Issuer", "subject", "issuer"}


def _iter_nodes(n):
    yield n
    for f in dataclasses.fields(n):
        v = getattr(n, f.name)
        if dataclasses.is_dataclass(v):
            yield from _iter_nodes(v)
        elif isinstance(v, (list, tuple)):
            for x in v:
                if dataclasses.is_dataclass(x):
                    yield from _iter_nodes(x)


def tree_all_certified(tree) -> tuple[bool, set]:
    """(all_certified, uncertified_atom_names). FieldEncodedAs counts as certified
    only on a DN holder (sound DER-tag form); elsewhere it's a charset approx."""
    bad = set()
    for n in _iter_nodes(tree):
        cn = type(n).__name__
        if cn in CERTIFIED:
            continue
        if cn == "FieldEncodedAs" and str(getattr(n, "field", "")) in DN_HOLDERS:
            continue
        bad.add(cn)
    return (not bad), bad


def load(p):
    p = Path(p)
    return [json.loads(l) for l in open(p) if l.strip()] if p.exists() else []


def main():
    det = load(RES / "exp_codegen_det_v2.jsonl")
    f1 = {str(r["rule_id"]) for r in load(RES / "reverse_check_lintability.jsonl") if r.get("verdict") == "FLIP"}
    f2 = {str(r["rule_id"]) for r in load(RES / "reverse_check_l3_pass2.jsonl") if r.get("verdict") == "FLIP"}
    flips = f1 | f2
    target = {str(r["rule_id"]) for r in det} - flips
    rows = {str(r["rule_id"]): r for r in load(RES / "uncovered_lintable_v2.jsonl")}

    reducible, uncertified, render_err = [], [], []
    luts = []  # (rule_id, code) for compile + sentinel
    for rid in sorted(target, key=int):
        r = rows.get(rid)
        if not r:
            continue
        ir = r.get("ir") or {}
        try:
            tree = det_codegen.deterministic_tree(int(rid), ir, section=r.get("section"))
        except Exception:
            tree = None
        if tree is None:
            continue
        ok, bad = tree_all_certified(tree)
        try:
            out = tree_codegen.render_from_tree(tree, None, "lint.Error")
            rl = runner.render_full_lint_from_tree(
                int(rid), r.get("source", "RFC"), str(r.get("section", "")),
                (r.get("rule_text") or "")[:180], out["execute_body"], out["imports"],
                tree=tree)
            code = rl.file_content
        except Exception as e:
            render_err.append((rid, str(e)[:80]))
            continue
        reducible.append(rid)
        if ok:
            luts.append(O.lint_from_code(rid, code))
        else:
            uncertified.append((rid, sorted(bad)))

    # batch compile the certified-atom lints
    compiles, compile_fail = set(), {}
    if luts:
        with tempfile.TemporaryDirectory(prefix="cicas_p2_") as tmp:
            ws = Path(tmp)
            runner.build_workspace(ws)
            for l in luts:
                runner.write_lint(ws, runner.RenderedLint(
                    rule_id=l.rule_id, pkg=l.pkg, struct_name=l.struct,
                    file_content=l.code, imports=set(), statement="",
                    template_id="<p2>", slots={}))
            (ws / "main.go").write_text("package main\nfunc main(){}\n")
            r = subprocess.run(["go", "build", "./pkgs/..."], cwd=ws,
                               capture_output=True, text=True, timeout=600)
            failed_pkgs = {ln[2:].split("/")[-1] for ln in r.stderr.splitlines()
                           if ln.startswith("# ")}
            for l in luts:
                if l.pkg in failed_pkgs:
                    compile_fail[l.rule_id] = True
                else:
                    compiles.add(str(l.rule_id))

    guaranteed = [l for l in luts if str(l.rule_id) in compiles]

    print("=" * 64)
    print("PHASE 2 — synonymy-guaranteed via certified deterministic path")
    print("=" * 64)
    print(f"  target rules (need new lint)        : {len(target)}")
    print(f"  deterministically reducible+render  : {len(reducible)}")
    print(f"    ├─ all atoms certified + compiles  : {len(guaranteed)}   <-- SYNONYMY-GUARANTEED (code==IR)")
    print(f"    ├─ uses uncertified/approx atom    : {len(uncertified)}")
    print(f"    └─ compile-fail after render       : {len(compile_fail)}")
    print(f"  render error                         : {len(render_err)}")
    if uncertified:
        bad_atoms = Counter(a for _, bads in uncertified for a in bads)
        print(f"\n  uncertified-atom breakdown (why not guaranteed): {dict(bad_atoms.most_common())}")

    # over-strictness sentinel over the guaranteed set (IR!=rule signal; corpus narrow)
    print(f"\n  [over-strictness sentinel over {len(guaranteed)} guaranteed lints, "
          f"{len(list(O.REAL_CERTS.glob('*.pem')))} real certs]")
    if guaranteed:
        rep = O.sentinel(guaranteed, flag_frac=0.30)
        rep.pop("_parse_errors", None)
        flagged = sorted((v for v in rep.values() if v["flagged_overstrict"]),
                         key=lambda v: -v["error_frac"])
        print(f"  flagged over-strict (likely IR!=rule, missing scope): {len(flagged)}/{len(guaranteed)}")
        print(f"  clean on corpus                                     : {len(guaranteed)-len(flagged)}/{len(guaranteed)}")

    out = {"target": len(target), "reducible": len(reducible),
           "guaranteed": [l.rule_id for l in guaranteed],
           "uncertified": uncertified, "compile_fail": list(compile_fail),
           "render_err": render_err}
    (RES / "oracle_pipeline.json").write_text(json.dumps(out, indent=1, default=str))
    print(f"\n[saved] {RES / 'oracle_pipeline.json'}")
    print(f"\nvs old pipeline: 157 'accepted' rested on a single-vote judge; "
          f"{len(guaranteed)} now rest on per-atom cert proof (code==IR).")


if __name__ == "__main__":
    main()
