"""codegen/cascade.py — deterministic-first, LLM-fallback orchestration.

Two cascades, both honoring one principle: **try the deterministic path first;
only call the LLM when the deterministic path cannot solve it.** The paper's
reported codegen / synonymy numbers are the SUM of the two paths.

  generate_tree(rule)        DSL synthesis:
        det_codegen.deterministic_tree  (zero LLM)
          └─⊥─▶ LLM tree synthesis  (tree_prompt → call_llm → parse_tree_output)

  synonymy_verdict(tree, …)  synonymy gate:
        cert oracle  (all atoms certified + compiles ⇒ Code≡IR, zero judge)
          └─miss─▶ LLM judge  (judge_vote: denoised k-vote over rule_text vs σ_mech)

This module ONLY orchestrates. It reuses det_codegen / tree_prompt /
tree_codegen / synonym_judge / oracle_pipeline / runner / tree_to_natural
without re-implementing their logic (iron law: codegen logic lives in the
backend, in one place). All sibling imports are relative so every tree stays
in ONE dsl namespace (see tree_codegen.py import note).
"""
from __future__ import annotations

from typing import Optional

from . import det_codegen, tree_prompt, tree_codegen, synonym_judge
from . import oracle_pipeline, runner
from .tree_to_natural import tree_to_natural


def _render_and_compile(tree, precondition, rule: dict, workspace=None):
    """Render a tv-dsl tree (+ optional precondition) to a full lint and run
    `go build`. Returns (ok: bool, stderr: str). Shared by the LLM-codegen
    acceptance gate and the oracle synonymy path. Render itself can raise
    dsl.DSLError (e.g. a value the emitter cannot lower); treat that as a
    non-compiling result rather than letting it propagate.

    Pass `workspace` (a Path from runner.build_workspace) to reuse one Go module
    across many compiles — building a fresh workspace per call re-runs `go get`
    for zlint+zcrypto (~minutes each) and does not scale to the full domain."""
    try:
        out = tree_codegen.render_from_tree(tree, precondition, "lint.Error")
        rl = runner.render_full_lint_from_tree(
            int(rule.get("id") or 0),
            rule.get("source") or "RFC",
            str(rule.get("section") or ""),
            (rule.get("text") or "")[:180],
            out["execute_body"], out["imports"], tree=tree)
    except Exception as e:
        return False, f"render_error: {e}"
    return runner.compile_check_one(rl, workspace=workspace)


# ---------------------------------------------------------------------------
# DSL synthesis cascade
# ---------------------------------------------------------------------------
def generate_tree(rule: dict, *, workspace=None, allow_llm: bool = True) -> dict:
    """DSL synthesis cascade (deterministic-first; LLM only on ⊥).

    rule: {id, text, source, section, requirement_level, ir}
    workspace: optional shared Go workspace (runner.build_workspace) reused for
               the LLM-path compile gate; see _render_and_compile.
    allow_llm: when False, stop after the deterministic path and report the
               ⊥ as a residual (method=None, reason="deterministic_only")
               WITHOUT calling the LLM. The measurement's deterministic phase
               uses this so it stays zero-LLM / bit-reproducible; the LLM phase
               re-runs the residuals with allow_llm=True once quota is available.

    Returns dict:
      tree         tv-dsl predicate node, or None
      precondition tv-dsl precondition node, or None (LLM path only; det folds
                   conditions into `tree` via When already)
      method       "deterministic" | "llm" | None
      reason       residual reason when method is None
      llm_raw      raw LLM reply (≤300 chars) for the ledger freeze; "" for det
    """
    rid = int(rule.get("id") or 0)
    ir = rule.get("ir") or {}
    section = rule.get("section")

    # --- path 1: deterministic (zero LLM) ---
    try:
        tree = det_codegen.deterministic_tree(rid, ir, section=section)
    except Exception:
        tree = None
    if tree is not None:
        # A returned tree is not yet a guarantee: det_codegen's _renderable check
        # is weaker than full render + `go build` (e.g. a FieldInSet whose value
        # is prose, or a charset-less ASN.1 type). Only count "deterministic" when
        # the tree actually COMPILES — same bar the LLM path must clear. A returned
        # tree that does not compile means the deterministic path did NOT solve it,
        # so fall through to the LLM (honoring deterministic-first). The compile
        # gate runs only when a workspace is supplied (the measurement passes one);
        # without it we keep the legacy "tree returned" behavior for cheap callers.
        if workspace is None:
            return {"tree": tree, "precondition": None,
                    "method": "deterministic", "reason": "", "llm_raw": ""}
        ok, stderr = _render_and_compile(tree, None, rule, workspace=workspace)
        if ok:
            return {"tree": tree, "precondition": None,
                    "method": "deterministic", "reason": "", "llm_raw": ""}
        det_noncompile_reason = "deterministic_noncompile: " + (stderr or "")[:140]
    else:
        det_noncompile_reason = None

    # --- path 2: LLM tree synthesis (only when deterministic returns ⊥) ---
    def _residual(reason, raw=""):
        return {"tree": None, "precondition": None, "method": None,
                "reason": reason, "llm_raw": (raw or "")[:300]}

    if not allow_llm:
        return _residual(det_noncompile_reason or "deterministic_only")

    try:
        prompt = tree_prompt.build_prompt_first(rule)
        raw = synonym_judge.call_llm(prompt)
    except Exception as e:
        return _residual(f"llm_call_error: {e}")
    if isinstance(raw, str) and raw.startswith("__ERROR__"):
        return _residual("llm_endpoint_error", raw)
    obj = synonym_judge.parse_json_block(raw)
    if obj is None:
        return _residual("llm_unparseable", raw)
    try:
        parsed = tree_codegen.parse_tree_output(obj)
    except Exception as e:
        return _residual(f"parse_tree_error: {e}", raw)
    if parsed.get("no_template"):
        return _residual("no_template: " + str(parsed.get("reason", "")), raw)
    errs = tree_codegen.validate_parsed(parsed)
    if errs:
        return _residual("validate_fail: " + "; ".join(map(str, errs))[:180], raw)

    tree = parsed["predicate"]
    precond = parsed.get("precondition")
    ok, stderr = _render_and_compile(tree, precond, rule, workspace=workspace)
    if not ok:
        return _residual("compile_fail: " + (stderr or "")[:180], raw)
    return {"tree": tree, "precondition": precond,
            "method": "llm", "reason": "", "llm_raw": (raw or "")[:300]}


# ---------------------------------------------------------------------------
# Synonymy gate — LLM judge only (Code ≡ Spec)
# ---------------------------------------------------------------------------
# Synonymy asks "does the code faithfully express the SPECIFICATION TEXT"
# (Code ≡ Spec). Only the judge can answer it — it reads the rule text and
# compares meaning. The certificate oracle proves Code ≡ IR, a DIFFERENT and
# narrower claim that does NOT read the spec; an oracle-certified lint can still
# fail Code ≡ Spec when the IR lost information during extraction. A cross-check
# (judge over all oracle-certified lints) showed the judge dissents on ~1/3 of
# them. So synonymy is measured by the judge alone; the oracle is reported
# separately (code_eq_ir_certified) as a deterministic Code ≡ IR soundness
# signal whose disagreement with the judge LOCALIZES the failure to extraction.
def synonymy_verdict(tree, rule_text: str, *,
                     precondition=None,
                     profile_scope: Optional[str] = None,
                     k: int = 5) -> dict:
    """Synonymy gate (LLM denoised judge; Code ≡ Spec).

    Returns the judge tally: verdict ("EXPRESSES"|"DOES_NOT_EXPRESS"),
    n_expresses, n_dne, agreement, sample_why, plus path="judge".
    """
    sm = tree_to_natural(tree, precondition)
    res = synonym_judge.judge_vote(rule_text, sm, k=k, profile_scope=profile_scope)
    res["path"] = "judge"
    res.setdefault("judge_raw", res.get("sample_why", ""))
    return res


def code_eq_ir_certified(tree, precondition=None, *, rule: Optional[dict] = None,
                         rule_text: str = "", section: str = "",
                         workspace=None) -> bool:
    """Deterministic certificate oracle: True iff every atom in the tree (and
    precondition) is certified-faithful AND the rendered lint compiles. Such a
    lint provably implements its IR predicate (Code ≡ IR) by structural
    composition over per-atom-verified emitters — no LLM. This is NOT a synonymy
    measure (it does not read the spec); it is reported alongside the judge as a
    soundness signal and to localize synonymy failures to the extraction step."""
    rule = rule or {"id": 0, "text": rule_text, "source": "RFC", "section": section}
    ok_pred, _ = oracle_pipeline.tree_all_certified(tree)
    ok_cond = True
    if precondition is not None:
        ok_cond, _ = oracle_pipeline.tree_all_certified(precondition)
    if not (ok_pred and ok_cond):
        return False
    compiled, _err = _render_and_compile(tree, precondition, rule, workspace=workspace)
    return bool(compiled)
