"""templates_v2 / tree_codegen.py — tree-only codegen helper.

Replaces the 40-template catalog with a single rendering interface that
takes a parsed DSL tree (predicate + optional precondition) and emits
the lint Execute body. The LLM no longer chooses among 40 templates;
it outputs a predicate tree directly. This collapses one layer of
LLM decision and removes the "LLM picks single-purpose template and
silently drops the other half of a compound predicate" failure mode.
"""
from __future__ import annotations

from typing import Optional

# Relative import so dsl/render/vocab resolve to the SAME module objects as the
# rest of the codegen package (det_codegen, oracle_pipeline, tree_to_natural all
# use `from . import dsl`). A hardcoded `cicas_backend.app...` prefix here would
# load a SECOND copy of these modules when the package is imported under the bare
# `app...` namespace (e.g. by the measurement scripts), so a det-produced tree
# (namespace A) would hit render dispatch keyed on namespace-B classes and raise
# "unhandled node" on every isinstance check. Following the loader namespace
# keeps trees from det_codegen and the LLM tree path renderable by one render.
from . import dsl, render, vocab as V


_COMPOUND_BODY = """\
        if {expr} {{
            return &lint.LintResult{{Status: lint.Pass}}
        }}
        return &lint.LintResult{{Status: {severity}}}"""

_CONDITIONAL_BODY = """\
        if !({pre}) {{
            return &lint.LintResult{{Status: lint.NA}}
        }}
        if {req} {{
            return &lint.LintResult{{Status: lint.Pass}}
        }}
        return &lint.LintResult{{Status: {severity}}}"""

_CONDITIONAL_BODY_NEG_PRE = """\
        if {pre_inner} {{
            return &lint.LintResult{{Status: lint.NA}}
        }}
        if {req} {{
            return &lint.LintResult{{Status: lint.Pass}}
        }}
        return &lint.LintResult{{Status: {severity}}}"""


def render_from_tree(predicate: dsl.Compound,
                     precondition: Optional[dsl.Compound] = None,
                     severity: str = "lint.Error") -> dict:
    """Render a DSL predicate (and optional precondition) into Go body
    + imports. Returns dict with keys: execute_body, imports, dsl_tree.
    Raises dsl.DSLError on rendering inconsistency.
    """
    if severity not in ("lint.Error", "lint.Warn", "lint.Notice"):
        raise dsl.DSLError(f"unknown severity {severity!r}")

    if precondition is None:
        expr = render.render(predicate)
        body = _COMPOUND_BODY.format(expr=expr, severity=severity)
        imps = render.collect_imports(predicate)
        return {"execute_body": body, "imports": imps,
                "dsl_tree": predicate}
    else:
        # Double-negation simplification: when precondition = Not(inner),
        # the conditional template `if !(precondition) { NA }` would emit
        # `if !(!(inner_expr)) { NA }`. This is correct Go but the semantic
        # extractor cannot reliably unwind two layers of `!`. Render the
        # `if !(precondition)` as `if (inner_expr)` directly, preserving
        # behavior while keeping the `if X { NA }` shape that the extract
        # prompt is calibrated to read.
        if isinstance(precondition, dsl.Not):
            pre_neg_expr = render.render(precondition.inner)
            body = _CONDITIONAL_BODY_NEG_PRE.format(
                pre_inner=pre_neg_expr,
                req=render.render(predicate),
                severity=severity)
            imps = (render.collect_imports(predicate)
                    | render.collect_imports(precondition.inner))
        else:
            body = _CONDITIONAL_BODY.format(
                pre=render.render(precondition),
                req=render.render(predicate),
                severity=severity)
            imps = (render.collect_imports(predicate)
                    | render.collect_imports(precondition))
        return {"execute_body": body, "imports": imps,
                "dsl_tree": (precondition, predicate)}


def parse_tree_output(obj: dict) -> dict:
    """Parse the LLM's tree-output JSON into a structured codegen request.

    Lenient about no_template phrasing — LLM may emit any of:
      {"no_template": true, "reason": "..."}
      {"reason": "...", "predicate": null}
      {"reason": "..."}                       (no predicate key)
      {"no_template": "true", ...}            (string instead of bool)

    Strict about everything else.
    """
    if obj.get("no_template") in (True, "true", "True", 1):
        return {"no_template": True, "reason": str(obj.get("reason", ""))}

    pred_obj = obj.get("predicate")
    # Lenient no_template: if predicate is null/missing AND a reason field is present,
    # treat as no_template
    if pred_obj is None:
        if obj.get("reason") or obj.get("explanation") or obj.get("error"):
            reason = str(obj.get("reason") or obj.get("explanation")
                         or obj.get("error"))
            return {"no_template": True, "reason": reason}
        raise dsl.DSLError(
            "missing 'predicate' field in tree output (and no 'reason'/"
            "'no_template' alternative). Either include 'predicate' with "
            "a DSL tree, or emit {\"no_template\": true, \"reason\": \"...\"}.")

    pred_node = dsl.parse(pred_obj)
    pre_obj = obj.get("precondition")
    pre_node = dsl.parse(pre_obj) if pre_obj else None

    severity = obj.get("severity", "lint.Error")
    label = str(obj.get("label", "")).strip()

    return {
        "no_template": False,
        "predicate": pred_node,
        "precondition": pre_node,
        "severity": severity,
        "label": label,
    }


def validate_parsed(parsed: dict) -> list:
    """Run DSL semantic validation on a parsed tree result."""
    if parsed.get("no_template"):
        return []
    errs = list(dsl.validate(parsed["predicate"]))
    if parsed.get("precondition") is not None:
        errs.extend(dsl.validate(parsed["precondition"]))
    return errs


if __name__ == "__main__":
    # Smoke: encoded_as + length compound
    raw = {
        "predicate": {"op": "And", "args": [
            {"op": "FieldEncodedAs",
             "args": ["Subject.Organization", ["UTF8String", "PrintableString"]]},
            {"op": "FieldLenInRange",
             "args": ["Subject.Organization", 0, 64]},
        ]},
        "precondition": None,
        "severity": "lint.Error",
        "label": "Organization MUST be UTF8|Printable and <=64",
    }
    parsed = parse_tree_output(raw)
    errs = validate_parsed(parsed)
    print(f"validate errs: {errs}")
    out = render_from_tree(parsed["predicate"], parsed["precondition"],
                           parsed["severity"])
    print("--- rendered ---")
    print(out["execute_body"])
    print(f"imports: {sorted(out['imports'])}")
