"""
Lintability judgment — trusted source of truth is the IR lintable field.

The IR lintable field is produced by ir_schema.auto_determine_lintable()
which enforces the four-condition framework (§5 of the paper):
  C1 obligation is normative (RFC 2119 except MAY/OPTIONAL)
  C2 assertion_subject is Certificate (single-certificate observable)
  C3 enforcement_phase is Encoding (or unset)
  C4 rule_category allows linting (whitelist: encoding/structural)

All repair operators (SAIV loop, feedback re-extraction, etc.) fix the
four-condition framework and re-extract — they do NOT patch the lintable
flag downstream.  This module is a thin facade that exposes the DB
decision to callers.
"""
from typing import Dict, Any


def judge_lintability(ir: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a lintability verdict for the given IR.

    The only authoritative signal is ir['lintable'] (produced by
    auto_determine_lintable).  This function wraps it in the
    canonical result format so callers don't need to know where
    lintable comes from.

    Returns:
        {
            "result": "strong" | "none",
            "can_generate": bool,
            "strength": "strong" | None,
            "reason_code": "PASS" | "FAILED",
            "explanation": str,
            "failed_step": str | None,
        }
    """
    ir_lintable = ir.get('lintable')
    if ir_lintable is None:
        # Compat: old IRs used 'is_lintable'
        ir_lintable = ir.get('is_lintable')

    if ir_lintable is None:
        # No lintable field at all — treat as unknown (caller decides)
        return {
            "result": "none",
            "can_generate": False,
            "strength": None,
            "reason_code": "MISSING",
            "explanation": "IR has no lintable field",
            "failed_step": "MissingField",
        }

    if ir_lintable:
        return {
            "result": "strong",
            "can_generate": True,
            "strength": "strong",
            "reason_code": "PASS",
            "explanation": "IR lintable=True (four-condition framework)",
            "failed_step": None,
        }
    else:
        # Build a readable reason from the IR's own fields
        parts = []
        subj = ir.get('assertion_subject', '')
        if subj:
            parts.append(f"assertion_subject={subj}")
        cat = ir.get('rule_category', '')
        if cat:
            parts.append(f"rule_category={cat}")
        phase = ir.get('enforcement_phase', '')
        if phase:
            parts.append(f"phase={phase}")
        reason = '; '.join(parts) if parts else 'Four-condition framework'

        failed_step = ir.get('failed_step')
        if not failed_step:
            failed_step = _infer_failed_step(ir)

        return {
            "result": "none",
            "can_generate": False,
            "strength": None,
            "reason_code": "FAILED",
            "explanation": f"IR lintable=False: {reason}",
            "failed_step": failed_step,
        }


def _infer_failed_step(ir: Dict[str, Any]) -> str:
    """Heuristic: infer which condition failed from IR fields."""
    # Try structured fields first
    subj = ir.get('assertion_subject', '')
    if subj and subj != 'Certificate':
        return 'C2_AssertionSubject'

    cat = ir.get('rule_category', '')
    lintable_cats = {'encoding_constraint', 'structural_constraint'}
    if cat and cat not in lintable_cats:
        return 'C4_RuleCategory'

    phase = ir.get('enforcement_phase', '')
    if phase and phase != 'Encoding':
        return 'C3_EnforcementPhase'

    return 'C1_Obligation'


# ---- Legacy compatibility (no longer needed after callers are updated) ----
# The LintabilityJudge class is removed.  If any old code still imports it,
# this stub prevents NameError.

class LintabilityJudge:
    """Legacy stub — do not use.  Call judge_lintability(ir) instead."""

    def __init__(self, knowledge_graph=None):
        pass

    def determine_zlint_lintability(self, ir: Dict[str, Any]) -> Dict[str, Any]:
        return judge_lintability(ir)
