"""Deterministic coverage-validity gate — an only-downgrade operator.

The LLM field-judge (`zlint_interface.check_rule_coverage_intelligent`) decides
whether a native zlint lint covers a rule by comparing subject / obligation /
predicate / constraint. It has no *structural* guard, so it can return
``verdict="full"`` naming a lint that cannot actually enforce the rule:

  * the named lint does not exist in the bundled zlint v3 source (hallucinated);
  * the lint runs on CRLs (``RegisterRevocationListLint``) not certificates;
  * the lint's ``CheckApplies`` certificate class is disjoint from the rule's
    (e.g. a subscriber-only lint claimed for a Root-CA rule — the lint can never
    execute on the certificate the rule targets);
  * the rule is a MUST / MUST NOT but the lint only reports Notice / Warn.

This module derives that structural metadata deterministically from the zlint
Go source and downgrades an unsound ``full`` to ``none``. It ONLY downgrades —
it never turns a non-full verdict into full, and it never fires on a lint whose
``CheckApplies`` has no cert-class restriction (those apply to any certificate).

Semantic mismatch (right cert class, wrong requirement) is NOT in scope here —
that is the field-judge's job.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_ZLINT_LINTS = Path(__file__).resolve().parents[3] / "zlint" / "v3" / "lints"

_NORMATIVE_MUST = {"MUST", "MUST NOT", "SHALL", "SHALL NOT", "REQUIRED"}


def _checkapplies_body(text: str) -> str:
    m = re.search(r"func\s*\([^)]*\)\s*CheckApplies\s*\([^)]*\)\s*bool\s*\{", text)
    if not m:
        return ""
    depth, start = 0, m.end() - 1
    for j in range(start, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:j]
    return ""


def _applies_class(body: str) -> set:
    """Negation-aware certificate class of a CheckApplies body.

    Empty set = no cert-class restriction found (treat as 'any', never downgrade).
    """
    if not body:
        return set()
    body = re.sub(r"//[^\n]*", "", body)
    has = lambda pat: re.search(pat, body) is not None
    neg_ca = has(r"!\s*util\.IsCACert\s*\(") or has(r"!\s*c\.IsCA\b")
    pos_ca = (has(r"(?<!!)util\.IsCACert\s*\(") or has(r"(?<!!)\bc\.IsCA\b")) and not neg_ca
    pos_sub = has(r"(?<!!)util\.IsSubscriberCert\s*\(")
    pos_subca = has(r"(?<!!)util\.IsSubCA\s*\(")
    neg_root = has(r"!\s*util\.IsRootCA\s*\(")
    pos_root = has(r"(?<!!)util\.IsRootCA\s*\(") and not neg_root
    cls: set = set()
    if neg_ca or pos_sub:
        cls.add("subscriber")
    if pos_ca:
        cls |= {"sub_ca"} if neg_root else {"root_ca"} if pos_root else {"ca", "root_ca", "sub_ca"}
    if pos_subca:
        cls.add("sub_ca")
    if pos_root and not pos_ca:
        cls.add("root_ca")
    return cls


@lru_cache(maxsize=1)
def _lint_index() -> dict:
    """name -> {exists, is_crl, applies:set, severity} from zlint v3 source."""
    idx: dict = {}
    if not _ZLINT_LINTS.exists():
        return idx
    name_re = re.compile(r'Name:\s*"([a-z][a-z0-9_]+)"')
    for go in _ZLINT_LINTS.rglob("*.go"):
        if go.name.endswith("_test.go"):
            continue
        t = go.read_text(errors="ignore")
        if "cicasgen_" in t:
            continue
        names = name_re.findall(t)
        if not names:
            continue
        is_crl = "RegisterRevocationListLint(" in t
        applies = _applies_class(_checkapplies_body(t))
        if "ocsp" in go.name or "OcspSigning" in t or "IsDelegatedOCSP" in t:
            applies = (applies | {"ocsp"}) if applies else {"ocsp", "subscriber"}
        for n in names:
            m = idx.setdefault(n, {"exists": True, "is_crl": is_crl, "applies": set(),
                                   "severity": ("warn" if n.startswith("w_")
                                                else "notice" if n.startswith("n_")
                                                else "error")})
            m["applies"] |= applies
            m["is_crl"] = m["is_crl"] or is_crl
    return idx


# CABF §7.1.2.N -> certificate class the rule constrains ('any' = unrestricted).
def rule_cert_class(standard_id: int, section: str) -> set:
    if standard_id == 1:
        return {"any"}
    parts = (section or "").split(".")
    if len(parts) >= 4 and parts[:3] == ["7", "1", "2"]:
        try:
            n = int(parts[3])
        except ValueError:
            return {"any"}
        return ({1: {"root_ca", "ca"}, 2: {"sub_ca", "ca"}, 3: {"sub_ca", "ca"},
                 4: {"sub_ca", "ca"}, 5: {"sub_ca", "ca"}, 6: {"sub_ca", "ca"},
                 7: {"subscriber"}, 8: {"ocsp", "subscriber"}, 9: {"any"},
                 10: {"ca", "root_ca", "sub_ca"}, 11: {"any"}}).get(n, {"any"})
    return {"any"}


def validate_full_coverage(lint_name: str, standard_id: int, section: str,
                           obligation: str) -> tuple[bool, str]:
    """Return (is_sound_full, downgrade_reason). Only judges 'full' verdicts.

    is_sound_full=True means the structural gate found no reason to downgrade
    (it does NOT assert semantic correctness). False means downgrade to none.
    """
    if "+" in (lint_name or ""):
        parts = [part.strip() for part in lint_name.split("+") if part.strip()]
        if not parts:
            return False, "covering lint union is empty"
        failures = []
        for part in parts:
            ok, why = validate_full_coverage(part, standard_id, section, obligation)
            if not ok:
                failures.append(f"{part}: {why}")
        if failures:
            return False, "covering lint union contains unsound member(s): " + "; ".join(failures)
        return True, ""
    meta = _lint_index().get(lint_name) if lint_name else None
    if not lint_name or meta is None:
        return False, "covering lint name does not exist in zlint v3 source"
    if meta["is_crl"]:
        return False, "covering lint is a CRL (RevocationList) lint; cannot enforce a certificate rule"
    rule_class = rule_cert_class(standard_id, section)
    ap = meta["applies"]
    if ap and "any" not in rule_class and not (ap & rule_class):
        return False, (f"covering lint CheckApplies class {sorted(ap)} is disjoint from "
                       f"the rule's certificate class {sorted(rule_class)}")
    ob = (obligation or "").upper().replace("_", " ")
    if ob in _NORMATIVE_MUST and meta["severity"] in ("warn", "notice"):
        return False, (f"rule obligation {ob} but covering lint severity is "
                       f"{meta['severity']} (under-enforcement, not full)")
    return True, ""
