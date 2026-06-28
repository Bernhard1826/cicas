"""codegen/detection/blame.py — attribute a spurious / over-broad generated lint to
the PIPELINE STAGE that produced it.

Per the iron law we never patch the generated Go or the stored IR; we name the
stage at fault and emit a re-extraction / re-check request. This is the
automation of the hand-written QUARANTINE dict in inject_and_build.py.

Blame stages (checked in this order — strongest evidence first):
  SCOPE_TOO_BROAD          cert-grounded: the lint fired on a self-signed Root CA
                           for a rule that governs only Subordinate CAs (or an AKI
                           rule that roots may skip). Fix surface = ir.section_scope
                           / intree_emitter scope map. -> re_extract_scope
  IR_GARBLED_TEXT          rule_text is a URL fragment / truncated cell. -> re_extract
  IR_SUBJECT_SCOPE_COLLAPSE  subject widened to a whole extension while the text
                           names a specific identifier/qualifier. -> re_extract
  IR_DROPPED_PRECONDITION  ir.precondition empty but the text is genuinely
                           conditional ("if/when ... present"). -> re_extract
  CODEGEN_OR_SYNONYMY      IR looks faithful, lint still over-strict (downstream of
                           extraction). -> re_judge

`classify` is pure (rule dict + spurious cert names + a self-signed predicate).
`blame` wires it to the DB and the testdata directory via injectable callables so
the module stays testable and DB-policy lives in one place.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Callable, Optional

# .../codegen/detection/blame.py -> parents[5] == cicas_backend/
_BACKEND = Path(__file__).resolve().parents[5]
DEFAULT_TESTDATA = _BACKEND / "zlint" / "v3" / "testdata"
_DB = "postgresql://postgres:123456@localhost:15432/cicas"

_RID_RE = re.compile(r"_(\d+)$")
# a genuine APPLICABILITY condition needs a conditional connective — a bare
# "MUST be present" is an unconditional presence obligation, not a condition.
_CONDITIONAL_CUE = re.compile(
    r"\b(if|when|whenever|unless|only if|in case|provided that)\b"
    r"[^.]*\b(present|absent|included|contains|set|exists)\b"
    r"|\b(if|when|unless|where)\b\s+\w+\s+(is|are)\b", re.I)
_URL_FRAGMENT = re.compile(r"(org/doc/html|rfc\d+\)|https?://|/html/)", re.I)
_BARE_EXT = re.compile(r"^extensions\.[a-z0-9]+$", re.I)
_NAMES_SPECIFIC = re.compile(
    r"identifier|qualifier|policy identifier|attribute|givenname|surname|"
    r"anypolicy|notice|cps|component", re.I)


def rule_id_of(lint_name: str) -> Optional[int]:
    m = _RID_RE.search(lint_name or "")
    return int(m.group(1)) if m else None


# --- injectable side-effect helpers (DB read, cert reverse-check) ----------

def db_rule_fetcher(db_url: str = _DB) -> Callable[[set], dict]:
    """Return a fetcher(rule_ids) -> {rid: {section,title,text,ir,source}} that
    reads the rules table. Imported lazily so importing blame needs no psycopg2."""
    def fetch(rule_ids: set) -> dict:
        if not rule_ids:
            return {}
        import psycopg2
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute(
            "SELECT r.id, r.section, r.title, r.text, r.ir_data, s.source "
            "FROM rules r JOIN standards s ON r.standard_id=s.id "
            "WHERE r.id = ANY(%s)", (list(rule_ids),))
        out = {}
        for rid, section, title, text, ir_data, source in cur.fetchall():
            ir_data = ir_data if isinstance(ir_data, dict) else json.loads(ir_data)
            out[rid] = {"section": section, "title": title, "text": text,
                        "ir": ir_data.get("ir", {}) or {}, "source": source}
        conn.close()
        return out
    return fetch


def make_self_signed_check(testdata: Path = DEFAULT_TESTDATA) -> Callable[[str], Optional[bool]]:
    """Return is_self_signed(cert_name) -> bool|None using openssl on a testdata
    cert (a self-signed cert is a Root CA candidate)."""
    def is_self_signed(cert_name: str) -> Optional[bool]:
        p = Path(testdata) / cert_name
        if not p.exists():
            return None
        try:
            subj = subprocess.run(["openssl", "x509", "-in", str(p), "-noout",
                                   "-subject", "-nameopt", "RFC2253"],
                                  capture_output=True, text=True).stdout
            issr = subprocess.run(["openssl", "x509", "-in", str(p), "-noout",
                                   "-issuer", "-nameopt", "RFC2253"],
                                  capture_output=True, text=True).stdout
        except Exception:
            return None
        s = subj.split("=", 1)[-1].strip()
        i = issr.split("=", 1)[-1].strip()
        return bool(s and s == i)
    return is_self_signed


# --- the pure classifier ---------------------------------------------------

def classify(rule: dict, spurious_certs: list[str],
             is_self_signed: Callable[[str], Optional[bool]]) -> dict:
    """Return {blame_stage, evidence, action}. Pure given the three inputs."""
    ir = rule["ir"]
    text = (rule["text"] or ir.get("description") or "")
    subject = str(ir.get("subject") or "")
    precond = ir.get("precondition")
    section = str(rule["section"] or "")
    lint_name = (ir.get("lint_name") or "")

    # 0. SCOPE_TOO_BROAD — cert-grounded reverse-check (highest confidence).
    sub_ca_section = section.startswith("7.1.2.2") or section.startswith("7.1.2.3")
    aki_rule = ("keyidentifier" in subject.lower() or "key_id" in lint_name
                or "authoritykeyidentifier" in lint_name.lower())
    if sub_ca_section or aki_rule:
        roots = [c for c in spurious_certs if is_self_signed(c)]
        if roots:
            why = (f"§{section} governs Subordinate CAs" if sub_ca_section
                   else "AKI keyIdentifier may be omitted by Root CAs")
            return {"blame_stage": "SCOPE_TOO_BROAD",
                    "evidence": f"{why}, but the lint fired on self-signed Root "
                                f"CA(s): {roots[:3]}",
                    "action": "re_extract_scope"}

    # 1. garbled rule_text
    if _URL_FRAGMENT.search(text):
        return {"blame_stage": "IR_GARBLED_TEXT",
                "evidence": f"rule_text looks like a URL/truncated fragment: {text[:80]!r}",
                "action": "re_extract"}

    # 2. subject collapsed to a whole extension while text names something specific
    if _BARE_EXT.match(subject) and _NAMES_SPECIFIC.search(text):
        return {"blame_stage": "IR_SUBJECT_SCOPE_COLLAPSE",
                "evidence": f"subject={subject!r} (bare extension) but rule names a "
                            f"specific element: {text[:80]!r}",
                "action": "re_extract"}

    # 3. dropped precondition
    if precond in (None, {}, "") and _CONDITIONAL_CUE.search(text):
        return {"blame_stage": "IR_DROPPED_PRECONDITION",
                "evidence": f"ir.precondition is empty but rule text is conditional: "
                            f"{text[:80]!r}",
                "action": "re_extract"}

    # 4. IR looks faithful -> downstream
    return {"blame_stage": "CODEGEN_OR_SYNONYMY",
            "evidence": "IR fields look faithful (subject specific, precondition "
                        "consistent) yet the lint is over-strict",
            "action": "re_judge"}


def blame(by_lint: list[dict], findings: list[dict], *,
          rule_fetcher: Optional[Callable[[set], dict]] = None,
          is_self_signed: Optional[Callable[[str], Optional[bool]]] = None) -> list[dict]:
    """Attribute every suspect lint. Returns the SAIV feedback ledger (a list of
    records). rule_fetcher / is_self_signed default to the DB + testdata helpers."""
    rule_fetcher = rule_fetcher or db_rule_fetcher()
    is_self_signed = is_self_signed or make_self_signed_check()

    from collections import defaultdict
    spurious_by_lint = defaultdict(list)
    for f in findings:
        if f["verdict"] == "SPURIOUS":
            spurious_by_lint[f["lint"]].append(f["cert"])

    suspects = [r for r in by_lint if r["suspect"]]
    rule_ids = {rule_id_of(r["lint"]) for r in suspects} - {None}
    irs = rule_fetcher(rule_ids)

    ledger = []
    for r in suspects:
        rid = rule_id_of(r["lint"])
        rule = irs.get(rid)
        if rule is None:
            continue
        cls = classify(rule, spurious_by_lint.get(r["lint"], []), is_self_signed)
        ledger.append({
            "rule_id": rid, "lint": r["lint"], "section": rule["section"],
            "source": rule["source"], "fires": r["fires"], "applies": r["applies"],
            "error_frac": r["error_frac"],
            "verdicts": {"REAL": r["REAL"], "SPURIOUS": r["SPURIOUS"],
                         "UNCERTAIN": r["UNCERTAIN"]},
            **cls,
        })
    ledger.sort(key=lambda x: (x["blame_stage"], -x["error_frac"]))
    return ledger
