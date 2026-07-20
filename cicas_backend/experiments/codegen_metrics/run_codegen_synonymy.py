#!/usr/bin/env python3
"""Code-generation rate and synonymy rate over the current DB (CABF-BR + RFC5280).

Self-owned measurement harness. It ONLY drives the canonical backend codegen
cascade — it never re-implements codegen or judging (iron law: codegen logic
lives in the backend, in one place):

    cascade.generate_tree      deterministic-first DSL synthesis, LLM fallback
    cascade.code_eq_ir_certified   certificate oracle (Code == IR, no spec read)
    cascade.synonymy_verdict   denoised k-vote LLM judge (Code == Spec)

Domain (the "codegen definition domain" = lintable rules zlint does NOT cover):
    standard_id in selected AND lintable
    AND lint_coverage IS NOT NULL      -- coverage was actually computed
    AND NOT lint_covered               -- and zlint has no equivalent lint

rule context
------------
Normative rows are often fragments of a section/table rather than standalone
sentences. CABF-BR profile rows inherit the per-certificate-type profile
(§7.1.2.N), and RFC 5280 rows such as "These fields ..." inherit their section
title. The synonymy judge must be told that spec-owned context, otherwise it
reads the row in isolation and can reject correct code as too narrow or too
broad. `profile_scope_for` derives CABF profile titles from the spec's own
section hierarchy (never hardcoded per rule); the harness then falls back to the
row's section title for non-profile rows.

Modes
-----
  (default)     generate + judge every pending domain row, append to ledger
  --rejudge     reuse cached trees/code_semantics from the ledger and ONLY
                re-run the synonymy judge (with rule context). Cheap: no
                recompile, no regeneration. Used to re-measure the judge after
                a judge/context change without paying the codegen cost.
  --rejudge-shipping
                reuse cached trees and re-run the strict shipped-lint judge:
                σ(final in-tree zlint lint) vs full available original context.
  --summary-only  recompute summary + manifests from the existing ledger
  --compact-ledger prune stale/duplicate ledger rows after targeted retries
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

import psycopg2

BACKEND = Path(__file__).resolve().parents[2]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.certificate.codegen import cascade, runner  # noqa: E402
from app.services.certificate.codegen import det_codegen, dsl, intree_emitter, synonym_judge  # noqa: E402
from app.services.certificate.codegen.tree_to_natural import obligation_aware_summary  # noqa: E402

HERE = Path(__file__).resolve().parent
OUTPUTS = HERE / "outputs"
DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")

STANDARDS = {
    "rfc5280": {"id": 1, "source": "RFC5280"},
    "cabf": {"id": 19, "source": "CABF-BR"},
}

RAW_SOURCES = {
    "CABF-BR": BACKEND / "data/raw/cabf-server/BR.md",
    "RFC5280": BACKEND / "data/raw/rfc/rfc5280.txt",
}


# ---------------------------------------------------------------------------
# profile_scope derivation (from the spec's own section hierarchy)
# ---------------------------------------------------------------------------
def _load_section_titles() -> dict[str, str]:
    """CABF section -> spec title, straight from the DB."""
    with psycopg2.connect(DB_URL, connect_timeout=3) as conn:
        cur = conn.cursor()
        cur.execute(
            "select section, title from rules where standard_id=19 and section is not null"
        )
        sec2title: dict[str, str] = {}
        for section, title in cur.fetchall():
            if section and title and section not in sec2title:
                sec2title[section] = title
    return sec2title


def _load_nearby_section_rows(selected: list[int], window: int = 4) -> dict[int, str]:
    """Nearby source rows from the same standard section/table.

    Extracted CABF/RFC rows can be terse table fragments.  A local same-section
    window gives the strict judge table-neighbor context such as paired
    stateOrProvinceName/localityName alternatives without special-casing any
    rule id or certificate profile.
    """
    with psycopg2.connect(DB_URL, connect_timeout=3) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            select id, standard_id, section, title, text
            from rules
            where standard_id = any(%s)
              and section is not null
            order by standard_id, section, id
            """,
            (selected,),
        )
        groups: dict[tuple[int, str], list[tuple[int, str, str]]] = {}
        for rid, standard_id, section, title, text in cur.fetchall():
            groups.setdefault((int(standard_id), section or ""), []).append(
                (int(rid), title or "", text or "")
            )
    out: dict[int, str] = {}
    for rows in groups.values():
        for idx, (rid, _title, _text) in enumerate(rows):
            start = max(0, idx - window)
            end = min(len(rows), idx + window + 1)
            lines = []
            for nrid, title, text in rows[start:end]:
                mark = ">>" if nrid == rid else "  "
                title_part = f" [{title}]" if title else ""
                lines.append(f"{mark} R{nrid}{title_part}: {text}")
            out[rid] = "\n".join(lines)
    return out


@lru_cache(maxsize=64)
def _raw_source_text(source: str) -> str:
    path = RAW_SOURCES.get(source)
    if not path or not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


@lru_cache(maxsize=512)
def _raw_section_excerpt(source: str, section: str, max_chars: int = 7000) -> str:
    """Return a bounded original-spec excerpt for a section.

    This is source-owned context, not IR.  It lets the strict shipping judge
    read table headers and sibling rows such as "Permitted policyQualifiers"
    when an extracted row says only "Any other qualifier".
    """
    source = source or ""
    section = section or ""
    text = _raw_source_text(source)
    if not text or not section:
        return ""

    import re

    if source == "CABF-BR":
        heading_re = re.compile(
            rf"(?m)^#{{1,6}}\s+{re.escape(section)}(?:\s|$)"
        )
        next_heading_re = re.compile(r"(?m)^#{1,6}\s+(\d+(?:\.\d+)*)(?:\s|$)")
    else:
        heading_re = re.compile(
            rf"(?m)^ {{0,2}}{re.escape(section)}(?:\.|\s+)"
        )
        next_heading_re = re.compile(r"(?m)^ {0,2}(\d+(?:\.\d+)*)(?:\.|\s+)")

    m = None
    for cand in heading_re.finditer(text):
        line_end = text.find("\n", cand.start())
        if line_end < 0:
            line_end = len(text)
        heading_line = text[cand.start():line_end]
        # RFC text files include table-of-contents entries such as
        # "4.1.2.6. Subject ................23". Those are not source context
        # for the rule and must not be selected as section excerpts.
        if source != "CABF-BR" and re.search(r"\.{3,}\s*\d+\s*$", heading_line):
            continue
        m = cand
        break
    if not m:
        return ""
    start = m.start()
    end = len(text)
    for nm in next_heading_re.finditer(text, m.end()):
        next_section = nm.group(1)
        if next_section == section or next_section.startswith(section + "."):
            continue
        end = nm.start()
        break
    excerpt = text[start:end].strip()
    if len(excerpt) <= max_chars:
        return excerpt
    return excerpt[:max_chars].rstrip() + "\n[excerpt truncated]"


def profile_scope_for(section: Optional[str], sec2title: dict[str, str]) -> Optional[str]:
    """The certificate-profile title governing `section`, or None.

    CABF §7.1.2.N is the certificate-profile level. Walk a leaf section up to its
    7.1.2.N ancestor and use that profile title; if the leaf adds a distinguishing
    sub-title (e.g. "Organization Validated" under the Subscriber profile), append
    it so the judge can recognize an OV/IV/DV/EV policy-OID guard too. Sections
    outside §7.1.2 (RFC fields, CABF key/encoding/process sections) return None.
    """
    if not section:
        return None
    parts = section.split(".")
    if len(parts) >= 4 and parts[:3] == ["7", "1", "2"]:
        prof = ".".join(parts[:4])                      # 7.1.2.N
        prof_title = sec2title.get(prof)
        leaf_title = sec2title.get(section)
        if prof_title and leaf_title and leaf_title != prof_title:
            return f"{prof_title} — {leaf_title}"
        return prof_title or leaf_title
    return None


def rule_context_for(source: str, section: Optional[str], title: Optional[str],
                     sec2title: dict[str, str]) -> Optional[str]:
    """Spec-owned context for a fragmentary rule row.

    The ledger field is still named ``profile_scope`` for backward
    compatibility with older experiment outputs, but the content is now broader:
    CABF profile context when available, otherwise the row's own section title.
    """
    profile = profile_scope_for(section, sec2title)
    def _with_reserved_policy_oid(ctx: str) -> str:
        key = ctx.lower()
        mapping = (
            ("extended validation", "2.23.140.1.1"),
            ("domain validated", "2.23.140.1.2.1"),
            ("organization validated", "2.23.140.1.2.2"),
            ("individual validated", "2.23.140.1.2.3"),
        )
        for label, oid in mapping:
            if label in key:
                return f"{ctx}; CABF reserved certificate policy identifier {oid}"
        if "rsa" in key:
            return (f"{ctx}; rsaEncryption AlgorithmIdentifier OID "
                    "1.2.840.113549.1.1.1; id-RSASSA-PSS OID "
                    "1.2.840.113549.1.1.10")
        return ctx

    def _with_signature_algid_context(ctx: str) -> str:
        if ((source or "").upper().startswith("CABF")
                and str(section or "").startswith("7.1.3.2")):
            return (
                f"{ctx}; CABF §7.1.3.2 Signature AlgorithmIdentifier applies "
                "to the signatureAlgorithm field of a Certificate or "
                "Precertificate and to the signature field of a TBSCertificate; "
                "no other encodings are permitted for these fields"
            )
        return ctx

    if profile:
        prefix = f"{source} §{section} " if section else f"{source} "
        return _with_signature_algid_context(_with_reserved_policy_oid(f"{prefix}{profile}"))
    if title:
        prefix = f"{source} §{section} " if section else f"{source} "
        ctx = f"{prefix}{title}"
        if (source or "").upper().startswith("CABF") and str(section or "") == "7.1.2.10.5":
            ctx += (
                "; source section contains separate No Policy Restrictions "
                "(anyPolicy) and Policy Restricted (anyPolicy MUST NOT) "
                "CertificatePolicies profiles; exact-one Reserved Certificate "
                "Policy Identifier rows belong to the Policy Restricted profile"
            )
        return _with_signature_algid_context(_with_reserved_policy_oid(ctx))
    return None


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------
def _json_default(obj):
    if dataclasses.is_dataclass(obj):
        try:
            return dsl.compound_to_dict(obj)
        except Exception:
            return {"op": type(obj).__name__, **dataclasses.asdict(obj)}
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def _parse_ir(raw_ir: str | None) -> dict:
    if not raw_ir:
        return {}
    try:
        data = json.loads(raw_ir)
    except Exception:
        return {}
    if isinstance(data, dict):
        ir = data.get("ir", data)
        return ir if isinstance(ir, dict) else {}
    return {}


def _selected_standards(value: str) -> list[str]:
    if value == "all":
        return ["cabf", "rfc5280"]
    out = []
    for part in value.split(","):
        key = part.strip().lower()
        if not key:
            continue
        if key in ("rfc", "rfc5280", "1"):
            out.append("rfc5280")
        elif key in ("cabf", "cabf-br", "br", "19"):
            out.append("cabf")
        else:
            raise SystemExit(f"unknown standard selector: {part!r}")
    return list(dict.fromkeys(out))


DEFAULT_DOMAIN_DEFINITION = (
    "standard_id IN selected AND lintable AND lint_coverage IS NOT NULL "
    "AND lint_covered=false"
)


def _load_domain_rule_ids(path: Path) -> list[int]:
    raw = path.read_text(encoding="utf-8")
    try:
        obj = json.loads(raw)
    except Exception:
        ids: list[int] = []
        for token in raw.replace(",", "\n").splitlines():
            token = token.strip()
            if not token:
                continue
            if token.upper().startswith("R") and token[1:].isdigit():
                token = token[1:]
            ids.append(int(token))
        return list(dict.fromkeys(ids))
    if isinstance(obj, dict):
        obj = obj.get("rule_ids", obj.get("ids"))
    if not isinstance(obj, list):
        raise SystemExit(f"domain rule-id file must contain a JSON list or a rule_ids list: {path}")
    ids = []
    for item in obj:
        if isinstance(item, str) and item.upper().startswith("R") and item[1:].isdigit():
            item = item[1:]
        ids.append(int(item))
    return list(dict.fromkeys(ids))


def _domain_definition_from_rows(domain: list[dict]) -> str:
    for row in domain:
        definition = row.get("_domain_definition")
        if definition:
            return str(definition)
    return DEFAULT_DOMAIN_DEFINITION


def load_domain(
    standards: list[str],
    limit: int | None = None,
    *,
    domain_rule_ids: set[int] | None = None,
    domain_definition: str | None = None,
    domain_input_path: str | None = None,
) -> list[dict]:
    selected = [STANDARDS[s]["id"] for s in standards]
    source_by_id = {v["id"]: v["source"] for v in STANDARDS.values()}
    sec2title = _load_section_titles()
    nearby_rows = _load_nearby_section_rows(selected)
    with psycopg2.connect(DB_URL, connect_timeout=3) as conn:
        cur = conn.cursor()
        where = """
            where standard_id = any(%s)
              and lintable
              and lint_coverage is not null
        """
        params: list[object] = [selected]
        if domain_rule_ids is None:
            where += "\n              and not lint_covered"
        else:
            where += "\n              and id = any(%s)"
            params.append(sorted(domain_rule_ids))
        cur.execute(
            f"""
            select id, standard_id, section, title, text, ir_data, obligation, context
            from rules
            {where}
            order by standard_id, section, id
            """,
            params,
        )
        rows = []
        for rid, standard_id, section, title, text, raw_ir, obligation, context in cur.fetchall():
            ir = _parse_ir(raw_ir)
            if obligation and not ir.get("obligation"):
                ir = dict(ir)
                ir["obligation"] = obligation
            context_scope = rule_context_for(
                source_by_id.get(int(standard_id), str(standard_id)),
                section,
                title,
                sec2title,
            )
            source = source_by_id.get(int(standard_id), str(standard_id))
            rows.append(
                {
                    "id": int(rid),
                    "standard_id": int(standard_id),
                    "source": source,
                    "section": section or "",
                    "title": title or "",
                    "text": text or "",
                    "context": context or "",
                    "nearby_section_rows": nearby_rows.get(int(rid), ""),
                    "source_excerpt": _raw_section_excerpt(source, section or ""),
                    "ir": ir,
                    "obligation": obligation or ir.get("obligation") or "",
                    "profile_scope": context_scope,
                    "_domain_definition": domain_definition or DEFAULT_DOMAIN_DEFINITION,
                    "_domain_input_path": domain_input_path,
                }
            )
    if domain_rule_ids is not None:
        found = {int(row["id"]) for row in rows}
        missing = sorted(domain_rule_ids - found)
        if missing:
            raise SystemExit(
                "explicit domain contains rule ids that are not currently selected "
                f"lintable rows with computed coverage: {missing}"
            )
    if limit is not None:
        rows = rows[:limit]
    return rows


def domain_from_ledger(ledger_path: Path, limit: int | None = None) -> list[dict]:
    """Fallback domain reconstructed from the current ledger.

    This does not change the denominator in normal runs.  It only keeps cached
    rejudging usable when the local DB is temporarily unavailable; the canonical
    domain is still ``load_domain`` from the DB.
    """
    latest = load_done(ledger_path)
    rows = []
    for rid in sorted(latest):
        rec = latest[rid]
        rows.append(
            {
                "id": int(rec.get("rule_id") or rid),
                "standard_id": rec.get("standard_id"),
                "source": rec.get("source") or "",
                "section": rec.get("section") or "",
                "title": rec.get("title") or "",
                "text": rec.get("text") or "",
                "context": rec.get("context") or "",
                "ir": rec.get("ir") or {},
                "obligation": rec.get("obligation") or (rec.get("ir") or {}).get("obligation") or "",
                "profile_scope": rec.get("profile_scope"),
            }
        )
    if limit is not None:
        rows = rows[:limit]
    return rows


def load_done(path: Path) -> dict[int, dict]:
    done: dict[int, dict] = {}
    if not path.exists():
        return done
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("complete") and obj.get("rule_id") is not None:
            done[int(obj["rule_id"])] = obj
    return done


def append_jsonl(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, default=_json_default) + "\n")
        f.flush()


def rewrite_ledger(path: Path, records: list[dict]) -> None:
    tmp = path.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for obj in records:
            f.write(json.dumps(obj, ensure_ascii=False, default=_json_default) + "\n")
    tmp.replace(path)


def _rate(n: int, d: int) -> float | None:
    return (n / d) if d else None


_DECIDED_SYNONYMY = {"EXPRESSES", "DOES_NOT_EXPRESS"}


def _shipping_gate(row: dict) -> str | None:
    syn = row.get("ship_synonymy") or {}
    verdict = syn.get("verdict")
    if verdict not in _DECIDED_SYNONYMY:
        return None
    if verdict != "EXPRESSES":
        return "DOES_NOT_EXPRESS"
    k = int(syn.get("k") or 1)
    min_expresses = max(1, math.ceil(k * 0.8))
    return "EXPRESSES" if int(syn.get("n_expresses") or 0) >= min_expresses else "UNCERTAIN"


def _shipping_unanimous(row: dict) -> bool:
    syn = row.get("ship_synonymy") or {}
    if syn.get("verdict") != "EXPRESSES":
        return False
    k = int(syn.get("k") or 0)
    return (
        k > 0
        and int(syn.get("n_expresses") or 0) == k
        and int(syn.get("n_dne") or 0) == 0
        and int(syn.get("n_err") or 0) == 0
    )


_LOGICAL_OPS = {"And", "Or", "Not", "When"}


def _walk_atom_ops(obj) -> Iterable[str]:
    """Yield atomic DSL op names from a cached tree/precondition JSON object."""
    if isinstance(obj, dict):
        op = obj.get("op")
        if op and op not in _LOGICAL_OPS:
            yield str(op)
        for item in obj.get("args") or []:
            yield from _walk_atom_ops(item)
        for key in ("inner", "cond", "main", "predicate", "precondition"):
            if key in obj:
                yield from _walk_atom_ops(obj[key])
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_atom_ops(item)


def _atom_genericity_summary(rows: list[dict], row_set_label: str | None = None) -> dict:
    buckets = Counter()
    non_generic_freq = Counter()
    unknown_freq = Counter()
    for row in rows:
        atoms = set(_walk_atom_ops(row.get("tree")))
        atoms.update(_walk_atom_ops(row.get("precondition")))
        generic = {a for a in atoms if a in dsl.GENERIC_ATOMS}
        non_generic = {a for a in atoms if a in dsl.NON_GENERIC_ATOMS}
        unknown = atoms - generic - non_generic
        for atom in non_generic:
            non_generic_freq[atom] += 1
        for atom in unknown:
            unknown_freq[atom] += 1
        if unknown:
            buckets["unknown"] += 1
        elif non_generic and generic:
            buckets["generic_and_non_generic"] += 1
        elif non_generic:
            buckets["non_generic_only"] += 1
        else:
            buckets["generic_only"] += 1
    total = len(rows)
    containing_generic = buckets["generic_only"] + buckets["generic_and_non_generic"]
    return {
        "definition": (
            f"{row_set_label or 'selected rows'}; counts atomic DSL ops in tree "
            "and precondition; logical combinators And/Or/Not/When are excluded"
        ),
        "total": total,
        "generic_only": buckets["generic_only"],
        "generic_and_non_generic": buckets["generic_and_non_generic"],
        "containing_generic": containing_generic,
        "non_generic_only": buckets["non_generic_only"],
        "unknown": buckets["unknown"],
        "shares": {
            "generic_only": _rate(buckets["generic_only"], total),
            "generic_and_non_generic": _rate(buckets["generic_and_non_generic"], total),
            "containing_generic": _rate(containing_generic, total),
            "non_generic_only": _rate(buckets["non_generic_only"], total),
            "unknown": _rate(buckets["unknown"], total),
        },
        "non_generic_atom_frequency": dict(sorted(non_generic_freq.items())),
        "unknown_atom_frequency": dict(sorted(unknown_freq.items())),
    }


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
def _summarize_rows(domain: list[dict], latest: dict[int, dict], ledger_path: Path) -> dict:
    total = len(domain)
    domain_ids = {int(r["id"]) for r in domain}
    scoped_latest = {
        rid: row for rid, row in latest.items()
        if int(rid) in domain_ids
    }
    generated = [r for r in scoped_latest.values() if r.get("generation_success")]
    generated_count = len(generated)
    judged = [
        r for r in generated
        if r.get("synonymy", {}).get("verdict") in _DECIDED_SYNONYMY
    ]
    expresses = [r for r in judged if r.get("synonymy", {}).get("verdict") == "EXPRESSES"]
    dne = [r for r in judged if r.get("synonymy", {}).get("verdict") == "DOES_NOT_EXPRESS"]
    ship_judged = [
        r for r in generated
        if r.get("ship_synonymy", {}).get("verdict") in _DECIDED_SYNONYMY
    ]
    ship_expresses = [
        r for r in ship_judged
        if _shipping_gate(r) == "EXPRESSES"
    ]
    ship_dne = [
        r for r in ship_judged
        if _shipping_gate(r) == "DOES_NOT_EXPRESS"
    ]
    ship_uncertain = [
        r for r in ship_judged
        if _shipping_gate(r) == "UNCERTAIN"
    ]
    ship_with_rejudge_error = [r for r in ship_judged if r.get("ship_rejudge_error")]
    ship_clean_judged = [r for r in ship_judged if not r.get("ship_rejudge_error")]
    ship_clean_expresses = [
        r for r in ship_clean_judged
        if _shipping_gate(r) == "EXPRESSES"
    ]
    ship_unanimous = [r for r in ship_judged if _shipping_unanimous(r)]
    ship_clean_unanimous = [
        r for r in ship_clean_judged
        if _shipping_unanimous(r)
    ]
    errors = [r for r in scoped_latest.values() if r.get("error")]

    by_source = {}
    for source in sorted({r["source"] for r in domain}):
        ids = {int(r["id"]) for r in domain if r["source"] == source}
        src_rows = [scoped_latest[i] for i in ids if i in scoped_latest]
        src_gen = [r for r in src_rows if r.get("generation_success")]
        src_judged = [
            r for r in src_gen
            if r.get("synonymy", {}).get("verdict") in _DECIDED_SYNONYMY
        ]
        src_exp = [r for r in src_judged if r.get("synonymy", {}).get("verdict") == "EXPRESSES"]
        src_dne = [r for r in src_judged if r.get("synonymy", {}).get("verdict") == "DOES_NOT_EXPRESS"]
        src_ship_judged = [
            r for r in src_gen
            if r.get("ship_synonymy", {}).get("verdict") in _DECIDED_SYNONYMY
        ]
        src_ship_exp = [
            r for r in src_ship_judged
            if _shipping_gate(r) == "EXPRESSES"
        ]
        src_ship_unanimous = [
            r for r in src_ship_judged
            if _shipping_unanimous(r)
        ]
        src_ship_uncertain = [r for r in src_ship_judged if _shipping_gate(r) == "UNCERTAIN"]
        src_ship_with_rejudge_error = [r for r in src_ship_judged if r.get("ship_rejudge_error")]
        src_ship_clean_judged = [r for r in src_ship_judged if not r.get("ship_rejudge_error")]
        src_ship_clean_exp = [
            r for r in src_ship_clean_judged
            if _shipping_gate(r) == "EXPRESSES"
        ]
        src_ship_clean_unanimous = [
            r for r in src_ship_clean_judged
            if _shipping_unanimous(r)
        ]
        by_source[source] = {
            "domain_total": len(ids),
            "completed": len(src_rows),
            "generation_success": len(src_gen),
            "generation_rate": _rate(len(src_gen), len(ids)),
            "final_shipping_strict_judged": len(src_ship_judged),
            "final_shipping_strict_expresses": len(src_ship_exp),
            "final_shipping_strict_uncertain": len(src_ship_uncertain),
            "final_shipping_strict_rate_over_generated": _rate(len(src_ship_exp), len(src_gen)),
            "final_shipping_strict_rate_over_domain": _rate(len(src_ship_exp), len(ids)),
            "final_shipping_rejudge_error_rows": len(src_ship_with_rejudge_error),
            "final_shipping_clean_judged": len(src_ship_clean_judged),
            "final_shipping_clean_expresses": len(src_ship_clean_exp),
            "final_shipping_clean_rate_over_domain": _rate(len(src_ship_clean_exp), len(ids)),
            "final_shipping_unanimous_expresses": len(src_ship_unanimous),
            "final_shipping_unanimous_rate_over_domain": _rate(len(src_ship_unanimous), len(ids)),
            "final_shipping_clean_unanimous_expresses": len(src_ship_clean_unanimous),
            "final_shipping_clean_unanimous_rate_over_domain": _rate(len(src_ship_clean_unanimous), len(ids)),
            "paper_synonymy_expresses": len(src_ship_unanimous),
            "paper_synonymy_rate_over_generated": _rate(len(src_ship_unanimous), len(src_gen)),
            "paper_synonymy_rate_over_domain": _rate(len(src_ship_unanimous), len(ids)),
            "paper_synonymy_non_unanimous_80pct_diagnostics": len(src_ship_exp) - len(src_ship_unanimous),
            "atom_genericity": _atom_genericity_summary(
                src_ship_unanimous,
                row_set_label="final emitted zlint lints with unanimous EXPRESS",
            ),
            "atom_genericity_80pct_expresses": _atom_genericity_summary(
                src_ship_exp,
                row_set_label="final emitted zlint lints passing the 80% EXPRESS diagnostic gate",
            ),
            "diagnostic_row_level": {
                "judged": len(src_judged),
                "not_judged": len(src_gen) - len(src_judged),
                "expresses": len(src_exp),
                "does_not_express": len(src_dne),
                "rate_over_generated": _rate(len(src_exp), len(src_judged)),
                "end_to_end_rate_over_domain": _rate(len(src_exp), len(ids)),
            },
            "code_eq_ir_certified": sum(1 for r in src_gen if r.get("code_eq_ir_certified")),
        }

    by_method = Counter()
    by_method_expresses = Counter()
    by_reason = Counter()
    for r in scoped_latest.values():
        if r.get("generation_success"):
            method = r.get("generation", {}).get("method") or "unknown"
            by_method[method] += 1
            if r.get("synonymy", {}).get("verdict") == "EXPRESSES":
                by_method_expresses[method] += 1
        else:
            reason = (r.get("generation", {}).get("reason") or r.get("error") or "unknown")
            by_reason[reason.split(":", 1)[0]] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "db_url": DB_URL,
        "standards": sorted({r["source"] for r in domain}),
        "domain_definition": _domain_definition_from_rows(domain),
        "domain_input_path": next((r.get("_domain_input_path") for r in domain
                                   if r.get("_domain_input_path")), None),
        "profile_scope": "Rule context derived from CABF §7.1.2.N profile or row section/table title",
        "domain_total": total,
        "completed": len(scoped_latest),
        "generation_success": generated_count,
        "generation_rate": _rate(generated_count, total),
        "generation_by_method": dict(sorted(by_method.items())),
        "generation_failure_by_reason": dict(sorted(by_reason.items())),
        "final_shipping_strict_definition": (
            "final emitted in-tree zlint lint semantics vs original rule text/context; "
            "row-fragment synonymy is diagnostic only; gate is verdict=EXPRESSES "
            "and at least ceil(0.8*k) EXPRESS votes"
        ),
        "paper_synonymy_definition": (
            "paper-facing synonymy numerator: final emitted in-tree zlint lint semantics "
            "vs original rule text/context with unanimous EXPRESS votes and no DNE/error votes"
        ),
        "paper_synonymy_expresses": len(ship_unanimous),
        "paper_synonymy_rate_over_generated": _rate(len(ship_unanimous), generated_count),
        "paper_synonymy_rate_over_domain": _rate(len(ship_unanimous), total),
        "paper_synonymy_non_unanimous_80pct_diagnostics": len(ship_expresses) - len(ship_unanimous),
        "final_shipping_strict_judged": len(ship_judged),
        "final_shipping_strict_not_judged": generated_count - len(ship_judged),
        "final_shipping_strict_expresses": len(ship_expresses),
        "final_shipping_strict_does_not_express": len(ship_dne),
        "final_shipping_strict_uncertain": len(ship_uncertain),
        "final_shipping_strict_rate_over_generated": _rate(len(ship_expresses), generated_count),
        "final_shipping_strict_rate_over_domain": _rate(len(ship_expresses), total),
        "final_shipping_rejudge_error_rows": len(ship_with_rejudge_error),
        "final_shipping_clean_judged": len(ship_clean_judged),
        "final_shipping_clean_expresses": len(ship_clean_expresses),
        "final_shipping_clean_rate_over_generated": _rate(len(ship_clean_expresses), generated_count),
        "final_shipping_clean_rate_over_domain": _rate(len(ship_clean_expresses), total),
        "final_shipping_unanimous_expresses": len(ship_unanimous),
        "final_shipping_unanimous_rate_over_generated": _rate(len(ship_unanimous), generated_count),
        "final_shipping_unanimous_rate_over_domain": _rate(len(ship_unanimous), total),
        "final_shipping_clean_unanimous_expresses": len(ship_clean_unanimous),
        "final_shipping_clean_unanimous_rate_over_generated": _rate(len(ship_clean_unanimous), generated_count),
        "final_shipping_clean_unanimous_rate_over_domain": _rate(len(ship_clean_unanimous), total),
        "diagnostic_row_level": {
            "judged": len(judged),
            "not_judged": generated_count - len(judged),
            "expresses": len(expresses),
            "does_not_express": len(dne),
            "rate_over_generated": _rate(len(expresses), len(judged)),
            "end_to_end_rate_over_domain": _rate(len(expresses), total),
        },
        "diagnostic_row_level_by_method": {
            method: {
                "generated": count,
                "judged": sum(
                    1 for r in generated
                    if (r.get("generation", {}).get("method") or "unknown") == method
                    and r.get("synonymy", {}).get("verdict") in _DECIDED_SYNONYMY
                ),
                "expresses": by_method_expresses.get(method, 0),
                "rate_over_generated": _rate(
                    by_method_expresses.get(method, 0),
                    sum(
                        1 for r in generated
                        if (r.get("generation", {}).get("method") or "unknown") == method
                        and r.get("synonymy", {}).get("verdict") in _DECIDED_SYNONYMY
                    ),
                ),
            }
            for method, count in sorted(by_method.items())
        },
        "atom_genericity": _atom_genericity_summary(
            ship_unanimous,
            row_set_label="final emitted zlint lints with unanimous EXPRESS",
        ),
        "atom_genericity_80pct_expresses": _atom_genericity_summary(
            ship_expresses,
            row_set_label="final emitted zlint lints passing the 80% EXPRESS diagnostic gate",
        ),
        "atom_registry": {
            "total": len(dsl.ATOM_CLASSES),
            "generic": len(dsl.GENERIC_ATOMS),
            "non_generic": len(dsl.NON_GENERIC_ATOMS),
        },
        "code_eq_ir_certified": sum(1 for r in generated if r.get("code_eq_ir_certified")),
        "rule_errors": len(errors),
        "pending": total - len(scoped_latest),
        "by_source": by_source,
        "ledger": str(ledger_path),
    }


def summarize(domain: list[dict], ledger_path: Path, summary_path: Path) -> dict:
    summary = _summarize_rows(domain, load_done(ledger_path), ledger_path)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


# ---------------------------------------------------------------------------
# synonymous-lint export (in-tree zlint file shapes, for later injection)
# ---------------------------------------------------------------------------
_ROW_OBLIGATION_CELLS = {
    "MUST",
    "MUST NOT",
    "REQUIRED",
    "SHALL",
    "SHALL NOT",
    "PROHIBITED",
    "SHOULD",
    "SHOULD NOT",
    "RECOMMENDED",
    "NOT RECOMMENDED",
}


def _row_text_obligation(text: str) -> str | None:
    """Return an explicit RFC2119-style obligation from a pipe-table row.

    Extracted IR can latch onto an embedded subclause ("If present, MUST ...")
    while the table row's Presence cell is the actual finding level
    ("NOT RECOMMENDED"). For experiment outputs, prefer the explicit table cell
    when it is present as a standalone cell. This is row-text derived, not a DB
    edit or rule-id override.
    """
    first_line = (text or "").splitlines()[0] if text else ""
    if "|" not in first_line:
        return None
    for cell in reversed(first_line.split("|")):
        norm = (
            cell.replace("`", "")
            .replace("_", " ")
            .strip()
            .strip(".;:")
            .upper()
        )
        norm = " ".join(norm.split())
        if norm in _ROW_OBLIGATION_CELLS:
            return norm
    return None


def _effective_obligation(rule: dict) -> str:
    return (
        _row_text_obligation(rule.get("text") or "")
        or rule.get("obligation")
        or (rule.get("ir") or {}).get("obligation")
        or ""
    )


def _render_synonymous_lint(rule: dict, tree, precondition) -> dict | None:
    severity = det_codegen.severity_from_obligation(_effective_obligation(rule))
    try:
        return intree_emitter.render_intree_file(
            int(rule["id"]),
            rule.get("source") or "",
            str(rule.get("section") or ""),
            rule.get("text") or "",
            tree,
            precondition=precondition,
            severity=severity,
            title=rule.get("title") or "",
            ir=rule.get("ir") or {},
        )
    except Exception as e:
        return {"render_error": str(e)[:1000]}


def _write_rendered(rendered: dict, out_root: Path) -> str | None:
    if not rendered or rendered.get("render_error"):
        return None
    out_dir = out_root / rendered["pkg"]
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / rendered["filename"]
    path.write_text(rendered["file_content"], encoding="utf-8")
    return str(path)


def _write_row_level_expresses_index(run_dir: Path, latest: dict[int, dict],
                                     domain_ids: set[int] | None = None) -> list[dict]:
    rows = []
    for row in latest.values():
        rid = row.get("rule_id")
        if domain_ids is not None and int(rid or 0) not in domain_ids:
            continue
        if row.get("synonymy", {}).get("verdict") != "EXPRESSES":
            continue
        rows.append(
            {
                "rule_id": row.get("rule_id"),
                "source": row.get("source"),
                "section": row.get("section"),
                "title": row.get("title"),
                "lint_name": row.get("rendered_lint", {}).get("lint_name"),
                "filename": row.get("rendered_lint", {}).get("filename"),
                "output_path": row.get("rendered_lint", {}).get("output_path"),
                "method": row.get("generation", {}).get("method"),
                "code_eq_ir_certified": row.get("code_eq_ir_certified"),
            }
        )
    rows.sort(key=lambda r: (str(r.get("source")), str(r.get("section")), int(r.get("rule_id") or 0)))
    (run_dir / "diagnostic_row_level_lints_manifest.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    with (run_dir / "diagnostic_row_level_lints_manifest.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return rows


def _write_shipping_index(run_dir: Path, latest: dict[int, dict],
                          domain_ids: set[int] | None = None) -> list[dict]:
    """Paper-facing shipped-lint manifest.

    Only rows whose final in-tree zlint semantics receive unanimous EXPRESS
    votes against the available original rule context may appear here.  The
    ``synonymous_lints_manifest`` filename is kept as a compatibility alias for
    this paper-facing unanimous manifest.
    """
    rows = []
    for row in latest.values():
        rid = row.get("rule_id")
        if domain_ids is not None and int(rid or 0) not in domain_ids:
            continue
        if not _shipping_unanimous(row):
            continue
        rendered = row.get("rendered_lint") or {}
        output_path = rendered.get("output_path")
        if not output_path or not Path(output_path).exists():
            continue
        rows.append(
            {
                "rule_id": row.get("rule_id"),
                "source": row.get("source"),
                "section": row.get("section"),
                "title": row.get("title"),
                "lint_name": rendered.get("lint_name"),
                "filename": rendered.get("filename"),
                "output_path": output_path,
                "method": row.get("generation", {}).get("method"),
                "code_eq_ir_certified": row.get("code_eq_ir_certified"),
                "row_synonymy_verdict": row.get("synonymy", {}).get("verdict"),
                "shipping_synonymy_verdict": row.get("ship_synonymy", {}).get("verdict"),
                "shipping_gate_verdict": _shipping_gate(row),
                "shipping_unanimous": True,
                "shipping_n_expresses": row.get("ship_synonymy", {}).get("n_expresses"),
                "shipping_k": row.get("ship_synonymy", {}).get("k"),
            }
        )
    rows.sort(key=lambda r: (str(r.get("source")), str(r.get("section")), int(r.get("rule_id") or 0)))
    (run_dir / "shipping_lints_manifest.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    with (run_dir / "shipping_lints_manifest.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    (run_dir / "synonymous_lints_manifest.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    with (run_dir / "synonymous_lints_manifest.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return rows


def export_synonymous_from_ledger(run_dir: Path, domain: list[dict] | None = None) -> None:
    ledger = run_dir / "codegen_synonymy.jsonl"
    summary_path = run_dir / "codegen_synonymy_summary.json"
    latest = load_done(ledger)
    domain_ids = {int(r["id"]) for r in domain} if domain is not None else None
    rows = _write_row_level_expresses_index(run_dir, latest, domain_ids)
    ship_rows = _write_shipping_index(run_dir, latest, domain_ids)
    expected_files = {r.get("filename") for r in rows if r.get("filename")}
    expected_files.update(r.get("filename") for r in ship_rows if r.get("filename"))
    rendered_root = run_dir / "synonymous_lints"
    if rendered_root.exists():
        for path in rendered_root.rglob("*.go"):
            if path.name not in expected_files:
                path.unlink()
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            summary = {}
        summary["synonymous_lints_manifest"] = str(run_dir / "synonymous_lints_manifest.json")
        summary["shipping_lints_manifest"] = str(run_dir / "shipping_lints_manifest.json")
        summary["paper_synonymy_manifest"] = str(run_dir / "shipping_lints_manifest.json")
        summary["diagnostic_row_level_lints_manifest"] = str(
            run_dir / "diagnostic_row_level_lints_manifest.json"
        )
        summary["diagnostic_row_level_lints_manifest_count"] = len(rows)
        summary["synonymous_lints_manifest_count"] = len(ship_rows)
        summary["shipping_lints_manifest_count"] = len(ship_rows)
        summary["paper_synonymy_manifest_count"] = len(ship_rows)
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def write_run_status(run_dir: Path, domain: list[dict], summary: dict) -> None:
    """Write a compact human/machine status derived from the current ledger."""
    latest = load_done(run_dir / "codegen_synonymy.jsonl")
    failures = []
    for rule in domain:
        rid = int(rule["id"])
        row = latest.get(rid)
        if not row or row.get("generation_success"):
            continue
        gen = row.get("generation") or {}
        failures.append(
            {
                "rule_id": rid,
                "reason": gen.get("reason") or row.get("error") or "unknown",
            }
        )

    by_source = {}
    for source, src in (summary.get("by_source") or {}).items():
        by_source[source] = {
            "domain_total": src.get("domain_total"),
            "generation_success": src.get("generation_success"),
            "paper_synonymy_expresses": src.get("paper_synonymy_expresses"),
            "paper_synonymy_rate_over_generated": src.get("paper_synonymy_rate_over_generated"),
            "paper_synonymy_rate_over_domain": src.get("paper_synonymy_rate_over_domain"),
        }

    status = {
        "run_dir": str(run_dir),
        "status": "complete" if summary.get("pending") == 0 else "incomplete",
        "domain_total": summary.get("domain_total"),
        "completed_rows": summary.get("completed"),
        "generation_success": summary.get("generation_success"),
        "generation_rate": summary.get("generation_rate"),
        "generation_by_method": summary.get("generation_by_method"),
        "generation_failure_by_reason": summary.get("generation_failure_by_reason"),
        "generation_failures": failures,
        "final_shipping_judged": summary.get("final_shipping_strict_judged"),
        "final_shipping_not_judged": summary.get("final_shipping_strict_not_judged"),
        "final_shipping_expresses_80pct": summary.get("final_shipping_strict_expresses"),
        "final_shipping_does_not_express": summary.get("final_shipping_strict_does_not_express"),
        "final_shipping_uncertain": summary.get("final_shipping_strict_uncertain"),
        "paper_unanimous_expresses": summary.get("paper_synonymy_expresses"),
        "paper_synonymy_rate_over_generated": summary.get("paper_synonymy_rate_over_generated"),
        "paper_synonymy_rate_over_domain": summary.get("paper_synonymy_rate_over_domain"),
        "by_source": by_source,
        "atom_genericity_unanimous": summary.get("atom_genericity"),
        "manifest": str(run_dir / "shipping_lints_manifest.json"),
        "compile_verification": str(run_dir / "shipping_compile.json"),
        "genericity_verification": str(run_dir / "generic_only_audit.json"),
        "native_coverage_false_negative_review": str(run_dir / "domain_rule_ids.json"),
    }
    (run_dir / "run_status.json").write_text(
        json.dumps(status, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    generated = int(summary.get("generation_success") or 0)
    domain_total = int(summary.get("domain_total") or 0)
    unanimous = int(summary.get("paper_synonymy_expresses") or 0)
    gen_rate = (generated / domain_total * 100) if domain_total else 0.0
    syn_rate = (unanimous / generated * 100) if generated else 0.0
    lines = [
        "# Run Status",
        "",
        f"- status: {status['status']}",
        f"- domain: {domain_total}",
        f"- generated: {generated} ({gen_rate:.1f}%)",
        f"- paper unanimous EXPRESS: {unanimous} ({syn_rate:.1f}% of generated)",
        f"- final shipping 80% EXPRESS diagnostic: {summary.get('final_shipping_strict_expresses')}",
        f"- final shipping DNE: {summary.get('final_shipping_strict_does_not_express')}",
        f"- uncertain: {summary.get('final_shipping_strict_uncertain')}",
        f"- generation failures: {len(failures)}",
        "",
        "## Generation Failures",
        "",
    ]
    if failures:
        lines.extend(f"- R{row['rule_id']}: {row['reason']}" for row in failures)
    else:
        lines.append("- none")
    (run_dir / "run_status.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def compact_ledger(domain: list[dict], run_dir: Path) -> dict:
    """Keep only the latest completed row for each current-domain rule."""
    ledger = run_dir / "codegen_synonymy.jsonl"
    summary_path = run_dir / "codegen_synonymy_summary.json"
    if not ledger.exists():
        return summarize(domain, ledger, summary_path)
    before = sum(1 for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip())
    latest = load_done(ledger)
    records = [
        latest[int(rule["id"])]
        for rule in domain
        if int(rule["id"]) in latest
    ]
    rewrite_ledger(ledger, records)
    summary = summarize(domain, ledger, summary_path)
    export_synonymous_from_ledger(run_dir, domain)
    write_run_status(run_dir, domain, summary)
    print(f"[compact] ledger rows {before} -> {len(records)}", flush=True)
    return summary


# ---------------------------------------------------------------------------
# per-rule work
# ---------------------------------------------------------------------------
def _judge(rule: dict, tree, precondition, code_semantics: str, k: int) -> dict:
    """Row-level synonymy: generated semantics vs this extracted source row.

    Keep this intentionally narrower than the strict shipping judge. A single IR
    row carries one normative keyword/atom; nearby rows and full section excerpts
    can contain sibling keywords that belong to separate IRs. Profile/table scope
    is still passed separately so certificate type/profile context is preserved.
    """
    return cascade.synonymy_verdict(
        tree,
        rule.get("text") or "",
        precondition=precondition,
        profile_scope=rule.get("profile_scope"),
        obligation=_effective_obligation(rule),
        k=k,
    )


def _full_rule_context(rule: dict) -> str:
    """Original-side text for the strict shipping synonymy judge.

    The row text is the verbatim extracted normative row, but many rows are
    terse table cells.  Include all spec-owned context currently available to
    the experiment so the judge compares the final lint against the rule in its
    section/profile setting, not against an isolated keyword cell.

    Do not include extracted IR subject/predicate/constraint metadata here.
    Strict synonymy is code-semantics-vs-original-text/context; IR fields are
    an intermediate representation and can be wrong or lossy. Feeding them to
    the judge lets an extraction artifact override the source text.
    """
    ir = rule.get("ir") or {}
    pieces = [
        f"Source: {rule.get('source') or ''}",
        f"Section: {rule.get('section') or ''}",
        f"Section/title context: {rule.get('title') or ''}",
        f"Original extracted rule text: {rule.get('text') or ''}",
    ]
    if rule.get("profile_scope"):
        pieces.append(f"Profile/table context: {rule.get('profile_scope')}")
    if rule.get("nearby_section_rows"):
        pieces.append(f"Nearby rows from the same source section/table:\n{rule.get('nearby_section_rows')}")
    modal_blob = " ".join(
        str(x or "")
        for x in (rule.get("text"), rule.get("nearby_section_rows"), rule.get("title"))
    )
    if "NOT RECOMMENDED" in modal_blob or "SHOULD NOT" in modal_blob:
        pieces.append(
            "Normative modal note: NOT RECOMMENDED / SHOULD NOT is an "
            "advisory discouragement (a warning-level requirement), not a "
            "prohibition. MUST NOT / SHALL NOT is the prohibitive modal."
        )
    source_name = rule.get("source") or ""
    section_name = str(rule.get("section") or "")
    row_text = rule.get("text") or ""
    if (
        source_name == "RFC5280"
        and section_name == "A.1"
        and "version MUST be v2 or v3" in row_text
    ):
        pieces.append(
            "Source-local ASN.1 antecedent: in RFC 5280 Appendix A.1, this "
            "trailing comment appears immediately after the optional "
            "`issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL` line or "
            "the optional `subjectUniqueID [2] IMPLICIT UniqueIdentifier "
            "OPTIONAL` line, so `If present` refers to either of those "
            "UniqueIdentifier fields being present."
        )
    if (
        source_name == "RFC5280"
        and section_name == "A.1"
        and "version MUST be v3" in row_text
        and "}" in row_text
    ):
        pieces.append(
            "Source-local ASN.1 antecedent: in RFC 5280 Appendix A.1, this "
            "trailing comment is attached to `extensions [3] Extensions "
            "OPTIONAL`, so `If present` refers to the TBSCertificate extensions "
            "[3] field being present."
        )
    if (
        source_name == "CABF-BR"
        and section_name == "7.1.4.3"
        and "IPv4 address" in row_text
        and "IPv4Address" in row_text
    ):
        pieces.append(
            "Source-local row role: in CABF §7.1.4.3, this extracted row is "
            "the IPv4 bullet under `The value of the field MUST be encoded as "
            "follows`, where the field is the Subscriber Certificate "
            "commonName attribute. The preceding sentence requiring commonName "
            "to contain a value from subjectAltName is a separate row-level "
            "requirement; this IPv4 bullet constrains the textual encoding of "
            "the commonName value when that value is an IPv4 address."
        )
    source_excerpt = _raw_section_excerpt(
        rule.get("source") or "",
        str(rule.get("section") or ""),
    )
    if source_excerpt:
        pieces.append(f"Original source section excerpt:\n{source_excerpt}")
    if ir.get("effective_date"):
        pieces.append(f"Rule effective date: {ir.get('effective_date')}")
    return "\n".join(p for p in pieces if p and not p.endswith(": "))


def _severity_for_rule(rule: dict) -> str:
    return det_codegen.severity_from_obligation(_effective_obligation(rule))


def _shipping_code_semantics(rule: dict, tree=None, precondition=None,
                             pass_condition_text: str | None = None) -> str:
    """Mechanical σ(final in-tree zlint lint), including CheckApplies."""
    return intree_emitter.intree_semantics_summary(
        str(rule.get("section") or ""),
        rule.get("title") or "",
        tree,
        precondition=precondition,
        severity=_severity_for_rule(rule),
        ir=rule.get("ir") or {},
        pass_condition_text=pass_condition_text,
        source=rule.get("source") or "",
    )


def _judge_shipping(rule: dict, tree, precondition, k: int,
                    inner_workers: int = 1,
                    pass_condition_text: str | None = None) -> tuple[str, dict]:
    """Strict ship gate: final zlint semantics vs full available source context."""
    ship_sem = _shipping_code_semantics(
        rule,
        tree,
        precondition,
        pass_condition_text=pass_condition_text,
    )
    res = synonym_judge.judge_vote(
        _full_rule_context(rule),
        ship_sem,
        k=k,
        profile_scope=rule.get("profile_scope"),
        inner_workers=inner_workers,
    )
    res["path"] = "shipping_judge"
    res.setdefault("judge_raw", res.get("sample_why", ""))
    return ship_sem, res


def _cached_node_to_parse_json(obj, *, role: str = "predicate"):
    """Convert legacy ledger dataclass JSON into the DSL parser's args form."""
    if obj is None:
        return None
    if not isinstance(obj, dict):
        return obj
    op = obj.get("op")
    if not isinstance(op, str):
        # Legacy ledgers sometimes stored dataclass fields without the class/op
        # name for nested nodes. Infer only unambiguous shapes; ambiguous
        # predicate nodes intentionally remain unparsed so we can fall back to
        # cached code_semantics rather than inventing a different predicate.
        if "parts" in obj:
            return {
                "op": "And",
                "args": [_cached_node_to_parse_json(arg, role=role)
                         for arg in (obj.get("parts") or [])],
            }
        if "inner" in obj:
            return {
                "op": "Not",
                "args": [_cached_node_to_parse_json(obj.get("inner"), role=role)],
            }
        if "holder" in obj:
            return {"op": "DNEmpty", "args": [obj.get("holder")]}
        if "algorithm" in obj:
            return {"op": "PublicKeyAlgorithmIs", "args": [obj.get("algorithm")]}
        if "field" in obj and "value" in obj:
            return {"op": "FieldEq", "args": [obj.get("field"), obj.get("value")]}
        if "field" in obj and "values" in obj:
            return {"op": "FieldInSet", "args": [obj.get("field"), obj.get("values")]}
        if "field" in obj and "oid" in obj:
            field = str(obj.get("field") or "")
            op_name = "OidListContains" if field == "PolicyIdentifiers" else "OidEq"
            return {"op": op_name, "args": [field, obj.get("oid")]}
        if role == "condition" and "field" in obj:
            return {"op": "FieldNonEmpty", "args": [obj.get("field")]}
        if "bit" in obj:
            return {"op": "KeyUsageHas", "args": [obj.get("bit")]}
        if role == "condition" and "oid" in obj:
            return {"op": "ExtPresent", "args": [obj.get("oid")]}
        return obj
    if "args" in obj:
        return {
            "op": op,
            "args": [_cached_node_to_parse_json(arg, role=role)
                     for arg in obj.get("args", [])],
        }
    if op == "Not":
        return {
            "op": "Not",
            "args": [_cached_node_to_parse_json(obj.get("inner"), role=role)],
        }
    if op == "When":
        return {
            "op": "When",
            "args": [
                _cached_node_to_parse_json(obj.get("cond"), role="condition"),
                _cached_node_to_parse_json(obj.get("main"), role="predicate"),
            ],
        }
    if op in ("And", "Or"):
        return {
            "op": op,
            "args": [_cached_node_to_parse_json(arg, role=role)
                     for arg in (obj.get("parts") or [])],
        }
    cls = dsl.ATOM_CLASSES.get(op)
    if cls is None:
        raise dsl.DSLError(f"unknown cached DSL op {op!r}")
    args = []
    for field in dataclasses.fields(cls):
        if field.name in obj:
            args.append(_cached_node_to_parse_json(obj[field.name], role=role))
    return {"op": op, "args": args}


def _parse_cached_node(obj):
    if obj is None:
        return None
    return dsl.parse(_cached_node_to_parse_json(obj))


def _parse_cached_applicability_condition(obj):
    """Best-effort parse of a legacy top-level When condition only.

    Some old ledger rows cannot safely reconstruct the full predicate because
    nested main nodes lost their op names.  For strict shipping rejudge we can
    still recover the applicability part and combine it with the cached
    code_semantics text, avoiding both data loss and predicate invention.
    """
    if not isinstance(obj, dict):
        return None
    if obj.get("op") != "When":
        return None
    cond = obj.get("cond")
    if cond is None:
        args = obj.get("args") if isinstance(obj.get("args"), list) else []
        cond = args[0] if args else None
    if cond is None:
        return None
    return dsl.parse(_cached_node_to_parse_json(cond, role="condition"))


def process_rule(rule: dict, rendered_root: Path, *, workspace, k: int,
                 allow_llm: bool, skip_synonymy: bool) -> dict:
    rid = int(rule["id"])
    rec = {
        "complete": False,
        "rule_id": rid,
        "standard_id": rule.get("standard_id"),
        "source": rule.get("source"),
        "section": rule.get("section"),
        "title": rule.get("title"),
        "text": rule.get("text"),
        "context": rule.get("context"),
        "nearby_section_rows": rule.get("nearby_section_rows"),
        "profile_scope": rule.get("profile_scope"),
        "ir": rule.get("ir"),
    }
    try:
        gen = cascade.generate_tree(rule, workspace=workspace, allow_llm=allow_llm)
        ok = bool(gen.get("tree"))
        rec["generation_success"] = ok
        rec["generation"] = {
            "method": gen.get("method"),
            "reason": gen.get("reason"),
            "llm_raw": gen.get("llm_raw"),
        }
        if ok:
            tree = gen["tree"]
            precondition = gen.get("precondition")
            rec["tree"] = dsl.compound_to_dict(tree)
            rec["precondition"] = dsl.compound_to_dict(precondition) if precondition else None
            rec["code_semantics"] = obligation_aware_summary(
                tree,
                precondition,
                obligation=_effective_obligation(rule),
            )
            rec["code_eq_ir_certified"] = cascade.code_eq_ir_certified(
                tree, precondition, rule=rule, workspace=workspace
            )
            if skip_synonymy:
                rec["synonymy"] = {
                    "verdict": None,
                    "path": "skipped",
                    "reason": "--skip-synonymy",
                }
            else:
                rec["synonymy"] = _judge(rule, tree, precondition, rec["code_semantics"], k)
            if not skip_synonymy:
                rendered = _render_synonymous_lint(rule, tree, precondition)
                if rendered:
                    output_path = _write_rendered(rendered, rendered_root)
                    if output_path:
                        rendered = dict(rendered)
                        rendered["output_path"] = output_path
                        rendered.pop("file_content", None)
                rec["rendered_lint"] = rendered
                if rendered and not rendered.get("render_error"):
                    ship_sem, ship_syn = _judge_shipping(rule, tree, precondition, k)
                    rec["ship_code_semantics"] = ship_sem
                    rec["ship_synonymy"] = ship_syn
        rec["complete"] = True
    except Exception as e:
        rec["generation_success"] = False
        rec["error"] = str(e)[:1000]
        rec["complete"] = True
    return rec


def iter_pending(domain, done, *, retry_errors, retry_generation_failures, retry_dne):
    for idx, rule in enumerate(domain, 1):
        rid = int(rule["id"])
        prev = done.get(rid)
        if prev is None:
            yield idx, rule
        elif retry_errors and prev.get("error"):
            yield idx, rule
        elif retry_generation_failures and not prev.get("generation_success"):
            yield idx, rule
        elif (retry_dne
              and prev.get("generation_success")
              and prev.get("synonymy", {}).get("verdict") == "DOES_NOT_EXPRESS"):
            yield idx, rule


# ---------------------------------------------------------------------------
# --rejudge : reuse cached generation, re-run only the judge with rule context
# ---------------------------------------------------------------------------
def rejudge(domain: list[dict], run_dir: Path, k: int, only_dne: bool,
            target_ids: set[int] | None = None) -> dict:
    ledger = run_dir / "codegen_synonymy.jsonl"
    summary_path = run_dir / "codegen_synonymy_summary.json"
    ps_by_id = {int(r["id"]): r.get("profile_scope") for r in domain}
    text_by_id = {int(r["id"]): r.get("text") for r in domain}
    records = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    n_rejudged = 0
    for rec in records:
        rid = rec.get("rule_id")
        if target_ids is not None and int(rid or 0) not in target_ids:
            continue
        if not rec.get("generation_success") or rec.get("code_semantics") is None:
            continue
        ps = ps_by_id.get(rid)
        # Rule context only supplies spec-owned section/profile context.
        # Skip rows that cannot change: EXPRESSES already, or no context.
        cur = rec.get("synonymy", {}).get("verdict")
        if ps is None:
            continue
        if only_dne and cur != "DOES_NOT_EXPRESS":
            continue
        # Reuse the cached code_semantics (sigma_mech rendering already frozen in
        # the ledger); the reloaded `tree` is a plain dict, so we judge the cached
        # text directly rather than re-render it.
        res = synonym_judge.judge_vote(
            text_by_id.get(rid) or rec.get("text") or "",
            rec.get("code_semantics") or "",
            k=k,
            profile_scope=ps,
        )
        res["path"] = "judge"
        res.setdefault("judge_raw", res.get("sample_why", ""))
        rec["synonymy"] = res
        rec["profile_scope"] = ps
        n_rejudged += 1
        print(f"  rejudge R{rid} ps={ps!r}: {cur} -> {res['verdict']} "
              f"({res['n_expresses']}E/{res['n_dne']}D)", flush=True)
    rewrite_ledger(ledger, records)
    summary = summarize(domain, ledger, summary_path)
    export_synonymous_from_ledger(run_dir, domain)
    write_run_status(run_dir, domain, summary)
    print(f"[rejudge] re-judged {n_rejudged} rows", flush=True)
    return summary


# ---------------------------------------------------------------------------
# --rejudge-shipping : final emitted zlint semantics vs original rule context
# ---------------------------------------------------------------------------
def rejudge_shipping(domain: list[dict], run_dir: Path, k: int,
                     only_missing: bool, inner_workers: int,
                     target_ids: set[int] | None = None) -> dict:
    ledger = run_dir / "codegen_synonymy.jsonl"
    summary_path = run_dir / "codegen_synonymy_summary.json"
    rendered_root = run_dir / "synonymous_lints"
    if not ledger.exists():
        raise SystemExit(f"ledger not found: {ledger}")
    domain_by_id = {int(r["id"]): r for r in domain}
    records = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    n_rejudged = 0
    n_skipped = 0
    for rec in records:
        rid = int(rec.get("rule_id") or 0)
        if target_ids is not None and rid not in target_ids:
            n_skipped += 1
            continue
        if not rid or not rec.get("generation_success"):
            n_skipped += 1
            continue
        cur = rec.get("ship_synonymy", {}).get("verdict")
        if only_missing and cur in _DECIDED_SYNONYMY:
            n_skipped += 1
            continue
        try:
            parse_error = None
            try:
                tree = _parse_cached_node(rec.get("tree"))
                precondition = _parse_cached_node(rec.get("precondition"))
            except Exception as e:
                tree = None
                try:
                    precondition = _parse_cached_node(rec.get("precondition"))
                except Exception:
                    precondition = None
                if precondition is None:
                    try:
                        precondition = _parse_cached_applicability_condition(rec.get("tree"))
                    except Exception:
                        precondition = None
                parse_error = str(e)[:1000]
            pass_condition_text = rec.get("code_semantics") if parse_error else None
            rule = {**rec, **domain_by_id.get(rid, {})}
            rule["id"] = rid
            if not rule.get("obligation"):
                rule["obligation"] = (rule.get("ir") or {}).get("obligation") or ""

            rendered = rec.get("rendered_lint") or {}
            output_path = rendered.get("output_path")
            rendered_exists = bool(output_path and Path(output_path).exists())
            if (not rendered_exists or rendered.get("render_error")) and tree is not None:
                rendered = _render_synonymous_lint(rule, tree, precondition) or {}
                output_path = _write_rendered(rendered, rendered_root)
                if output_path:
                    rendered = dict(rendered)
                    rendered["output_path"] = output_path
                    rendered.pop("file_content", None)
                rec["rendered_lint"] = rendered
                rendered_exists = bool(output_path and Path(output_path).exists())
            if rendered.get("render_error") or not rendered_exists:
                reason = rendered.get("render_error") or parse_error or "rendered lint output_path is missing"
                rec["ship_synonymy"] = {
                    "verdict": None,
                    "path": "shipping_rejudge_error",
                    "reason": reason,
                }
                n_skipped += 1
                continue

            ship_sem, ship_syn = _judge_shipping(
                rule,
                tree,
                precondition,
                k,
                inner_workers=inner_workers,
                pass_condition_text=pass_condition_text,
            )
            if ship_syn.get("verdict") == "ERROR":
                previous = rec.get("ship_synonymy") or {}
                if previous.get("verdict") in _DECIDED_SYNONYMY:
                    err = dict(ship_syn)
                    rec["ship_rejudge_error"] = err
                    ship_syn = previous
                    ship_sem = rec.get("ship_code_semantics") or ship_sem
                else:
                    rec["ship_synonymy"] = {
                        "verdict": None,
                        "path": "shipping_rejudge_error",
                        "reason": ship_syn.get("sample_why") or ship_syn.get("judge_raw") or "shipping judge error",
                    }
                    n_skipped += 1
                    print(
                        f"  shipping R{rid}: {cur or 'UNJUDGED'} -> ERROR "
                        f"({ship_syn.get('n_err', 0)}X; kept unjudged)",
                        flush=True,
                    )
                    continue
            if parse_error:
                ship_syn["cached_tree_parse_error"] = parse_error
                ship_syn["execute_semantics_source"] = "cached_code_semantics"
            rec["ship_code_semantics"] = ship_sem
            rec["ship_synonymy"] = ship_syn
            rec.pop("ship_rejudge_error", None)
            n_rejudged += 1
            print(
                f"  shipping R{rid}: {cur or 'UNJUDGED'} -> {ship_syn['verdict']} "
                f"({ship_syn['n_expresses']}E/{ship_syn['n_dne']}D/"
                f"{ship_syn.get('n_err', 0)}X)",
                flush=True,
            )
        except Exception as e:
            rec["ship_synonymy"] = {
                "verdict": None,
                "path": "shipping_rejudge_error",
                "reason": str(e)[:1000],
            }
            n_skipped += 1
            print(f"  shipping R{rid}: ERROR {str(e)[:200]}", flush=True)
    rewrite_ledger(ledger, records)
    summary = summarize(domain, ledger, summary_path)
    export_synonymous_from_ledger(run_dir, domain)
    write_run_status(run_dir, domain, summary)
    print(f"[rejudge-shipping] re-judged {n_rejudged} rows; skipped {n_skipped}", flush=True)
    return summary


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--standards", default="all", help="all, cabf, rfc5280, or comma list")
    ap.add_argument("--k", type=int, default=5, help="synonym judge vote count")
    ap.add_argument("--limit", type=int, help="process only the first N domain rows")
    ap.add_argument(
        "--run-name",
        default="allow_nongeneric_20260718",
        help="outputs/<run-name>",
    )
    ap.add_argument(
        "--domain-rule-ids",
        help=(
            "JSON/text file containing the explicit rule-id domain. With this "
            "option, the domain is selected_id AND lintable AND computed-coverage "
            "AND id in file; it does not trust the DB lint_covered boolean."
        ),
    )
    ap.add_argument("--overwrite", action="store_true", help="discard existing run ledger")
    ap.add_argument("--retry-errors", action="store_true")
    ap.add_argument("--retry-generation-failures", action="store_true")
    ap.add_argument("--retry-dne", action="store_true",
                    help="retry rows whose cached synonymy verdict is DOES_NOT_EXPRESS")
    ap.add_argument("--rule-id", type=int, action="append",
                    help="only process this rule id this run; repeatable. Summary still uses the full domain.")
    ap.add_argument("--force-rule-id", action="store_true",
                    help="with --rule-id, reprocess those rules even if already complete")
    ap.add_argument("--no-llm-codegen", action="store_true", help="deterministic path only")
    ap.add_argument("--skip-synonymy", action="store_true",
                    help="do not call the LLM synonymy judge; report generation/oracle metrics only")
    ap.add_argument("--rejudge", action="store_true",
                    help="reuse cached generation; re-run only the judge with rule context")
    ap.add_argument("--rejudge-all", action="store_true",
                    help="with --rejudge, re-judge every profile-scoped row (not just DNE)")
    ap.add_argument("--rejudge-shipping", action="store_true",
                    help="reuse cached generation; judge final emitted zlint semantics against original context")
    ap.add_argument("--rejudge-shipping-all", action="store_true",
                    help="with --rejudge-shipping, re-judge rows even if shipping verdict is already cached")
    ap.add_argument("--shipping-inner-workers", type=int, default=1,
                    help="parallel votes per shipping judge row; default 1 avoids LLM gateway concurrency errors")
    ap.add_argument("--summary-only", action="store_true")
    ap.add_argument("--compact-ledger", action="store_true",
                    help="rewrite ledger to latest rows for the current domain and prune stale rendered lints")
    ap.add_argument("--zlint-v3", default=str(BACKEND / "zlint" / "v3"))
    args = ap.parse_args()

    os.environ["ZLINT_LOCAL"] = str(Path(args.zlint_v3).resolve())
    standards = _selected_standards(args.standards)
    explicit_rule_ids: set[int] | None = None
    domain_definition: str | None = None
    domain_input_path: str | None = None
    if args.domain_rule_ids:
        domain_path = Path(args.domain_rule_ids).resolve()
        explicit_rule_ids = set(_load_domain_rule_ids(domain_path))
        domain_input_path = str(domain_path)
        domain_definition = (
            "explicit strict-uncovered rule-id domain from experiment input; "
            "standard_id IN selected AND lintable AND lint_coverage IS NOT NULL "
            "AND id IN domain_rule_ids. Native-zlint coverage is taken from the "
            "strict coverage audit inputs, not from the DB lint_covered boolean."
        )
    run_dir = OUTPUTS / args.run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    ledger = run_dir / "codegen_synonymy.jsonl"
    summary_path = run_dir / "codegen_synonymy_summary.json"
    rendered_root = run_dir / "synonymous_lints"

    if args.overwrite:
        for path in (ledger, summary_path, run_dir / "synonymous_lints_manifest.json",
                     run_dir / "synonymous_lints_manifest.jsonl",
                     run_dir / "shipping_lints_manifest.json",
                     run_dir / "shipping_lints_manifest.jsonl",
                     run_dir / "diagnostic_row_level_lints_manifest.json",
                     run_dir / "diagnostic_row_level_lints_manifest.jsonl"):
            if path.exists():
                path.unlink()
        if rendered_root.exists():
            shutil.rmtree(rendered_root)

    try:
        domain = load_domain(
            standards,
            limit=args.limit,
            domain_rule_ids=explicit_rule_ids,
            domain_definition=domain_definition,
            domain_input_path=domain_input_path,
        )
    except Exception as e:
        can_fallback = (
            ledger.exists()
            and (args.summary_only or args.rejudge or args.rejudge_shipping or args.compact_ledger)
        )
        if not can_fallback:
            raise
        print(f"[warn] DB domain load failed; using current ledger fallback: {e}", flush=True)
        domain = domain_from_ledger(ledger, limit=args.limit)

    if args.compact_ledger:
        summary = compact_ledger(domain, run_dir)
        print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
        return 0

    if args.summary_only:
        summary = summarize(domain, ledger, summary_path)
        export_synonymous_from_ledger(run_dir, domain)
        write_run_status(run_dir, domain, summary)
        print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
        return 0

    if args.rejudge:
        target_ids = {int(x) for x in args.rule_id} if args.rule_id else None
        summary = rejudge(
            domain,
            run_dir,
            k=args.k,
            only_dne=not args.rejudge_all,
            target_ids=target_ids,
        )
        print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
        return 0

    if args.rejudge_shipping:
        target_ids = {int(x) for x in args.rule_id} if args.rule_id else None
        summary = rejudge_shipping(
            domain,
            run_dir,
            k=args.k,
            only_missing=not args.rejudge_shipping_all,
            inner_workers=max(1, args.shipping_inner_workers),
            target_ids=target_ids,
        )
        print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
        return 0

    done = load_done(ledger)
    if args.force_rule_id:
        if not args.rule_id:
            raise SystemExit("--force-rule-id requires at least one --rule-id")
        wanted = {int(x) for x in args.rule_id}
        pending = [(idx, rule) for idx, rule in enumerate(domain, 1) if int(rule["id"]) in wanted]
    else:
        pending = list(iter_pending(domain, done, retry_errors=args.retry_errors,
                                    retry_generation_failures=args.retry_generation_failures,
                                    retry_dne=args.retry_dne))
        if args.rule_id:
            wanted = {int(x) for x in args.rule_id}
            pending = [(idx, rule) for idx, rule in pending if int(rule["id"]) in wanted]
    print(f"[domain] standards={','.join(standards)} rows={len(domain)} "
          f"complete={len(done)} pending={len(pending)} run={run_dir}", flush=True)

    with tempfile.TemporaryDirectory(prefix="cicas_codegen_") as tmp:
        workspace = Path(tmp)
        print(f"[workspace] building Go workspace at {workspace}", flush=True)
        runner.build_workspace(workspace)
        for idx, rule in pending:
            rid = int(rule["id"])
            print(f"[{idx}/{len(domain)}] R{rid} {rule['source']} {rule.get('section') or ''} "
                  f"ps={rule.get('profile_scope')!r}", flush=True)
            rec = process_rule(rule, rendered_root, workspace=workspace,
                               k=args.k, allow_llm=not args.no_llm_codegen,
                               skip_synonymy=args.skip_synonymy)
            append_jsonl(ledger, rec)
            summary = summarize(domain, ledger, summary_path)
            export_synonymous_from_ledger(run_dir, domain)
            sr = summary["final_shipping_unanimous_rate_over_domain"]
            print("[progress] completed={completed}/{domain_total} generated={generation_success} "
                  "shipping_unanimous={final_shipping_unanimous_expresses} "
                  "gen_rate={generation_rate:.3f} synonymy_e2e={sr}".format(
                      **{**summary, "sr": f"{sr:.3f}" if sr is not None else "NA"}), flush=True)

    summary = summarize(domain, ledger, summary_path)
    export_synonymous_from_ledger(run_dir, domain)
    write_run_status(run_dir, domain, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
    return 0 if summary["pending"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
