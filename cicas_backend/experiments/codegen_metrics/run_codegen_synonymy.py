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
  --summary-only  recompute summary + manifests from the existing ledger
  --compact-ledger prune stale/duplicate ledger rows after targeted retries
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import psycopg2

BACKEND = Path(__file__).resolve().parents[2]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.certificate.codegen import cascade, runner  # noqa: E402
from app.services.certificate.codegen import det_codegen, intree_emitter, synonym_judge  # noqa: E402
from app.services.certificate.codegen.tree_to_natural import obligation_aware_summary  # noqa: E402

HERE = Path(__file__).resolve().parent
OUTPUTS = HERE / "outputs"
DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")

STANDARDS = {
    "rfc5280": {"id": 1, "source": "RFC5280"},
    "cabf": {"id": 19, "source": "CABF-BR"},
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

    if profile:
        prefix = f"{source} §{section} " if section else f"{source} "
        return _with_reserved_policy_oid(f"{prefix}{profile}")
    if title:
        prefix = f"{source} §{section} " if section else f"{source} "
        return _with_reserved_policy_oid(f"{prefix}{title}")
    return None


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------
def _json_default(obj):
    if dataclasses.is_dataclass(obj):
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


def load_domain(standards: list[str], limit: int | None = None) -> list[dict]:
    selected = [STANDARDS[s]["id"] for s in standards]
    source_by_id = {v["id"]: v["source"] for v in STANDARDS.values()}
    sec2title = _load_section_titles()
    with psycopg2.connect(DB_URL, connect_timeout=3) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            select id, standard_id, section, title, text, ir_data, obligation
            from rules
            where standard_id = any(%s)
              and lintable
              and lint_coverage is not null
              and not lint_covered
            order by standard_id, section, id
            """,
            (selected,),
        )
        rows = []
        for rid, standard_id, section, title, text, raw_ir, obligation in cur.fetchall():
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
            rows.append(
                {
                    "id": int(rid),
                    "standard_id": int(standard_id),
                    "source": source_by_id.get(int(standard_id), str(standard_id)),
                    "section": section or "",
                    "title": title or "",
                    "text": text or "",
                    "ir": ir,
                    "obligation": obligation or ir.get("obligation") or "",
                    "profile_scope": context_scope,
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
    judged = [r for r in generated if r.get("synonymy", {}).get("verdict")]
    expresses = [r for r in judged if r.get("synonymy", {}).get("verdict") == "EXPRESSES"]
    dne = [r for r in judged if r.get("synonymy", {}).get("verdict") == "DOES_NOT_EXPRESS"]
    errors = [r for r in scoped_latest.values() if r.get("error")]

    by_source = {}
    for source in sorted({r["source"] for r in domain}):
        ids = {int(r["id"]) for r in domain if r["source"] == source}
        src_rows = [scoped_latest[i] for i in ids if i in scoped_latest]
        src_gen = [r for r in src_rows if r.get("generation_success")]
        src_judged = [r for r in src_gen if r.get("synonymy", {}).get("verdict")]
        src_exp = [r for r in src_judged if r.get("synonymy", {}).get("verdict") == "EXPRESSES"]
        src_dne = [r for r in src_judged if r.get("synonymy", {}).get("verdict") == "DOES_NOT_EXPRESS"]
        by_source[source] = {
            "domain_total": len(ids),
            "completed": len(src_rows),
            "generation_success": len(src_gen),
            "generation_rate": _rate(len(src_gen), len(ids)),
            "synonymy_judged": len(src_judged),
            "synonymy_not_judged": len(src_gen) - len(src_judged),
            "synonymy_expresses": len(src_exp),
            "synonymy_does_not_express": len(src_dne),
            "synonymy_rate_over_generated": _rate(len(src_exp), len(src_judged)),
            "end_to_end_expresses_rate_over_domain": _rate(len(src_exp), len(ids)),
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
        "domain_definition": (
            "standard_id IN selected AND lintable AND lint_coverage IS NOT NULL "
            "AND lint_covered=false"
        ),
        "profile_scope": "Rule context derived from CABF §7.1.2.N profile or row section/table title",
        "domain_total": total,
        "completed": len(scoped_latest),
        "generation_success": generated_count,
        "generation_rate": _rate(generated_count, total),
        "generation_by_method": dict(sorted(by_method.items())),
        "generation_failure_by_reason": dict(sorted(by_reason.items())),
        "synonymy_judged": len(judged),
        "synonymy_not_judged": generated_count - len(judged),
        "synonymy_expresses": len(expresses),
        "synonymy_does_not_express": len(dne),
        "synonymy_rate_over_generated": _rate(len(expresses), len(judged)),
        "end_to_end_expresses_rate_over_domain": _rate(len(expresses), total),
        "synonymy_by_method": {
            method: {
                "generated": count,
                "judged": sum(
                    1 for r in generated
                    if (r.get("generation", {}).get("method") or "unknown") == method
                    and r.get("synonymy", {}).get("verdict")
                ),
                "expresses": by_method_expresses.get(method, 0),
                "rate_over_generated": _rate(
                    by_method_expresses.get(method, 0),
                    sum(
                        1 for r in generated
                        if (r.get("generation", {}).get("method") or "unknown") == method
                        and r.get("synonymy", {}).get("verdict")
                    ),
                ),
            }
            for method, count in sorted(by_method.items())
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
def _render_synonymous_lint(rule: dict, tree, precondition) -> dict | None:
    severity = det_codegen.severity_from_obligation(
        rule.get("obligation") or (rule.get("ir") or {}).get("obligation")
    )
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


def _write_expresses_index(run_dir: Path, latest: dict[int, dict],
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
    rows = _write_expresses_index(run_dir, latest, domain_ids)
    expected_files = {r.get("filename") for r in rows if r.get("filename")}
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
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


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
    print(f"[compact] ledger rows {before} -> {len(records)}", flush=True)
    return summary


# ---------------------------------------------------------------------------
# per-rule work
# ---------------------------------------------------------------------------
def _judge(rule: dict, tree, precondition, code_semantics: str, k: int) -> dict:
    return cascade.synonymy_verdict(
        tree,
        rule.get("text") or "",
        precondition=precondition,
        profile_scope=rule.get("profile_scope"),
        obligation=rule.get("obligation") or (rule.get("ir") or {}).get("obligation"),
        k=k,
    )


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
            rec["tree"] = tree
            rec["precondition"] = precondition
            rec["code_semantics"] = obligation_aware_summary(
                tree,
                precondition,
                obligation=rule.get("obligation") or (rule.get("ir") or {}).get("obligation"),
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
            if rec["synonymy"].get("verdict") == "EXPRESSES":
                rendered = _render_synonymous_lint(rule, tree, precondition)
                if rendered:
                    output_path = _write_rendered(rendered, rendered_root)
                    if output_path:
                        rendered = dict(rendered)
                        rendered["output_path"] = output_path
                        rendered.pop("file_content", None)
                rec["rendered_lint"] = rendered
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
def rejudge(domain: list[dict], run_dir: Path, k: int, only_dne: bool) -> dict:
    ledger = run_dir / "codegen_synonymy.jsonl"
    summary_path = run_dir / "codegen_synonymy_summary.json"
    ps_by_id = {int(r["id"]): r.get("profile_scope") for r in domain}
    text_by_id = {int(r["id"]): r.get("text") for r in domain}
    records = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    n_rejudged = 0
    for rec in records:
        rid = rec.get("rule_id")
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
    print(f"[rejudge] re-judged {n_rejudged} rows", flush=True)
    return summary


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--standards", default="all", help="all, cabf, rfc5280, or comma list")
    ap.add_argument("--k", type=int, default=5, help="synonym judge vote count")
    ap.add_argument("--limit", type=int, help="process only the first N domain rows")
    ap.add_argument("--run-name", default="full_current_db", help="outputs/<run-name>")
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
    ap.add_argument("--summary-only", action="store_true")
    ap.add_argument("--compact-ledger", action="store_true",
                    help="rewrite ledger to latest rows for the current domain and prune stale rendered lints")
    ap.add_argument("--zlint-v3", default=str(BACKEND / "zlint" / "v3"))
    args = ap.parse_args()

    os.environ["ZLINT_LOCAL"] = str(Path(args.zlint_v3).resolve())
    standards = _selected_standards(args.standards)
    run_dir = OUTPUTS / args.run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    ledger = run_dir / "codegen_synonymy.jsonl"
    summary_path = run_dir / "codegen_synonymy_summary.json"
    rendered_root = run_dir / "synonymous_lints"

    if args.overwrite:
        for path in (ledger, summary_path, run_dir / "synonymous_lints_manifest.json",
                     run_dir / "synonymous_lints_manifest.jsonl"):
            if path.exists():
                path.unlink()
        if rendered_root.exists():
            shutil.rmtree(rendered_root)

    domain = load_domain(standards, limit=args.limit)

    if args.compact_ledger:
        summary = compact_ledger(domain, run_dir)
        print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
        return 0

    if args.summary_only:
        summary = summarize(domain, ledger, summary_path)
        export_synonymous_from_ledger(run_dir, domain)
        print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
        return 0

    if args.rejudge:
        summary = rejudge(domain, run_dir, k=args.k, only_dne=not args.rejudge_all)
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
            sr = summary["synonymy_rate_over_generated"]
            print("[progress] completed={completed}/{domain_total} generated={generation_success} "
                  "expresses={synonymy_expresses} gen_rate={generation_rate:.3f} syn_rate={sr}".format(
                      **{**summary, "sr": f"{sr:.3f}" if sr is not None else "NA"}), flush=True)

    summary = summarize(domain, ledger, summary_path)
    export_synonymous_from_ledger(run_dir, domain)
    print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
    return 0 if summary["pending"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
