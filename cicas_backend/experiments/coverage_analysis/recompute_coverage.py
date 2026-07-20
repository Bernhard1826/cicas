#!/usr/bin/env python3
"""Targeted zlint coverage recomputation.

This script persists the same coverage verdict shape used by Table 2:
rules.lint_coverage / rules.lint_covered / rules.lint_name.

Default scope is deliberately incremental:
  lintable RFC5280/CABF-BR rules whose coverage is pending or currently uncovered.

That is the only scope that can shrink the code-generation denominator after a
coverage-candidate change such as CABF-BR rules also considering RFC5280 zlint
lints. Already-covered rows do not affect the codegen denominator and are not
rejudged unless --include-covered is passed.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2
from psycopg2.extras import RealDictCursor

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.certificate.zlint_interface import ZLintInterface  # noqa: E402
from app.services.certificate.native_go_coverage import NativeGoCoverageJudge  # noqa: E402

DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")
OUTPUTS = HERE / "outputs"


def _json_default(obj: Any) -> str:
    return str(obj)


def _parse_ir(raw: Any) -> dict:
    if not raw:
        return {}
    if isinstance(raw, dict):
        data = raw
    else:
        try:
            data = json.loads(raw)
        except Exception:
            return {}
    if isinstance(data, dict) and isinstance(data.get("ir"), dict):
        return data["ir"]
    return data if isinstance(data, dict) else {}


def _resolve_source_path(file_path: str | None) -> Path | None:
    if not file_path:
        return None
    raw = Path(file_path)
    candidates = [raw]
    if not raw.is_absolute():
        candidates.extend((BACKEND / raw, BACKEND.parent / raw))
    return next((candidate for candidate in candidates if candidate.exists()), None)


def _source_section(file_path: str | None, section: str | None, limit: int = 12000) -> str:
    """Read the authoritative rule section for the native-Go coverage judge."""
    path = _resolve_source_path(file_path)
    if path is None or not section:
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    # RFC plain-text headings; ignore table-of-contents dots.
    rfc_heading = re.compile(rf"(?m)^\s*{re.escape(section)}\.\s+.*$")
    match = next((candidate for candidate in rfc_heading.finditer(text)
                  if "...." not in candidate.group(0)), None)
    if match:
        next_heading = re.compile(r"(?m)^\s*(\d+(?:\.\d+)*)\.\s+")
        end = len(text)
        for candidate in next_heading.finditer(text, match.end()):
            next_section = candidate.group(1)
            if next_section.startswith(section + "."):
                continue
            end = candidate.start()
            break
        return text[match.start():end].strip()[:limit]
    # Markdown headings used by CABF sources.
    md_heading = re.compile(rf"(?m)^#{{1,6}}\s+{re.escape(section)}(?:\s+|$).*$")
    match = md_heading.search(text)
    if not match:
        return ""
    next_heading = re.compile(r"(?m)^#{1,6}\s+(\d+(?:\.\d+)*)(?:\s+|$)")
    end = len(text)
    for candidate in next_heading.finditer(text, match.end()):
        next_section = candidate.group(1)
        if next_section == section or next_section.startswith(section + "."):
            continue
        end = candidate.start()
        break
    return text[match.start():end].strip()[:limit]


def _same_document_reference_sections(ir: dict[str, Any], source: str, current_section: str | None) -> list[str]:
    """Return explicit, same-document section references in deterministic order.

    A normative table atom can delegate part of its meaning with wording such
    as "according to Section 7.1.4.3".  The controlled extractor records that
    relation in ``IR.references``.  Coverage must give the native-Go judge the
    referenced authoritative text as well as the local row, otherwise it may
    silently omit an incorporated cardinality or encoding constraint.  This
    intentionally follows only explicit IR references whose document is absent
    (same-document by default) or clearly names the current standard; cross-
    standard references remain out of scope for this single-file loader.
    """
    if not isinstance(ir, dict):
        return []
    source_key = re.sub(r"[^a-z0-9]", "", (source or "").lower())
    refs = ir.get("references") if isinstance(ir.get("references"), list) else []
    sections: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        section = str(ref.get("section") or "").strip()
        doc_id = re.sub(r"[^a-z0-9]", "", str(ref.get("doc_id") or "").lower())
        if not section or section == str(current_section or ""):
            continue
        if doc_id and source_key and source_key not in doc_id and doc_id not in source_key:
            continue
        if section not in sections:
            sections.append(section)
    return sections


def _authoritative_source_context(
    file_path: str | None,
    section: str | None,
    ir: dict[str, Any],
    source: str,
    limit: int = 12000,
) -> str:
    """Build the source context for semantic coverage review.

    The primary section is always present first.  Explicit same-document
    references are appended with headings, subject to the same fixed size
    bound, so the audit input is reproducible from the source file and IR.
    """
    primary = _source_section(file_path, section, limit=limit)
    if not primary:
        return ""
    parts = [f"[Authoritative section {section}]\n{primary}"]
    used = len(parts[0])
    for referenced_section in _same_document_reference_sections(ir, source, section):
        remaining = limit - used
        if remaining <= 0:
            break
        referenced = _source_section(file_path, referenced_section, limit=remaining)
        if not referenced:
            continue
        part = f"[Normatively referenced same-document section {referenced_section}]\n{referenced}"
        if used + len(part) > limit:
            part = part[:remaining]
        parts.append(part)
        used += len(part)
    return "\n\n".join(parts)[:limit]


def _build_query(args: argparse.Namespace) -> tuple[str, list[Any]]:
    where = ["r.lintable = true", "r.standard_id in (1, 19)"]
    params: list[Any] = []

    if args.rule_id:
        where.append("r.id = any(%s)")
        params.append([int(x) for x in args.rule_id])
    elif args.standard_id:
        where.append("r.standard_id = %s")
        params.append(args.standard_id)

    if args.only_pending:
        where.append("r.lint_coverage is null")
    elif args.only_uncovered:
        where.append("r.lint_coverage is not null and not coalesce(r.lint_covered, false)")
    elif args.only_covered:
        where.append("r.lint_coverage is not null and coalesce(r.lint_covered, false)")
    elif not args.include_covered:
        where.append("(r.lint_coverage is null or not coalesce(r.lint_covered, false))")

    sql = f"""
        select r.id, r.standard_id, s.source, s.file_path, r.section, r.title, r.text,
               r.ir_data, r.obligation, r.lint_covered, r.lint_name, r.lint_coverage
        from rules r
        join standards s on r.standard_id = s.id
        where {' and '.join(where)}
        order by r.standard_id, r.section, r.id
    """
    if args.limit:
        sql += " limit %s"
        params.append(args.limit)
    return sql, params


def load_rules(args: argparse.Namespace) -> list[dict]:
    sql, params = _build_query(args)
    with psycopg2.connect(DB_URL, connect_timeout=3) as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
    for row in rows:
        ir = _parse_ir(row.get("ir_data"))
        row["ir"] = ir
        row["source"] = row.get("source") or ("RFC" if row.get("standard_id") == 1 else "CABF-BR")
        row["source_section"] = _authoritative_source_context(
            row.get("file_path"), row.get("section"), ir, row["source"]
        )
        if row.get("obligation") and not ir.get("obligation"):
            ir["obligation"] = row["obligation"]
    return rows


def coverage_json(result: dict) -> dict:
    return {
        "verdict": result.get("verdict"),
        "reason": result.get("reasoning") or "",
        "fields": result.get("fields") or {},
        "lint": result.get("lint_name"),
        "n_candidates": result.get("n_candidates"),
        "match_method": result.get("match_method"),
        "matched_lints": result.get("matched_lints") or [],
        "audit": result.get("audit") or {},
        "recomputed_at": datetime.now(timezone.utc).isoformat(),
    }


def persist_result(conn, rule_id: int, result: dict) -> None:
    cov = coverage_json(result)
    with conn.cursor() as cur:
        cur.execute(
            """
            update rules
            set lint_covered = %s,
                lint_name = %s,
                lint_coverage = %s
            where id = %s
            """,
            (
                bool(result.get("has_coverage")),
                result.get("lint_name") if result.get("has_coverage") else None,
                json.dumps(cov, ensure_ascii=False, default=_json_default),
                rule_id,
            ),
        )


async def run(args: argparse.Namespace) -> int:
    OUTPUTS.mkdir(parents=True, exist_ok=True)
    out = OUTPUTS / (args.output or "recompute_coverage_results.jsonl")

    rules = load_rules(args)
    print(
        f"[scope] rows={len(rules)} standard_id={args.standard_id or 'all'} "
        f"pending={args.only_pending} uncovered={args.only_uncovered} "
        f"include_covered={args.include_covered} dry_run={args.dry_run}",
        flush=True,
    )
    if not rules:
        return 0

    zlint = None
    native_go = None
    if args.engine == "legacy-ir":
        zlint = ZLintInterface(zlint_path=str(BACKEND / "zlint"))
        await zlint.initialize_coverage_detection()
        print(
            f"[zlint-ir] CABF={len(zlint.zlint_ir_cabf)} RFC={len(zlint.zlint_ir_rfc)}",
            flush=True,
        )
    else:
        native_go = NativeGoCoverageJudge(BACKEND / "zlint")
        print(f"[native-go] certificate lints={len(native_go.load_lints())}", flush=True)

    changed_to_full = 0
    processed = 0
    errors = 0
    with psycopg2.connect(DB_URL, connect_timeout=3) as conn, out.open("a", encoding="utf-8") as log:
        for idx, row in enumerate(rules, 1):
            rid = int(row["id"])
            before = bool(row.get("lint_covered"))
            rule = {
                "id": rid,
                "text": row.get("text") or "",
                "section": row.get("section") or "",
                "title": row.get("title") or "",
                "source": row.get("source") or "",
                "source_section": row.get("source_section") or "",
                "ir": row.get("ir") or {},
                "ir_data": row.get("ir_data"),
                "lint_name": row.get("lint_name"),
            }
            try:
                if native_go is not None:
                    result = await native_go.judge(
                        rule,
                        candidate_limit=args.candidate_limit,
                        require_skeptic=not args.no_skeptic,
                    )
                else:
                    result = await zlint.check_rule_coverage_intelligent(rule)
                after = bool(result.get("has_coverage"))
                if after and not before:
                    changed_to_full += 1
                if not args.dry_run:
                    persist_result(conn, rid, result)
                    conn.commit()
                rec = {
                    "rule_id": rid,
                    "source": row.get("source"),
                    "section": row.get("section"),
                    "before_covered": before,
                    "after_covered": after,
                    "verdict": result.get("verdict"),
                    "lint_name": result.get("lint_name"),
                    "n_candidates": result.get("n_candidates"),
                    "dry_run": args.dry_run,
                    "match_method": result.get("match_method"),
                    "audit": result.get("audit") or {},
                }
                log.write(json.dumps(rec, ensure_ascii=False, default=_json_default) + "\n")
                log.flush()
                processed += 1
                print(
                    f"[{idx}/{len(rules)}] R{rid} {row.get('source')} {row.get('section') or ''} "
                    f"{'FULL' if after else result.get('verdict')} lint={result.get('lint_name')}",
                    flush=True,
                )
            except Exception as e:
                if not args.dry_run:
                    conn.rollback()
                errors += 1
                rec = {
                    "rule_id": rid,
                    "source": row.get("source"),
                    "section": row.get("section"),
                    "error": str(e)[:1000],
                    "dry_run": args.dry_run,
                }
                log.write(json.dumps(rec, ensure_ascii=False, default=_json_default) + "\n")
                log.flush()
                print(f"[{idx}/{len(rules)}] R{rid} ERROR {e}", flush=True)

    print(
        f"[done] processed={processed} changed_to_full={changed_to_full} "
        f"errors={errors} log={out}",
        flush=True,
    )
    return 0 if errors == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Targeted zlint coverage recomputation")
    ap.add_argument("--standard-id", type=int, choices=(1, 19), help="1=RFC5280, 19=CABF-BR")
    ap.add_argument("--rule-id", type=int, action="append", help="specific rule id; repeatable")
    ap.add_argument("--limit", type=int, help="maximum rows to process")
    ap.add_argument("--include-covered", action="store_true", help="also rejudge already-covered rows")
    ap.add_argument("--only-pending", action="store_true", help="only rows with lint_coverage IS NULL")
    ap.add_argument("--only-uncovered", action="store_true", help="only rows currently judged not covered")
    ap.add_argument("--only-covered", action="store_true", help="only rows currently judged fully covered")
    ap.add_argument("--dry-run", action="store_true", help="call judge but do not update DB")
    ap.add_argument(
        "--engine",
        choices=("native-go", "legacy-ir"),
        default="native-go",
        help="native-go uses actual CheckApplies/Execute plus source sections; legacy-ir is retained for comparison",
    )
    ap.add_argument("--candidate-limit", type=int, default=24, help="native Go candidates supplied to each primary judge")
    ap.add_argument("--no-skeptic", action="store_true", help="do not require the independent second full-coverage vote")
    ap.add_argument("--output", help="output JSONL filename under outputs/")
    args = ap.parse_args()
    scoped = [args.only_pending, args.only_uncovered, args.only_covered]
    if sum(bool(value) for value in scoped) > 1:
        ap.error("--only-pending, --only-uncovered, and --only-covered are mutually exclusive")
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
