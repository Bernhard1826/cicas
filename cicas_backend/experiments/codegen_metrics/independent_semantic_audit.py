#!/usr/bin/env python3
"""Build a source-and-code dossier for an independent semantic audit.

This tool deliberately does not import or call ``synonym_judge``.  It freezes
the evidence needed to review every successfully emitted lint independently:
the original source-section excerpt, current canonical IR, cached DSL tree,
and the actual emitted Go ``CheckApplies`` / ``Execute`` bodies.  It performs
only mechanical provenance checks; a separately maintained human adjudication
file records the semantic conclusion for each rule.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2


BACKEND = Path(__file__).resolve().parents[2]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

HERE = Path(__file__).resolve().parent
RUN_DIR = HERE / "outputs" / "audited_coverage_domain"
LEDGER = RUN_DIR / "codegen_synonymy.jsonl"
MANIFEST = RUN_DIR / "all_generated_lints_manifest.json"
OUTPUT = RUN_DIR / "independent_semantic_dossier.jsonl"
SUMMARY = RUN_DIR / "independent_semantic_dossier_summary.json"
DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")
RAW_SOURCES = {
    "CABF-BR": BACKEND / "data" / "raw" / "cabf-server" / "BR.md",
    "RFC5280": BACKEND / "data" / "raw" / "rfc" / "rfc5280.txt",
}


def _json_loads(raw: Any) -> Any:
    if isinstance(raw, (dict, list)) or raw is None:
        return raw
    if isinstance(raw, str) and raw.strip():
        return json.loads(raw)
    return raw


def _inner_ir(raw: Any) -> dict[str, Any]:
    parsed = _json_loads(raw)
    if isinstance(parsed, dict) and isinstance(parsed.get("ir"), dict):
        return parsed["ir"]
    return parsed if isinstance(parsed, dict) else {}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _normalized(text: str) -> str:
    text = re.sub(r"`", "", text or "")
    text = re.sub(r"--\s*}\s*$", "", text)
    return re.sub(r"\s+", " ", text).strip().lower()


_TABLE_ROW_RULE_RE = re.compile(
    r"^In the (?P<table>.+?) table, for (?P<attribute>[A-Za-z][A-Za-z0-9-]*) "
    r"in .+?, MUST use (?P<encodings>.+?); maximum length is "
    r"(?P<length>\d+) characters$"
)


def _rule_anchor_offset(text: str, rule_text: str) -> int | None:
    """Find source-local evidence even when an extractor normalizes line breaks.

    RFC ASN.1 comments and table cells are often flattened into a rule sentence,
    so exact-string matching is intentionally not the only provenance strategy.
    The anchors are derived from the rule text, not from rule IDs.
    """
    table = _TABLE_ROW_RULE_RE.match(rule_text or "")
    lower = text.lower()
    if table:
        table_pos = lower.find(table.group("table").lower())
        search_from = table_pos if table_pos >= 0 else 0
        attr = table.group("attribute")
        attr_pos = lower.find(attr.lower(), search_from)
        if attr_pos >= 0:
            return attr_pos

    # ASN.1 modules commonly render a flattened rule as "If X is present, ..."
    # while the source places the optional field declaration between X and the
    # trailing comment.  Recover that local relation without relying on IDs.
    present = re.match(r"^If (?P<subject>[A-Za-z][A-Za-z0-9-]*) is present, (?P<tail>.+)$", rule_text or "", re.I)
    if present:
        tail_words = re.findall(r"[A-Za-z][A-Za-z0-9-]*", present.group("tail"))
        if tail_words:
            tail_pattern = r"[^A-Za-z0-9]+".join(
                re.escape(word) for word in tail_words[: min(5, len(tail_words))]
            )
            bridge = re.search(
                rf"(?is)(?<![A-Za-z0-9]){re.escape(present.group('subject'))}"
                rf"(?![A-Za-z0-9]).{{0,300}}?if\s+present[^A-Za-z0-9]+{tail_pattern}",
                text,
            )
            if bridge is not None:
                return bridge.start()

    words = re.findall(r"[A-Za-z][A-Za-z0-9-]*", rule_text or "")
    if not words:
        return None
    best: tuple[int, int] | None = None
    for width in range(min(9, len(words)), 1, -1):
        for start in range(0, len(words) - width + 1):
            chunk = words[start:start + width]
            if not any(len(word) >= 5 for word in chunk):
                continue
            pattern = r"(?i)(?<![A-Za-z0-9])" + r"[^A-Za-z0-9]+".join(
                re.escape(word) for word in chunk
            ) + r"(?![A-Za-z0-9])"
            match = re.search(pattern, text)
            if match is None:
                continue
            score = width * 100 + sum(min(len(word), 20) for word in chunk)
            candidate = (score, match.start())
            if best is None or candidate[0] > best[0] or (
                candidate[0] == best[0] and candidate[1] < best[1]
            ):
                best = candidate
        if best is not None:
            return best[1]
    return None


def _source_excerpt(source: str, section: str, rule_text: str = "",
                    max_chars: int = 8000) -> str:
    path = RAW_SOURCES[source]
    text = path.read_text(encoding="utf-8", errors="replace")
    if source == "CABF-BR":
        heading = re.compile(rf"(?m)^#{{1,6}}\s+{re.escape(section)}(?:\s|$)")
        next_heading = re.compile(r"(?m)^#{1,6}\s+(\d+(?:\.\d+)*)(?:\s|$)")
    else:
        appendix_prefix = r"(?:Appendix\s+)?" if re.fullmatch(r"[A-Z]", section) else ""
        heading = re.compile(rf"(?m)^\s*{appendix_prefix}{re.escape(section)}(?:\.|\s+)")
        next_heading = re.compile(r"(?m)^\s*(\d+(?:\.\d+)*)(?:\.|\s+)")
    fallback_excerpt = ""
    for candidate in heading.finditer(text):
        line_end = text.find("\n", candidate.start())
        line_end = len(text) if line_end < 0 else line_end
        line = text[candidate.start():line_end]
        if source == "RFC5280" and "...." in line:
            continue
        end = len(text)
        for next_candidate in next_heading.finditer(text, candidate.end()):
            line_end = text.find("\n", next_candidate.start())
            line_end = len(text) if line_end < 0 else line_end
            line = text[next_candidate.start():line_end]
            if source == "RFC5280":
                if "...." in line or line[: len(line) - len(line.lstrip())]:
                    continue
            next_section = next_candidate.group(1)
            if next_section == section or next_section.startswith(section + "."):
                continue
            end = next_candidate.start()
            break
        excerpt = text[candidate.start():end].strip()
        if not fallback_excerpt:
            fallback_excerpt = excerpt
        if rule_text and not _source_evidence_found(excerpt, rule_text):
            continue
        break
    else:
        excerpt = fallback_excerpt
    if not excerpt:
        return ""
    if len(excerpt) <= max_chars:
        return excerpt
    anchor = _rule_anchor_offset(excerpt, rule_text)
    if anchor is None:
        return excerpt[:max_chars] + "\n[truncated]"
    start = max(0, anchor - max_chars // 3)
    end = min(len(excerpt), start + max_chars)
    start = max(0, end - max_chars)
    return excerpt[start:end] + ("\n[truncated]" if end < len(excerpt) else "")


def _find_function_body(source: str, function_name: str) -> str | None:
    match = re.search(rf"(?m)^func\s+\([^\n]*\)\s+{re.escape(function_name)}\([^\n]*\)\s*[^{{]*{{", source)
    if match is None:
        return None
    start = source.find("{", match.start())
    depth = 0
    for idx in range(start, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():idx + 1]
    return None


def _go_metadata(source: str, field: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(field)}:\s*(.+),\s*$", source)
    return match.group(1).strip() if match else None


def _source_contains_rule(excerpt: str, rule_text: str) -> bool:
    needle = _normalized(rule_text)
    haystack = _normalized(excerpt)
    return bool(needle and needle in haystack)


def _source_evidence_found(excerpt: str, rule_text: str) -> bool:
    if _source_contains_rule(excerpt, rule_text):
        return True
    table = _TABLE_ROW_RULE_RE.match(rule_text or "")
    if table is None:
        return _rule_anchor_offset(excerpt, rule_text) is not None
    haystack = _normalized(excerpt)
    encodings = re.findall(r"[A-Za-z][A-Za-z0-9-]*", table.group("encodings"))
    required = [
        table.group("table"),
        table.group("attribute"),
        "must use",
        table.group("length"),
        *encodings,
    ]
    return all(_normalized(value) in haystack for value in required)


def _load_current_rules(rule_ids: set[int]) -> dict[int, dict[str, Any]]:
    with psycopg2.connect(DB_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, standard_id, section, title, text, ir_data, context
                from rules
                where id = any(%s)
                """,
                (sorted(rule_ids),),
            )
            rows = cur.fetchall()
    result: dict[int, dict[str, Any]] = {}
    for rid, standard_id, section, title, text, raw_ir, context in rows:
        source = "CABF-BR" if int(standard_id) == 19 else "RFC5280"
        ir = _inner_ir(raw_ir)
        result[int(rid)] = {
            "rule_id": int(rid),
            "standard_id": int(standard_id),
            "source": source,
            "section": section or "",
            "title": title or "",
            "text": text or "",
            "context": context or "",
            "ir": ir,
        }
    missing = sorted(rule_ids - set(result))
    if missing:
        raise RuntimeError(f"manifest rules missing from DB: {missing}")
    return result


def _mechanical_record(manifest_row: dict[str, Any], ledger_row: dict[str, Any],
                       current: dict[str, Any]) -> dict[str, Any]:
    generated_path = Path(manifest_row["output_path"])
    go_source = generated_path.read_text(encoding="utf-8") if generated_path.is_file() else ""
    excerpt = _source_excerpt(current["source"], current["section"], current["text"])
    check_applies = _find_function_body(go_source, "CheckApplies")
    execute = _find_function_body(go_source, "Execute")
    expected_description = json.dumps(current["text"], ensure_ascii=False)
    return {
        "rule_id": current["rule_id"],
        "source": current["source"],
        "section": current["section"],
        "title": current["title"],
        "rule_text": current["text"],
        "rule_context": current["context"],
        "raw_source_path": str(RAW_SOURCES[current["source"]]),
        "raw_source_sha256": _sha256_file(RAW_SOURCES[current["source"]]),
        "raw_section_excerpt": excerpt,
        "rule_text_found_in_section": _source_contains_rule(excerpt, current["text"]),
        "canonical_ir": current["ir"],
        "ledger_ir": ledger_row.get("ir"),
        "dsl_tree": ledger_row.get("tree"),
        "dsl_precondition": ledger_row.get("precondition"),
        "generation_method": (ledger_row.get("generation") or {}).get("method"),
        "generated_go_path": str(generated_path),
        "generated_go_sha256": _sha256_file(generated_path) if generated_path.is_file() else None,
        "go_metadata": {
            "name": _go_metadata(go_source, "Name"),
            "description": _go_metadata(go_source, "Description"),
            "citation": _go_metadata(go_source, "Citation"),
            "source": _go_metadata(go_source, "Source"),
        },
        "go_check_applies": check_applies,
        "go_execute": execute,
        "mechanical": {
            "model_shipping_gate_expresses": manifest_row.get("shipping_gate_verdict") == "EXPRESSES",
            "canonical_ir_matches_ledger": current["ir"] == ledger_row.get("ir"),
            "generated_file_exists": generated_path.is_file(),
            "go_registers_certificate_lint": "RegisterCertificateLint" in go_source,
            "go_has_check_applies": check_applies is not None,
            "go_has_execute": execute is not None,
            "go_description_matches_rule_text": expected_description in go_source,
            "go_citation_mentions_section": current["section"] in (_go_metadata(go_source, "Citation") or ""),
            "source_evidence_found": _source_evidence_found(excerpt, current["text"]),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=RUN_DIR)
    parser.add_argument(
        "--manifest",
        type=Path,
        help="review manifest; defaults to all successfully generated lints",
    )
    parser.add_argument(
        "--target",
        choices=("all-generated", "shipping-unanimous"),
        default="all-generated",
        help="rule set expected in the manifest",
    )
    parser.add_argument("--output", type=Path, help="dossier JSONL path")
    args = parser.parse_args()
    run_dir = args.run_dir
    ledger_path = run_dir / LEDGER.name
    manifest_path = args.manifest or (run_dir / MANIFEST.name)
    output_path = args.output or (run_dir / OUTPUT.name)
    summary_path = run_dir / SUMMARY.name

    ledger_rows = _read_jsonl(ledger_path)
    ledger = {int(row["rule_id"]): row for row in ledger_rows if row.get("complete")}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_ids = {int(row["rule_id"]) for row in manifest}
    if args.target == "shipping-unanimous":
        expected_ids = {
            rid
            for rid, row in ledger.items()
            if (row.get("ship_synonymy") or {}).get("verdict") == "EXPRESSES"
            and int((row.get("ship_synonymy") or {}).get("n_expresses") or 0)
            == int((row.get("ship_synonymy") or {}).get("k") or -1)
            and int((row.get("ship_synonymy") or {}).get("n_dne") or 0) == 0
            and int((row.get("ship_synonymy") or {}).get("n_err") or 0) == 0
            and (row.get("rendered_lint") or {}).get("output_path")
            and Path((row.get("rendered_lint") or {})["output_path"]).is_file()
        }
    else:
        expected_ids = {
            rid
            for rid, row in ledger.items()
            if row.get("generation_success")
            and (row.get("rendered_lint") or {}).get("output_path")
            and Path((row.get("rendered_lint") or {})["output_path"]).is_file()
        }
    if manifest_ids != expected_ids:
        raise RuntimeError(
            "manifest/generated rule sets differ: "
            f"only_manifest={sorted(manifest_ids - expected_ids)}, "
            f"only_generated={sorted(expected_ids - manifest_ids)}"
        )
    current = _load_current_rules(manifest_ids)
    manifest_by_id = {int(row["rule_id"]): row for row in manifest}
    records = [
        _mechanical_record(manifest_by_id[rid], ledger[rid], current[rid])
        for rid in sorted(manifest_ids)
    ]
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    checks = Counter()
    for record in records:
        for name, passed in record["mechanical"].items():
            checks[name] += int(bool(passed))
    required_mechanical_checks = {
        "canonical_ir_matches_ledger",
        "generated_file_exists",
        "go_registers_certificate_lint",
        "go_has_check_applies",
        "go_has_execute",
        "go_description_matches_rule_text",
        "go_citation_mentions_section",
        "source_evidence_found",
    }
    core_mechanical_pass = all(
        checks[name] == len(records) for name in required_mechanical_checks
    )
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "independent evidence dossier; no synonym_judge invocation",
        "target_definition": (
            "shipping manifest rows with unanimous final-emitted-code EXPRESS"
            if args.target == "shipping-unanimous"
            else "all successful generation records with an emitted Go file"
        ),
        "rule_count": len(records),
        "ledger_sha256": _sha256_file(ledger_path),
        "manifest_sha256": _sha256_file(manifest_path),
        "dossier_sha256": _sha256_file(output_path),
        "mechanical_checks": {name: {"passed": count, "total": len(records)} for name, count in sorted(checks.items())},
        "required_mechanical_checks": sorted(required_mechanical_checks),
        "core_mechanical_pass": core_mechanical_pass,
        "dossier": str(output_path),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if core_mechanical_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
