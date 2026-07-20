#!/usr/bin/env python3
"""Partial feedback re-extraction for only non-synonymous/problem rows.

This is deliberately a driver around the canonical Layer-2 extractor.  It does
not patch lintability or invent per-rule outcomes.  By default it enforces the
experiment safety boundary: never re-extract rows that the current row-level
synonymy ledger already marks EXPRESSES.  Use --allow-expresses only for an
explicit source-text audit where the row-level source was found incomplete.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg2
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services.extraction.rule_discovery import RuleSkeleton
from app.services.extraction.lintability_guard import (
    context_lintability_assertion_subject,
    non_single_artifact_context_lintability_reason,
)
from app.services.certificate.codegen import vocab as cert_vocab
from app.services.full_pipeline_extractor import FullPipelineExtractor


BACKEND = Path(__file__).resolve().parent.parent
DB = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")
DEFAULT_LEDGER = (
    BACKEND
    / "experiments/codegen_metrics/outputs/allow_nongeneric_20260718/codegen_synonymy.jsonl"
)
REPO_ROOT = BACKEND.parent

DECIDED_SYNONYMY = {"EXPRESSES", "DOES_NOT_EXPRESS"}
KEYWORDS = (
    "NOT RECOMMENDED",
    "MUST NOT",
    "SHALL NOT",
    "SHOULD NOT",
    "MUST",
    "SHALL",
    "REQUIRED",
    "SHOULD",
    "RECOMMENDED",
    "MAY",
    "OPTIONAL",
)


def _make_sa_session_factory():
    engine = create_engine(DB, pool_pre_ping=True)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _loads(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _latest_ledger(path: Path) -> dict[int, dict[str, Any]]:
    latest: dict[int, dict[str, Any]] = {}
    if not path.exists():
        return latest
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        rid = row.get("rule_id")
        if row.get("complete") and rid is not None:
            latest[int(rid)] = row
    return latest


def _ledger_targets(
    path: Path,
    *,
    include_dne: bool,
    include_generation_failures: bool,
) -> tuple[list[int], set[int]]:
    latest = _latest_ledger(path)
    target: list[int] = []
    expresses: set[int] = set()
    for rid, row in sorted(latest.items()):
        syn = (row.get("synonymy") or {}).get("verdict")
        if row.get("generation_success") and syn == "EXPRESSES":
            expresses.add(rid)
            continue
        if include_dne and row.get("generation_success") and syn == "DOES_NOT_EXPRESS":
            target.append(rid)
            continue
        if include_generation_failures and not row.get("generation_success"):
            target.append(rid)
    return target, expresses


def _explicit_targets(ids: str | None) -> list[int]:
    if not ids:
        return []
    out: list[int] = []
    for part in ids.split(","):
        part = part.strip()
        if part:
            out.append(int(part))
    return list(dict.fromkeys(out))


def _keyword_for(text: str, fallback: str | None = None) -> tuple[str, int]:
    for keyword in KEYWORDS:
        m = re.search(rf"\b{re.escape(keyword)}\b", text)
        if m:
            return keyword, m.start()
    if fallback:
        fb = str(fallback).strip().upper()
        if fb:
            return fb, max(text.upper().find(fb), 0)
    return "MUST", max(text.upper().find("MUST"), 0)


def _source_name(raw: str | None, standard_id: int) -> str:
    source = (raw or "").upper()
    if "CABF" in source or standard_id == 19:
        return "CABF"
    if "RFC" in source or standard_id == 1:
        return "RFC"
    return raw or str(standard_id)


def _resolve_file_path(file_path: str | None) -> Path | None:
    """Resolve DB paths without assuming the caller's cwd.

    The standards table stores paths relative to the backend root
    (for example ``data/raw/rfc/rfc5280.txt``).  Experiment scripts run from the
    repo root, so plain ``Path(file_path)`` silently misses the source document.
    """
    if not file_path:
        return None
    raw = Path(file_path)
    candidates = [raw]
    if not raw.is_absolute():
        candidates.extend((BACKEND / raw, REPO_ROOT / raw))
    for path in candidates:
        if path.exists():
            return path
    return None


def _section_excerpt(file_path: str | None, section: str | None, max_chars: int) -> str:
    if not file_path or not section:
        return ""
    path = _resolve_file_path(file_path)
    if not path:
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    # Markdown specs such as CABF BR.
    heading = re.search(rf"(?m)^#{{1,6}}\s+{re.escape(section)}(?:\s|$)", text)
    if heading:
        next_heading = re.compile(r"(?m)^#{1,6}\s+(\d+(?:\.\d+)*)(?:\s|$)")
        end = len(text)
        for m in next_heading.finditer(text, heading.end()):
            next_section = m.group(1)
            if next_section == section or next_section.startswith(section + "."):
                continue
            end = m.start()
            break
        excerpt = text[heading.start() : end].strip()
        return _bounded(excerpt, max_chars)

    # Plain-text RFC sections.
    heading_re = re.compile(rf"(?m)^\s*{re.escape(section)}(?:\.|\s+)")
    heading = None
    for candidate in heading_re.finditer(text):
        line_end = text.find("\n", candidate.start())
        if line_end == -1:
            line_end = len(text)
        heading_line = text[candidate.start() : line_end]
        # Skip RFC table-of-contents entries, e.g.
        # "4.2.1.2. Subject Key Identifier ....................28".
        if "...." in heading_line:
            continue
        heading = candidate
        break
    if heading:
        next_heading = re.compile(r"(?m)^\s*(\d+(?:\.\d+)*)(?:\.|\s+)")
        end = len(text)
        for m in next_heading.finditer(text, heading.end()):
            line_end = text.find("\n", m.start())
            if line_end == -1:
                line_end = len(text)
            heading_line = text[m.start() : line_end]
            indent = len(heading_line) - len(heading_line.lstrip())
            if indent > 0:
                continue
            next_section = m.group(1)
            if next_section == section or next_section.startswith(section + "."):
                continue
            end = m.start()
            break
        excerpt = text[heading.start() : end].strip()
        return _bounded(excerpt, max_chars)

    return ""


def _bounded(text: str, max_chars: int) -> str:
    text = text.strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\n[excerpt truncated]"


def _normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").replace("`", "")).strip()


def _first_keyword(text: str) -> str | None:
    for keyword in KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", text or "", flags=re.I):
            return keyword
    return None


def _has_keyword(text: str) -> bool:
    return _first_keyword(text) is not None


def _hex_literals(text: str, min_len: int = 12) -> list[str]:
    return [m.group(1).lower() for m in re.finditer(r"`?([0-9a-fA-F]{%d,})`?" % min_len, text or "")]


def _candidate_needles(text: str) -> list[str]:
    norm = _normalize_ws(text)
    if not norm:
        return []
    candidates = [norm]
    short_table_needles: list[str] = []
    if "|" in norm:
        cells = [part.strip() for part in norm.split("|")]
        for cell in cells:
            if len(cell) >= 24 and _has_keyword(cell):
                candidates.append(cell)
        if len(cells) >= 2 and _has_keyword(cells[1]):
            field = _clean_table_label(cells[0])
            if field:
                short_table_needles.append(f"{field} {cells[1]}")
                short_table_needles.append(field)
    # Truncated rows often end in a dangling parenthetical reference such as
    # "(Section 4.".  Drop that tail for source-sentence lookup.
    if "(" in norm:
        candidates.append(norm.rsplit("(", 1)[0].strip())
    words = norm.split()
    for n in (18, 14, 10):
        if len(words) >= n:
            candidates.append(" ".join(words[:n]))
    out: list[str] = []
    for item in candidates + short_table_needles:
        if (len(item) >= 24 or item in short_table_needles) and item not in out:
            out.append(item)
    return out


def _needs_source_recovery(row: dict[str, Any]) -> bool:
    text = _normalize_ws(row.get("text") or "")
    if not text:
        return True
    lower = text.lower()
    if " | " in text:
        return True
    if re.search(r"\bsection\s+\d+\.$", lower):
        return True
    if re.search(r"\b(which|whose|where|whereby)$", lower):
        return True
    if re.search(r"\[[^\]]*$|\([^)]*$", text):
        return True
    if text[0].islower() or text[0].isdigit() or text[0] in {'"', ')', '.', ']', '-'}:
        return True
    if any(phrase in lower for phrase in (
        "one of the following",
        "specified hex-encoded bytes",
        "following hex-encoded bytes",
        "following signature algorithms",
    )):
        return True
    first_word = text.split(maxsplit=1)[0].upper().strip("`*_")
    if first_word in {k.split()[0] for k in KEYWORDS} and len(text) < 90:
        return True
    return False


def _loose_norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _normalize_ws(text).lower()).strip()


def _candidate_matches_old(candidate: str, old_text: str) -> bool:
    old_kw = _first_keyword(old_text)
    cand_kw = _first_keyword(candidate)
    if old_kw and cand_kw and old_kw != cand_kw:
        return False
    old_norm = _normalize_ws(old_text).lower()
    cand_norm = _normalize_ws(candidate).lower()
    if old_norm and (old_norm in cand_norm or cand_norm in old_norm):
        return True
    old_loose = _loose_norm(old_text)
    cand_loose = _loose_norm(candidate)
    return bool(old_loose and (old_loose in cand_loose or cand_loose in old_loose))


def _split_source_sentences(text: str) -> list[str]:
    compact = _normalize_ws(text)
    if not compact:
        return []
    # Split only before likely sentence starts.  This avoids breaking RFC section
    # numbers such as "4.2.1.1) of certificates issued ...".
    return [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+(?=[A-Z`])", compact)
        if part.strip()
    ]


def _split_line_sentences(line: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    start = 0
    for m in re.finditer(r"(?<=[.!?])\s+(?=[A-Z`])", line):
        end = m.start()
        part = line[start:end].strip()
        if part:
            spans.append((start, end, part))
        start = m.end()
    part = line[start:].strip()
    if part:
        spans.append((start, len(line), part))
    return spans


def _paragraph_around_line(lines: list[str], idx: int) -> str:
    """Return the physical paragraph containing lines[idx].

    Plain-text RFCs wrap one sentence across several indented lines. Looking at
    only the matched physical line can lose an antecedent on the previous line
    and then the continuation collector may pull in the whole paragraph. This
    helper gives source recovery a sentence-level window first.
    """
    start = idx
    while start > 0 and lines[start - 1].strip():
        start -= 1
    end = idx + 1
    while end < len(lines) and lines[end].strip():
        end += 1
    return _normalize_ws(" ".join(line.strip() for line in lines[start:end]))


def _matched_sentence_in_paragraph(paragraph: str, needles: list[str],
                                   loose_needles: list[str]) -> str | None:
    if not paragraph:
        return None
    for _start, _end, sentence in _split_line_sentences(paragraph):
        sentence_norm = _normalize_ws(sentence).lower()
        sentence_loose = _loose_norm(sentence)
        if (
            any(needle in sentence_norm for needle in needles)
            or any(needle and needle in sentence_loose for needle in loose_needles)
        ):
            return sentence.strip()
    return None


def _split_markdown_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _keyword_matches(text: str) -> list[re.Match[str]]:
    keywords = "|".join(re.escape(k) for k in KEYWORDS)
    return list(re.finditer(rf"\b(?:{keywords})\b", text or "", flags=re.I))


def _atomic_clause_candidates(text: str) -> list[str]:
    compact = _normalize_ws(text)
    if not compact:
        return []
    candidates: list[str] = []
    keywords = "|".join(re.escape(k) for k in KEYWORDS)
    next_keyword = re.compile(rf"\s+and\s+(?=(?:{keywords})\b)|[;|]", flags=re.I)
    for _start, _end, sentence in _split_line_sentences(compact):
        matches = _keyword_matches(sentence)
        if not matches:
            continue
        first_subject = sentence[: matches[0].start()].strip(" (,")
        antecedent_prefix = ""
        antecedent_match = re.match(r"(?is)^\s*(if\b.+?\bthen)\s+(.+)$", sentence)
        if antecedent_match:
            antecedent_prefix = antecedent_match.group(1).strip()
        for idx, m in enumerate(matches):
            next_m = matches[idx + 1] if idx + 1 < len(matches) else None
            boundary = next_keyword.search(sentence, m.end())
            if next_m is not None:
                and_before_next = sentence.rfind(" and ", m.end(), next_m.start())
                if and_before_next != -1 and (boundary is None or and_before_next < boundary.start()):
                    end = and_before_next
                else:
                    end = boundary.start() if boundary else len(sentence)
            else:
                end = boundary.start() if boundary else len(sentence)
            tail = sentence[m.start() : end].strip()
            prefix = re.sub(r"\band\s*$", "", sentence[: m.start()], flags=re.I).strip(" (,")
            quoted = re.search(r'("[^"]+"|`[^`]+`)\s*$', prefix)
            if quoted:
                subject = quoted.group(1)
            elif m.start() != matches[0].start():
                prev_and = sentence.rfind(" and ", 0, m.start())
                subject = sentence[prev_and + 5 : m.start()].strip(" (,") if prev_and != -1 else first_subject
                if antecedent_prefix and subject and not subject.lower().startswith("if "):
                    subject = f"{antecedent_prefix} {subject}"
            else:
                subject = prefix
            candidate = f"{subject} {tail}".strip() if subject else tail
            candidate = candidate.strip(" ()")
            if candidate and candidate not in candidates:
                candidates.append(candidate)
    return candidates


def _clause_around_match(text: str, old_text: str) -> str | None:
    for candidate in _atomic_clause_candidates(text):
        if _candidate_matches_old(candidate, old_text):
            return candidate
    return None


def _sentence_from_cell(cell: str, old_text: str) -> str:
    old_norm = _normalize_ws(old_text).lower()
    if (
        "must be encoded" in old_norm
        or old_norm.startswith('"')
        or old_norm.startswith("'")
    ):
        old_needles = [n.lower() for n in _candidate_needles(old_text)]
        for _start, _end, sentence in _split_line_sentences(cell):
            sentence_norm = _normalize_ws(sentence).lower()
            if not any(needle in sentence_norm for needle in old_needles):
                continue
            if re.search(r"\(\s*e\.g\.", sentence, flags=re.I):
                main = re.split(r"\s*\(\s*e\.g\.", sentence, maxsplit=1, flags=re.I)[0].strip()
                if main and _has_keyword(main):
                    return main
    clause = _clause_around_match(cell, old_text)
    if clause:
        return clause
    old_needles = [n.lower() for n in _candidate_needles(old_text)]
    for _start, _end, sentence in _split_line_sentences(cell):
        sentence_norm = _normalize_ws(sentence).lower()
        if any(needle in sentence_norm for needle in old_needles):
            return sentence.strip()
    return _normalize_ws(cell)


def _clean_table_label(cell: str) -> str:
    label = re.sub(r"\([^)]*\)", "", cell or "")
    label = re.sub(r"[*`_]", "", label)
    label = re.sub(r"\[[^\]]+\]\([^)]+\)", lambda m: m.group(0).split("](", 1)[0].lstrip("["), label)
    return _normalize_ws(label)


def _table_field_from_fragment(text: str) -> str | None:
    if "|" not in (text or ""):
        return None
    first = _normalize_ws(text).split("|", 1)[0].strip()
    field = _clean_table_label(first)
    return field or None


def _contextual_table_row_atom(lines: list[str], idx: int, old_text: str) -> str | None:
    cells = _split_markdown_row(lines[idx].strip())
    if len(cells) < 2:
        return None
    field = _clean_table_label(cells[0])
    obligation = _normalize_ws(cells[1]).upper()
    if not (re.search(r"\bany\s+other\s+qualifier\b", field, flags=re.I) and obligation == "MUST NOT"):
        return None

    allowed: list[str] = []
    cursor = idx - 1
    while cursor >= 0:
        raw = lines[cursor].strip()
        if not raw:
            if allowed:
                break
            cursor -= 1
            continue
        if raw.lower().startswith("table:"):
            break
        pcells = _split_markdown_row(raw)
        if len(pcells) >= 2:
            presence = _normalize_ws(pcells[1]).upper()
            label = _clean_table_label(pcells[0])
            if (
                label
                and not set(label) <= {"-", " "}
                and not re.search(r"\b(qualifier id|field|presence)\b", label, flags=re.I)
                and "ANY OTHER" not in label.upper()
                and "MUST NOT" not in presence
                and re.search(r"\b(MAY|MUST|SHALL|SHOULD|RECOMMENDED)\b", presence)
            ):
                allowed.append(label)
        cursor -= 1
    allowed.reverse()
    if not allowed:
        return None
    if len(allowed) == 1:
        return f"Any policyQualifier other than `{allowed[0]}` MUST NOT be present"
    return "Any policyQualifier other than " + ", ".join(f"`{x}`" for x in allowed) + " MUST NOT be present"


def _table_row_atom(line: str, old_text: str, needles: list[str]) -> str | None:
    cells = _split_markdown_row(line)
    if not cells:
        return None
    if len(cells) >= 2:
        field = _clean_table_label(cells[0])
        obligation = _normalize_ws(cells[1]).upper()
        if (
            re.search(r"\bpolicyqualifiers?\b", field, flags=re.I)
            and obligation == "NOT RECOMMENDED"
        ):
            return "`policyQualifiers` are NOT RECOMMENDED to be present"
    if len(cells) >= 4:
        field = _clean_table_label(cells[0])
        encoding = next((cell.strip() for cell in cells[1:] if re.search(r"\bMUST\s+use\b", cell, flags=re.I)), "")
        if field and encoding:
            return f"`{field}` {_normalize_ws(encoding)}"
    if len(cells) >= 3:
        field = _clean_table_label(cells[0])
        value_cell = _normalize_ws(cells[2])
        if (
            field
            and re.search(r"\bMUST\s+be\s+present\s+if\b", value_cell, flags=re.I)
        ):
            first_sentence = _split_line_sentences(value_cell)
            value = first_sentence[0][2] if first_sentence else value_cell
            return f"`{field}` {value}"
    old_norm = _normalize_ws(old_text).lower()
    loose_needles = [_loose_norm(n) for n in needles if _loose_norm(n)]
    for cell in cells:
        cell_norm = _normalize_ws(cell).lower()
        cell_loose = _loose_norm(cell)
        if old_norm and old_norm in cell_norm:
            return _sentence_from_cell(cell, old_text)
        if any(needle in cell_norm for needle in needles):
            return _sentence_from_cell(cell, old_text)
        if any(needle and needle in cell_loose for needle in loose_needles):
            return _sentence_from_cell(cell, old_text)

    if len(cells) >= 2 and re.search(r"\b(MUST|SHALL|SHOULD|RECOMMENDED)\b", cells[1], re.I):
        if len(cells) >= 3 and cells[2].strip() not in {"", "-"}:
            return _sentence_from_cell(cells[2], old_text)
        obligation = cells[1].strip()
        field = re.sub(r"[*`_]", "", cells[0]).strip()
        if obligation.upper() in {"MUST NOT", "SHALL NOT", "NOT RECOMMENDED"}:
            return f"{field} {obligation} be present"
        return f"{field} {obligation} be present"
    return _normalize_ws(line)


def _line_based_recovery(row: dict[str, Any], excerpt: str, needles: list[str]) -> str | None:
    old_text = row.get("text") or ""
    old_table_field = _table_field_from_fragment(old_text)
    loose_needles = [_loose_norm(n) for n in needles if _loose_norm(n)]
    required_hexes = _hex_literals(old_text)
    lines = excerpt.splitlines()
    for idx, line in enumerate(lines):
        line_norm = _normalize_ws(line).lower()
        line_loose = _loose_norm(line)
        if required_hexes and not any(hex_lit in line_loose for hex_lit in required_hexes):
            continue
        if (not line_norm
                or not (
                    any(needle in line_norm for needle in needles)
                    or any(needle and needle in line_loose for needle in loose_needles)
                )):
            continue

        stripped = line.strip()
        if stripped.startswith("|"):
            if old_table_field:
                cells = _split_markdown_row(stripped)
                if not cells or _clean_table_label(cells[0]) != old_table_field:
                    continue
            contextual = _contextual_table_row_atom(lines, idx, old_text)
            if contextual:
                return contextual
            return _table_row_atom(stripped, old_text, needles)

        matched_sentence = stripped
        paragraph_sentence = _matched_sentence_in_paragraph(
            _paragraph_around_line(lines, idx),
            needles,
            loose_needles,
        )
        if paragraph_sentence:
            matched_sentence = paragraph_sentence
        matched_span: tuple[int, int] | None = None
        sentence_spans: list[tuple[int, int, str]] = []
        if not paragraph_sentence:
            sentence_spans = _split_line_sentences(stripped)
            for start, end, sentence in sentence_spans:
                sentence_norm = _normalize_ws(sentence).lower()
                if any(needle in sentence_norm for needle in needles):
                    matched_sentence = sentence
                    matched_span = (start, end)
                    break

        if matched_span is not None:
            prior_sentences = [
                sentence
                for start, _end, sentence in sentence_spans
                if start < matched_span[0]
            ]
            if (
                matched_sentence.strip().lower().startswith("when encoded")
                and prior_sentences
                and re.search(r"\bif\b.{0,80}\bsigning key\b", prior_sentences[-1], flags=re.I)
            ):
                matched_sentence = f"{prior_sentences[-1].strip()} {matched_sentence.strip()}"

        clause = _clause_around_match(matched_sentence, old_text)
        if (
            clause
            and not re.search(r"\bif\b.{0,80}\bsigning key\b", matched_sentence, flags=re.I)
        ):
            matched_sentence = clause

        if paragraph_sentence:
            return _normalize_ws(matched_sentence)

        block = [matched_sentence]
        cursor = idx + 1
        matched_is_list_item = matched_sentence.strip().startswith(("- ", "* "))
        saw_list = matched_is_list_item
        in_code = False
        while cursor < len(lines):
            raw = lines[cursor]
            cur = raw.rstrip()
            cur_stripped = cur.strip()
            if not cur_stripped:
                if saw_list or in_code:
                    lookahead = cursor + 1
                    while lookahead < len(lines) and not lines[lookahead].strip():
                        lookahead += 1
                    if (
                        matched_is_list_item
                        and not in_code
                        and lookahead < len(lines)
                        and lines[lookahead].strip().startswith(("- ", "* "))
                    ):
                        break
                    block.append("")
                    cursor += 1
                    continue
                lookahead = cursor + 1
                while lookahead < len(lines) and not lines[lookahead].strip():
                    lookahead += 1
                if lookahead < len(lines):
                    nxt = lines[lookahead].strip()
                    if nxt.startswith(("- ", "* ", "```")):
                        cursor += 1
                        continue
                break
            if cur_stripped.startswith("```"):
                in_code = not in_code
                saw_list = True
                block.append(cur_stripped)
                cursor += 1
                continue
            if matched_is_list_item and saw_list and not in_code and cur_stripped.startswith(("- ", "* ")):
                break
            is_list_or_continuation = (
                in_code
                or cur.startswith((" ", "\t"))
                or cur_stripped.startswith(("- ", "* "))
            )
            if not is_list_or_continuation:
                break
            saw_list = True
            block.append(cur_stripped)
            cursor += 1

        return _normalize_ws("\n".join(block))
    return None


def _recover_source_sentence(row: dict[str, Any], max_chars: int = 50000) -> str | None:
    if not _needs_source_recovery(row):
        return None
    excerpt = _section_excerpt(row.get("file_path"), row.get("section"), max_chars)
    if not excerpt:
        return None
    needles = [n.lower() for n in _candidate_needles(row.get("text") or "")]
    if not needles:
        return None
    line_match = _line_based_recovery(row, excerpt, needles)
    if line_match:
        return line_match
    required_hexes = _hex_literals(row.get("text") or "")
    for sentence in _split_source_sentences(excerpt):
        sentence_norm = _normalize_ws(sentence).lower()
        sentence_loose = _loose_norm(sentence)
        if required_hexes and not any(hex_lit in sentence_loose for hex_lit in required_hexes):
            continue
        if any(needle in sentence_norm for needle in needles):
            return _clause_around_match(sentence, row.get("text") or "") or sentence.strip()
    return None


def _same_section_rows(cur, standard_id: int, section: str | None, rid: int, window: int) -> str:
    if not section:
        return ""
    cur.execute(
        """
        select id, title, text
        from rules
        where standard_id = %s and section = %s
        order by id
        """,
        (standard_id, section),
    )
    rows = [(int(r[0]), r[1] or "", r[2] or "") for r in cur.fetchall()]
    idx = next((i for i, row in enumerate(rows) if row[0] == rid), None)
    if idx is None:
        return ""
    start = max(0, idx - window)
    end = min(len(rows), idx + window + 1)
    lines = []
    for nrid, title, text in rows[start:end]:
        mark = ">>" if nrid == rid else "  "
        title_part = f" [{title}]" if title else ""
        lines.append(f"{mark} R{nrid}{title_part}: {text}")
    return "\n".join(lines)


def _context_block(cur, row: dict[str, Any], *, window: int, max_section_chars: int) -> str:
    nearby = _same_section_rows(
        cur,
        int(row["standard_id"]),
        row.get("section"),
        int(row["id"]),
        window,
    )
    excerpt = _section_excerpt(row.get("file_path"), row.get("section"), max_section_chars)
    parts = []
    if nearby:
        parts.append("[Same-section extracted rows]\n" + nearby)
    if excerpt:
        parts.append("[Original section excerpt]\n" + excerpt)
    return "\n\n".join(parts)


def _fetch_rows(conn, ids: list[int]) -> list[dict[str, Any]]:
    cur = conn.cursor()
    cur.execute(
        """
        select r.id, r.text, r.ir_data, r.lintable, r.standard_id, r.section,
               r.title, r.rule_type, r.sentence_index, r.context, r.is_noise,
               s.source, s.file_path, s.title, s.version
        from rules r
        join standards s on s.id = r.standard_id
        where r.id = any(%s)
        order by r.standard_id, r.section, r.id
        """,
        (ids,),
    )
    rows: list[dict[str, Any]] = []
    for rec in cur.fetchall():
        rows.append(
            {
                "id": int(rec[0]),
                "text": rec[1] or "",
                "ir_data": rec[2],
                "lintable": rec[3],
                "standard_id": int(rec[4]),
                "section": rec[5] or "",
                "title": rec[6] or "",
                "rule_type": rec[7] or "",
                "sentence_index": rec[8],
                "context": rec[9] or "",
                "is_noise": bool(rec[10]),
                "source": rec[11] or "",
                "file_path": rec[12] or "",
                "standard_title": rec[13] or "",
                "version": rec[14] or "",
            }
        )
    return rows


def _backup(rows: list[dict[str, Any]], backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = backup_dir / f"reextract_pilot_backup_{stamp}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(
                json.dumps(
                    {
                        "id": row["id"],
                        "text": row["text"],
                        "ir_data": row["ir_data"]
                        if isinstance(row["ir_data"], str)
                        else json.dumps(row["ir_data"], ensure_ascii=False),
                        "lintable": row["lintable"],
                        "is_noise": row.get("is_noise"),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return path


def _ir_key(text: str) -> str:
    return hashlib.md5((text or "").strip().encode("utf-8")).hexdigest()


def _inner_ir(ir_obj: Any) -> dict[str, Any]:
    return json.loads(ir_obj.to_json())["ir"]


def _diff_summary(old_inner: dict[str, Any], new_inner: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "lintable",
        "non_lintable_reason",
        "assertion_subject",
        "enforcement_phase",
        "rule_category",
        "subject",
        "predicate",
        "obligation",
        "constraint",
        "precondition",
    )
    out: dict[str, Any] = {}
    for key in keys:
        old = old_inner.get(key)
        new = new_inner.get(key)
        if old != new:
            out[key] = {"old": old, "new": new}
    return out


def _context_lintability_guard(row: dict[str, Any]) -> str | None:
    return non_single_artifact_context_lintability_reason(
        row.get("title"),
        row.get("text"),
        row.get("context"),
        row.get("_local_context"),
    )


def _apply_context_lintability_guard(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    old_outer = _loads(row["ir_data"])
    old_inner = old_outer.get("ir", old_outer)
    new_inner = dict(old_inner) if isinstance(old_inner, dict) else {}
    reason = _context_lintability_guard(row) or (
        "rule context is not decidable from one certificate's encoded bytes"
    )
    new_inner.update(
        {
            "assertion_subject": context_lintability_assertion_subject(reason),
            "verifiability": "context_dependent",
            "lintable": False,
            "non_lintable_reason": reason,
        }
    )
    if not new_inner.get("rule_category"):
        new_inner["rule_category"] = "encoding_constraint"
    return old_outer if isinstance(old_outer, dict) else {}, new_inner


def _canonical_dn_attr_name(value: Any) -> str | None:
    raw = str(value or "").strip().strip("`")
    if not raw:
        return None
    if raw in cert_vocab.DN_ATTR_OID_BY_NAME:
        return raw
    if raw in cert_vocab.DN_FIELD_TO_ATTR_NAME:
        return cert_vocab.DN_FIELD_TO_ATTR_NAME[raw]
    compact = re.sub(r"[^a-z0-9]", "", raw.lower())
    for attr in cert_vocab.DN_ATTR_OID_BY_NAME:
        if compact == re.sub(r"[^a-z0-9]", "", attr.lower()):
            return attr
    for field, attr in cert_vocab.DN_FIELD_TO_ATTR_NAME.items():
        if compact == re.sub(r"[^a-z0-9]", "", field.lower()):
            return attr
    return None


def _extract_subject_attr_table_allowlist(context: str) -> list[str]:
    lines = (context or "").splitlines()
    target_rows = [
        i for i, line in enumerate(lines)
        if line.strip().startswith("|")
        and "any other attribute" in line.lower()
        and ("not recommended" in line.lower() or "must not" in line.lower())
    ]
    for idx in target_rows:
        attrs_rev: list[str] = []
        saw_subject_table = False
        j = idx - 1
        while j >= 0:
            line = lines[j]
            stripped = line.strip()
            lower = stripped.lower()
            if "table:" in lower and "`subject` attributes" in lower:
                saw_subject_table = True
                break
            if stripped.startswith("|"):
                cells = [cell.strip() for cell in stripped.strip("|").split("|")]
                first = cells[0] if cells else ""
                if not first or "---" in first or "attribute name" in first.lower():
                    j -= 1
                    continue
                presence = re.sub(r"\s+", " ", cells[1].lower()) if len(cells) > 1 else ""
                if "must not" in presence:
                    j -= 1
                    continue
                attr = _canonical_dn_attr_name(first)
                if attr and attr not in attrs_rev:
                    attrs_rev.append(attr)
            elif attrs_rev and stripped:
                break
            j -= 1
        attrs = list(reversed(attrs_rev))
        if attrs and saw_subject_table:
            return attrs
    return []


def _subject_attribute_allowlist_reextract(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Recover "Any other subject attribute" table rows as a closed DN allow-list.

    This is a deterministic re-extraction from the source table, not a DB patch:
    it rewrites only ir_data.ir so downstream lintability/coverage/codegen derive
    their results from structured IR.
    """
    row_text = str(row.get("text") or "")
    row_lower = row_text.lower()
    if "any other attribute" not in row_lower:
        return None, None
    if "not recommended" not in row_lower and "must not" not in row_lower:
        return None, None
    blob = "\n".join(
        str(row.get(k) or "")
        for k in ("text", "title", "context", "_local_context")
    ).lower()
    if "`subject` attributes" not in blob and "subject attribute" not in blob:
        return None, None
    allowed_attrs = _extract_subject_attr_table_allowlist(row.get("_local_context") or "")
    if not allowed_attrs:
        return None, None

    old_outer = _loads(row["ir_data"])
    old_inner = old_outer.get("ir", old_outer)
    new_inner = dict(old_inner) if isinstance(old_inner, dict) else {}
    obligation = "NOT RECOMMENDED" if "not recommended" in row_lower else "MUST NOT"
    new_inner.update(
        {
            "lint_name": "subject_attribute_types_only_allowed",
            "description": "Any other subject attribute is not recommended",
            "subject": "subject.attributeTypes",
            "subject_ref": {
                "path": "subject.attributeTypes",
                "aliases": ["subject AttributeType", "AttributeTypeAndValue.type"],
                "field_id": None,
                "raw": "Any other attribute",
                "resolved": True,
                "resolution_method": "source_table_allowlist",
            },
            "obligation": obligation,
            "predicate": "must_only_include",
            "constraint": {
                "raw_text": f"Any other attribute {obligation}",
                "type": "dn_attribute_allowlist",
                "value": None,
                "unit": None,
                "expanded": None,
                "min_value": None,
                "max_value": None,
                "pattern": None,
                "allowed_values": allowed_attrs,
                "asn1_types": None,
            },
            "assertion_subject": "Certificate",
            "enforcement_phase": "Encoding",
            "lintable": True,
            "non_lintable_reason": None,
            "rule_category": "encoding_constraint",
            "verifiability": "observable",
        }
    )
    return old_outer if isinstance(old_outer, dict) else {}, new_inner


def _write_report(report_rows: list[dict[str, Any]], backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = backup_dir / f"reextract_pilot_report_{stamp}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for row in report_rows:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", help="comma-separated explicit rule ids; EXPRESS rows are still skipped unless --allow-expresses is set")
    ap.add_argument(
        "--allow-expresses",
        action="store_true",
        help="allow explicit re-extraction of rows currently marked EXPRESSES; use only for source-text audits",
    )
    ap.add_argument("--from-ledger", action="store_true", help="derive targets from current codegen ledger")
    ap.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    ap.add_argument("--include-dne", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--include-generation-failures", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--max-rules", type=int, default=None)
    ap.add_argument("--context-window", type=int, default=8)
    ap.add_argument("--max-section-chars", type=int, default=7000)
    ap.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="rules per backend Layer-2 call; default 1 preserves id/result alignment",
    )
    ap.add_argument("--commit", action="store_true")
    ap.add_argument(
        "--llm-only",
        action="store_true",
        help=(
            "bypass deterministic IR rewrite helpers and send every selected row "
            "through canonical Layer-2 re-extraction; use for source-scope audits"
        ),
    )
    ap.add_argument(
        "--update-text",
        action="store_true",
        help="with --commit, also persist recovered source text to rules.text when it changed",
    )
    ap.add_argument(
        "--clear-noise-on-lintable",
        action="store_true",
        help=(
            "with --commit, set is_noise=false when re-extraction produces "
            "ir.lintable=true; this keeps the generated lintable column aligned "
            "with the re-adjudicated IR instead of preserving an obsolete discovery "
            "noise flag"
        ),
    )
    ap.add_argument("--backup-dir", type=Path, default=Path(__file__).resolve().parent / "backups")
    args = ap.parse_args()

    explicit = _explicit_targets(args.ids)
    ledger_targets, expresses = _ledger_targets(
        args.ledger,
        include_dne=args.include_dne,
        include_generation_failures=args.include_generation_failures,
    )
    if explicit:
        candidate_ids = explicit
    elif args.from_ledger or not args.ids:
        candidate_ids = ledger_targets
    else:
        candidate_ids = []

    skipped_expresses = [] if args.allow_expresses else [rid for rid in candidate_ids if rid in expresses]
    target_ids = candidate_ids if args.allow_expresses else [rid for rid in candidate_ids if rid not in expresses]
    target_ids = list(dict.fromkeys(target_ids))
    if args.max_rules is not None:
        target_ids = target_ids[: args.max_rules]

    if not target_ids:
        print("[done] no eligible targets; already-EXPRESSES rows are protected")
        if skipped_expresses:
            print(f"[protected] skipped EXPRESS rows: {skipped_expresses}")
        return 0

    conn = psycopg2.connect(DB)
    sa_session_factory = _make_sa_session_factory()
    cur = conn.cursor()
    rows = _fetch_rows(conn, target_ids)
    found = {row["id"] for row in rows}
    missing = [rid for rid in target_ids if rid not in found]
    if missing:
        print(f"[warn] ids not found in DB: {missing}")
    if skipped_expresses:
        print(f"[protected] skipped current row-level EXPRESS rows: {skipped_expresses}")

    backup_path = _backup(rows, args.backup_dir)
    print(f"[backup] {len(rows)} rows -> {backup_path}")
    print(f"[mode] commit={args.commit} db={DB} ledger={args.ledger}")

    report_rows: list[dict[str, Any]] = []
    wrote = 0
    llm_rows: list[dict[str, Any]] = []
    for row in rows:
        row["_local_context"] = _context_block(
            cur,
            row,
            window=args.context_window,
            max_section_chars=args.max_section_chars,
        )
        if args.llm_only:
            llm_rows.append(row)
            continue
        guard_reason = _context_lintability_guard(row)
        if guard_reason:
            old_outer, new_inner = _apply_context_lintability_guard(row)
            old_inner = old_outer.get("ir", old_outer)
            diff = _diff_summary(old_inner if isinstance(old_inner, dict) else {}, new_inner)
            report_rows.append(
                {
                    "id": row["id"],
                    "status": "matched",
                    "match_method": "deterministic_context_lintability_guard",
                    "old_lintable": row["lintable"],
                    "old_is_noise": row.get("is_noise"),
                    "input_text_changed": False,
                    "input_text": row["text"],
                    "new_lintable": new_inner.get("lintable"),
                    "new_is_noise": row.get("is_noise"),
                    "new_assertion_subject": new_inner.get("assertion_subject"),
                    "new_rule_category": new_inner.get("rule_category"),
                    "new_non_lintable_reason": new_inner.get("non_lintable_reason"),
                    "diff": diff,
                }
            )
            print(
                f"  R{row['id']}: context guard lintable {row['lintable']} -> "
                f"{new_inner.get('lintable')} as={new_inner.get('assertion_subject')} "
                f"reason={guard_reason}"
            )
            if args.commit:
                old_outer = old_outer if isinstance(old_outer, dict) else {}
                old_outer["ir"] = new_inner
                cur.execute(
                    """
                    update rules
                       set ir_data = %s,
                           lint_coverage = null,
                           lint_covered = null,
                           lint_name = null
                     where id = %s
                    """,
                    (json.dumps(old_outer, ensure_ascii=False), row["id"]),
                )
                wrote += 1
            continue
        old_outer, new_inner = _subject_attribute_allowlist_reextract(row)
        if new_inner is not None:
            old_inner = old_outer.get("ir", old_outer) if isinstance(old_outer, dict) else {}
            diff = _diff_summary(old_inner if isinstance(old_inner, dict) else {}, new_inner)
            report_rows.append(
                {
                    "id": row["id"],
                    "status": "matched",
                    "match_method": "deterministic_subject_attribute_allowlist_reextract",
                    "old_lintable": row["lintable"],
                    "old_is_noise": row.get("is_noise"),
                    "input_text_changed": False,
                    "input_text": row["text"],
                    "new_lintable": new_inner.get("lintable"),
                    "new_is_noise": row.get("is_noise"),
                    "new_assertion_subject": new_inner.get("assertion_subject"),
                    "new_rule_category": new_inner.get("rule_category"),
                    "new_non_lintable_reason": new_inner.get("non_lintable_reason"),
                    "diff": diff,
                }
            )
            print(
                f"  R{row['id']}: subject AttributeType allow-list recovered "
                f"({len(new_inner.get('constraint', {}).get('allowed_values') or [])} attrs)"
            )
            if args.commit:
                old_outer = old_outer if isinstance(old_outer, dict) else {}
                old_outer["ir"] = new_inner
                cur.execute(
                    """
                    update rules
                       set ir_data = %s,
                           lint_coverage = null,
                           lint_covered = null,
                           lint_name = null
                     where id = %s
                    """,
                    (json.dumps(old_outer, ensure_ascii=False), row["id"]),
                )
                wrote += 1
            continue
        llm_rows.append(row)

    by_std: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in llm_rows:
        key = (
            row["standard_id"],
            row["source"],
            row["file_path"],
            row["standard_title"],
            row["version"],
        )
        by_std.setdefault(key, []).append(row)

    for (standard_id, source, file_path, standard_title, version), std_rows in by_std.items():
        path = _resolve_file_path(file_path)
        document_text = path.read_text(encoding="utf-8", errors="ignore") if path else ""
        if not document_text:
            print(f"[warn] source text unavailable for standard {standard_id}: {file_path}")
        context = {
            "source": _source_name(source, int(standard_id)),
            "title": standard_title,
            "version": version,
            "file_path": str(path or file_path or ""),
            "standard_id": standard_id,
        }
        for start in range(0, len(std_rows), max(1, args.batch_size)):
            batch_rows = std_rows[start : start + max(1, args.batch_size)]
            # FullPipelineExtractor caches ContextBuilder.  Recreate it per
            # backend call so a previous standard/document cannot leak context.
            sa_db = sa_session_factory()
            extractor = FullPipelineExtractor(db=sa_db)
            skeletons: list[RuleSkeleton] = []
            for row in batch_rows:
                input_text = _recover_source_sentence(row) or row["text"]
                row["_reextract_text"] = input_text
                kw, pos = _keyword_for(input_text, row.get("rule_type"))
                para = _context_block(
                    cur,
                    row,
                    window=args.context_window,
                    max_section_chars=args.max_section_chars,
                )
                skeletons.append(
                    RuleSkeleton(
                        rule_id=f"reextract-{row['id']}",
                        section=row.get("section") or "",
                        sentence=input_text,
                        keyword=kw,
                        keyword_position=pos,
                        sentence_index=row.get("sentence_index")
                        if row.get("sentence_index") is not None
                        else 0,
                        line_number=row.get("sentence_index"),
                        source_sentence=input_text,
                        assertion_text=input_text,
                        section_title=row.get("title") or "",
                        paragraph_text=para,
                    )
                )

            try:
                layer2 = asyncio.run(extractor._layer2_llm_extraction(skeletons, document_text, context))
            finally:
                sa_db.close()
            resolved = layer2.get("resolved_irs", [])
            by_hash: dict[str, Any] = {}
            for ir in resolved:
                by_hash.setdefault(_ir_key(getattr(ir, "rule_text", "")), ir)

            print(
                f"[{context['source']}:{standard_id}] extracted {len(resolved)} IRs "
                f"for {len(batch_rows)} targets"
            )
            positional_ok = len(resolved) == len(batch_rows)
            for idx, row in enumerate(batch_rows):
                input_text = row.get("_reextract_text") or row["text"]
                ir_obj = by_hash.get(_ir_key(input_text))
                match_method = "rule_text_hash"
                if ir_obj is None and positional_ok:
                    ir_obj = resolved[idx]
                    match_method = "position"
                if ir_obj is None:
                    print(f"  R{row['id']}: NO MATCH")
                    report_rows.append(
                        {
                            "id": row["id"],
                            "status": "no_match",
                            "input_text_changed": input_text != row["text"],
                            "input_text": input_text,
                        }
                    )
                    continue

                new_inner = _inner_ir(ir_obj)
                old_outer = _loads(row["ir_data"])
                old_inner = old_outer.get("ir", old_outer)
                diff = _diff_summary(old_inner if isinstance(old_inner, dict) else {}, new_inner)
                report_rows.append(
                    {
                        "id": row["id"],
                        "status": "matched",
                        "match_method": match_method,
                        "old_lintable": row["lintable"],
                        "old_is_noise": row.get("is_noise"),
                        "input_text_changed": input_text != row["text"],
                        "input_text": input_text,
                        "new_lintable": new_inner.get("lintable"),
                        "new_is_noise": (
                            False
                            if args.clear_noise_on_lintable
                            and new_inner.get("lintable") is True
                            else row.get("is_noise")
                        ),
                        "new_assertion_subject": new_inner.get("assertion_subject"),
                        "new_rule_category": new_inner.get("rule_category"),
                        "new_non_lintable_reason": new_inner.get("non_lintable_reason"),
                        "diff": diff,
                    }
                )
                print(
                    f"  R{row['id']}: lintable {row['lintable']} -> {new_inner.get('lintable')} "
                    f"as={new_inner.get('assertion_subject')} cat={new_inner.get('rule_category')} "
                    f"subject={new_inner.get('subject')} pred={new_inner.get('predicate')}"
                )
                if args.commit:
                    old_outer = old_outer if isinstance(old_outer, dict) else {}
                    old_outer["ir"] = new_inner
                    clear_noise = (
                        args.clear_noise_on_lintable
                        and new_inner.get("lintable") is True
                    )
                    cur.execute(
                        """
                        update rules
                           set ir_data = %s,
                               is_noise = case when %s then false else is_noise end,
                               lint_coverage = null,
                               lint_covered = null,
                               lint_name = null
                         where id = %s
                        """,
                        (
                            json.dumps(old_outer, ensure_ascii=False),
                            clear_noise,
                            row["id"],
                        ),
                    )
                    if args.update_text and input_text != row["text"]:
                        cur.execute(
                            "update rules set text = %s where id = %s",
                            (input_text, row["id"]),
                        )
                    wrote += 1

    report_path = _write_report(report_rows, args.backup_dir)
    if args.commit:
        conn.commit()
    else:
        conn.rollback()
    print(f"[report] {report_path}")
    print(f"[done] wrote={wrote} commit={args.commit} protected_expresses={len(skipped_expresses)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
