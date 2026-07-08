#!/usr/bin/env python3
"""Audit rules that may not be observable from one certificate.

This is intentionally conservative. It does not demote a rule merely because
current codegen lacks an atom. It only reports candidates whose truth appears
to depend on a non-certificate artifact, issuer history, or protocol/process
text outside the DER certificate being linted.

Important: this script does not update the DB and must not be used to reduce
coverage/codegen denominators directly. Denominator changes must come from
targeted IR re-extraction or targeted lintability adjudication that writes
`ir_data.ir.lintable=false` plus a concrete `non_lintable_reason`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass

import psycopg2


DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")


@dataclass(frozen=True)
class ReasonRule:
    reason: str
    title_re: str | None = None
    text_re: str | None = None

    def matches(self, *, title: str, text: str, section: str) -> bool:
        hay_title = f"{section} {title}"
        if self.title_re and not re.search(self.title_re, hay_title, re.I):
            return False
        if self.text_re and not re.search(self.text_re, text, re.I):
            return False
        return True


RULES: tuple[ReasonRule, ...] = (
    ReasonRule(
        reason="not_single_certificate_artifact:dns_txt_rdata",
        title_re=r"\bDNS\s+TXT\b|TXT Record|Email Contact",
        text_re=r"\bRDATA\b|TXT record",
    ),
    ReasonRule(
        reason="not_single_certificate_artifact:communication_result_message",
        title_re=r"Communication of results",
    ),
    ReasonRule(
        reason="not_single_certificate_context:issuer_history_new_subject",
        text_re=r"\bnew subjects?\b",
    ),
    ReasonRule(
        reason="not_single_certificate_artifact:certificate_request_or_csr",
        text_re=r"\b(certificate request|CSR|PKCS#10|Request Token)\b",
    ),
)


def classify(title: str, text: str, section: str) -> str | None:
    for rule in RULES:
        if rule.matches(title=title or "", text=text or "", section=section or ""):
            return rule.reason
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--standards", default="1,19", help="comma-separated standard ids")
    args = ap.parse_args()
    standard_ids = [int(x.strip()) for x in args.standards.split(",") if x.strip()]

    with psycopg2.connect(DB_URL, connect_timeout=3) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            select id, standard_id, section, title, text
            from rules
            where standard_id = any(%s)
              and lintable = true
            order by standard_id, section, id
            """,
            (standard_ids,),
        )
        rows = cur.fetchall()
        matches: list[tuple[int, str, str, str, str, str]] = []
        for rid, sid, section, title, text in rows:
            reason = classify(title or "", text or "", section or "")
            if reason:
                matches.append((int(rid), str(sid), section or "", title or "", text or "", reason))
        conn.rollback()

    print(json.dumps({
        "mode": "CANDIDATE_AUDIT_ONLY",
        "db_updates": 0,
        "matched": len(matches),
        "rules": [
            {
                "id": rid,
                "standard_id": sid,
                "section": section,
                "title": title,
                "text": text,
                "reason": reason,
            }
            for rid, sid, section, title, text, reason in matches
        ],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
