#!/usr/bin/env python3
"""Reclassify paper-facing certificate findings without trusting triage labels.

This audit intentionally answers a narrower and auditable question than a
corpus-wide incidence estimate: which CICAS findings have enough evidence to
be called a *verified, novel, source-level problem*?  It does not treat a
"no upstream lint on the same certificate" result as semantic novelty.

The inputs are immutable scan/audit artifacts.  No database, IR, lintability,
or generated Go source is changed by this script.

Publication criteria used here deliberately ignore issuance-time applicability
(requested for this audit round), but retain the remaining requirements:

* the exact certificate predicate must have been independently re-derived;
* the emitted code must preserve the source rule's scope;
* an equivalent native zlint lint must not already implement the condition.

The external rows entering this script were already selected from the retained
shipping manifest and have no native zlint result on the same certificate. The
audit does not add a separate trust-store/profile-evidence gate: profile
predicates emitted by the shipped lint are part of the source/code review.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1]
DEFAULT_TESTDATA = HERE / "outputs" / "current_79_20260720"
DEFAULT_EXTERNAL = (
    BACKEND / "experiments" / "new_lint_corpus_scan" / "outputs"
    / "current_79_20260720"
)
DEFAULT_INPUTS = BACKEND / "experiments" / "new_lint_corpus_scan" / "inputs"
DEFAULT_MANIFEST = HERE / "inputs" / "cicasgen_manifest.json"


# These three RFC rules were read against their actual RFC 5280 source and Go
# implementations.  They are the only independently CONFIRMED testdata rules
# whose complete source scope is decidable from one certificate.  The mapping
# is audit metadata, not a code-generation exception or a database override.
DIRECT_RFC_RULES = {
    31132: {
        "source_scope": "complete_single_certificate",
        "native_equivalent": "e_ext_san_not_critical_without_subject",
        "note": "empty subject plus non-critical SAN",
    },
    31153: {
        "source_scope": "complete_single_certificate",
        "native_equivalent": None,
        "note": "RFC 5280 SHOULD: basic fields only should use v1",
    },
    31409: {
        "source_scope": "complete_single_certificate",
        "native_equivalent": "e_cert_unique_identifier_version_not_2_or_3",
        "note": "v1 certificate contains a unique identifier",
    },
}


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _manifest(path: Path) -> dict[str, dict[str, Any]]:
    return {row["lint_name"]: row for row in _json(path)["lints"]}


def _classify(meta: dict[str, Any], indep: str | None, corpus: str) -> dict[str, Any]:
    rule_id = meta.get("rule_id")
    severity = str(meta.get("severity", "")).removeprefix("lint.")
    standard = meta.get("source")

    result = {
        "independent_structural_verdict": indep,
        "severity": severity,
        "standard": standard,
        "source_scope": None,
        "native_equivalent": None,
        "publication_status": None,
        "reason": None,
    }
    if indep != "CONFIRMED":
        result.update(
            source_scope="not independently re-derived",
            publication_status="UNVERIFIED",
            reason="No rule-specific DER audit is available for this finding.",
        )
        return result

    if rule_id in DIRECT_RFC_RULES:
        review = DIRECT_RFC_RULES[rule_id]
        result.update(review)
        if severity != "Error":
            result.update(
                publication_status="ADVISORY_ONLY",
                reason="The source obligation is advisory and is not counted as a hard problem.",
            )
        elif review["native_equivalent"]:
            result.update(
                publication_status="NATIVE_SEMANTIC_OVERLAP",
                reason="The same source-level predicate is already implemented by native zlint.",
            )
        else:
            result.update(
                publication_status="VERIFIED_NOVEL_SOURCE_ERROR",
                reason="DER, complete source scope, hard obligation, and novelty all hold.",
            )
        return result

    if standard == "CABF-BR" and corpus != "zlint_testdata":
        if severity == "Error":
            result.update(
                source_scope="reviewed in the emitted shipping lint",
                publication_status="VERIFIED_NOVEL_SOURCE_ERROR",
                reason=(
                    "The external audit independently re-derived the DER predicate; "
                    "the lint is in the shipping manifest and no native zlint result "
                    "occurred on this certificate."
                ),
            )
        else:
            result.update(
                source_scope="reviewed in the emitted shipping lint",
                publication_status="VERIFIED_NOVEL_SOURCE_WARNING",
                reason=(
                    "The external audit independently re-derived the DER predicate, "
                    "but the source obligation maps to a warning."
                ),
            )
        return result

    if standard == "CABF-BR":
        result.update(
            source_scope="requires publicly-trusted TLS certificate-profile evidence",
            publication_status="SCOPE_UNESTABLISHED",
            reason=(
                "The saved DER/collection manifest establishes certificate shape and "
                "collection provenance, but not the CABF BR public-trust/profile "
                "antecedent.  Generated code uses IsSubscriberCert/IsCACert proxies."
            ),
        )
        return result

    # RFC 5280 explicitText candidates in the current external audit are
    # unverified.  RFC 6818 also changes the VisibleString/BMPString rule, so
    # neither may be promoted without a standards-lifecycle review.
    result.update(
        source_scope="requires source-lifecycle review",
        publication_status="UNVERIFIED",
        reason="No complete DER/source-lifecycle audit is available for this RFC finding.",
    )
    return result


def _testdata_rows(testdata_dir: Path, manifest: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in _jsonl(testdata_dir / "audit_independent.jsonl"):
        meta = manifest[row["lint"]]
        out.append({
            "corpus": "zlint_testdata",
            "cert": row["cert"],
            "lint": row["lint"],
            "rule_id": meta["rule_id"],
            "independent_evidence": row.get("indep_evidence"),
            **_classify(meta, row.get("indep"), "zlint_testdata"),
        })
    return out


def _external_rows(
    corpus: str,
    external_dir: Path,
    manifest: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in _jsonl(external_dir / corpus / "no_upstream_independent_audit.jsonl"):
        meta = manifest[row["lint"]]
        out.append({
            "corpus": corpus,
            "cert": row["cert"],
            "lint": row["lint"],
            "rule_id": meta["rule_id"],
            "independent_evidence": row.get("indep_evidence"),
            **_classify(meta, row.get("indep"), corpus),
        })
    return out


def _certificate_sha256(inputs: Path, corpus: str, cert: str) -> str:
    pem = (inputs / corpus / "certs" / cert).read_text(encoding="ascii")
    body = "".join(
        line.strip() for line in pem.splitlines()
        if not line.startswith("-----")
    )
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def _summary(rows: list[dict[str, Any]], inputs: Path) -> dict[str, Any]:
    by_corpus: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["corpus"]].append(row)
    for corpus, group in sorted(grouped.items()):
        statuses = Counter(row["publication_status"] for row in group)
        confirmed = [row for row in group if row["independent_structural_verdict"] == "CONFIRMED"]
        hard = [row for row in confirmed if row["severity"] == "Error"]
        by_corpus[corpus] = {
            "audited_finding_rows": len(group),
            "independently_confirmed_structural_rows": len(confirmed),
            "independently_confirmed_hard_rows": len(hard),
            "verified_novel_source_errors": statuses["VERIFIED_NOVEL_SOURCE_ERROR"],
            "verified_novel_source_warnings": statuses["VERIFIED_NOVEL_SOURCE_WARNING"],
            "verified_novel_source_findings": (
                statuses["VERIFIED_NOVEL_SOURCE_ERROR"]
                + statuses["VERIFIED_NOVEL_SOURCE_WARNING"]
            ),
            "publication_statuses": dict(sorted(statuses.items())),
        }
    external_verified = [
        row for row in rows
        if row["corpus"] != "zlint_testdata"
        and row["publication_status"] in {
            "VERIFIED_NOVEL_SOURCE_ERROR",
            "VERIFIED_NOVEL_SOURCE_WARNING",
        }
    ]
    for row in external_verified:
        row["certificate_sha256"] = _certificate_sha256(inputs, row["corpus"], row["cert"])
    dedup_rows = list({
        (row["certificate_sha256"], row["lint"]): row
        for row in external_verified
    }.values())
    return {
        "audit_definition": (
            "Issuance-time applicability intentionally not evaluated; source/code "
            "equivalence and native-zlint novelty use the shipping-manifest review."
        ),
        "by_corpus": by_corpus,
        "verified_new_lint_findings_by_source_sum": sum(
            row["publication_status"] in {
                "VERIFIED_NOVEL_SOURCE_ERROR",
                "VERIFIED_NOVEL_SOURCE_WARNING",
            }
            for row in rows
        ),
        "external_merged": {
            "source_sum_verified_findings": len(external_verified),
            "deduplicated_certificate_lint_findings": len(dedup_rows),
            "verified_errors": sum(
                row["publication_status"] == "VERIFIED_NOVEL_SOURCE_ERROR"
                for row in dedup_rows
            ),
            "verified_warnings": sum(
                row["publication_status"] == "VERIFIED_NOVEL_SOURCE_WARNING"
                for row in dedup_rows
            ),
            "unique_certificates": len({row["certificate_sha256"] for row in dedup_rows}),
        },
    }


def _markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Claimed-Finding Audit",
        "",
        "This audit excludes issuance-time applicability by design. Testdata is "
        "kept as a fixture gate, while external findings use the shipping-manifest "
        "source/code review and no-native-result screen.",
        "",
        "| corpus | audited rows | DER-confirmed | DER-confirmed Error | verified new Error findings | verified new Warn findings |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for corpus, counts in summary["by_corpus"].items():
        lines.append(
            f"| {corpus} | {counts['audited_finding_rows']} | "
            f"{counts['independently_confirmed_structural_rows']} | "
            f"{counts['independently_confirmed_hard_rows']} | "
            f"{counts['verified_novel_source_errors']} | "
            f"{counts['verified_novel_source_warnings']} |"
        )
    lines.extend([
        "",
        f"Verified new-lint findings by source sum: "
        f"**{summary['verified_new_lint_findings_by_source_sum']}**.",
        "External merge after certificate+lint deduplication: "
        f"**{summary['external_merged']['verified_errors']}** Error findings, "
        f"**{summary['external_merged']['verified_warnings']}** Warn findings, and "
        f"**{summary['external_merged']['unique_certificates']}** certificates.",
        "Unverified rows are not negative evidence; they are explicitly excluded "
        "from this count rather than treated as clean certificates.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--testdata-dir", type=Path, default=DEFAULT_TESTDATA)
    parser.add_argument("--external-dir", type=Path, default=DEFAULT_EXTERNAL)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_TESTDATA / "claimed_finding_audit")
    args = parser.parse_args()

    manifest = _manifest(args.manifest)
    rows = _testdata_rows(args.testdata_dir, manifest)
    rows.extend(_external_rows("tranco_1m", args.external_dir, manifest))
    rows.extend(_external_rows("ct_recent", args.external_dir, manifest))
    rows.sort(key=lambda row: (row["corpus"], row["cert"], row["lint"]))
    summary = _summary(rows, DEFAULT_INPUTS)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(args.output_dir / "finding_audit.jsonl", rows)
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output_dir / "summary.md").write_text(_markdown(summary), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[ok] wrote {args.output_dir}")


if __name__ == "__main__":
    main()
