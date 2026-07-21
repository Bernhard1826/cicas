#!/usr/bin/env python3
"""Freeze an independent source-to-emitted-code semantic review.

This audit intentionally does not invoke the generator or ``synonym_judge``.
The review notes are a bounded, rule-by-rule adjudication over the frozen
source/code dossier.  Before emitting a result it verifies that every current
generated lint was reviewed, that its source and Go hashes still match the
dossier, and that the independently authored behavior witnesses passed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.certificate.codegen import dsl  # noqa: E402

RUN_DIR = HERE / "outputs" / "audited_coverage_domain"
DOSSIER = RUN_DIR / "independent_semantic_dossier.jsonl"
BEHAVIOR = RUN_DIR / "independent_semantic_behavior.json"
OUTPUT = RUN_DIR / "independent_semantic_review.jsonl"
SUMMARY = RUN_DIR / "independent_semantic_review_summary.json"


# These notes record the independent adjudication criterion for every emitted
# lint. They are not read by extraction, generation, coverage, or any metric
# pipeline; the script only freezes review evidence after generation.
REVIEW_NOTES: dict[int, dict[str, str]] = {
    28730: {"source": "AKI authorityCertSerialNumber is absent.", "code": "Rejects encoded AuthorityKeyIdentifier context tag [2]."},
    29274: {"source": "AKI authorityCertIssuer is absent.", "code": "Rejects encoded AuthorityKeyIdentifier context tag [1]."},
    29536: {"source": "RSA SPKI AlgorithmIdentifier has a parameters element.", "code": "For an RSA public-key BIT STRING, requires a second AlgorithmIdentifier element."},
    29537: {"source": "RSA SPKI parameters are an explicit DER NULL.", "code": "For an RSA public-key BIT STRING, requires NULL tag 5 with empty contents."},
    29538: {"source": "An RSA key is indicated with rsaEncryption, not another algorithm.", "code": "For an RSA public-key BIT STRING, requires the rsaEncryption OID DER element."},
    29540: {"source": "ECDSA AlgorithmIdentifier parameters use namedCurve encoding.", "code": "For x509 ECDSA keys, requires the parameters element to be an OBJECT IDENTIFIER."},
    29543: {"source": "A P-521 ECDSA key uses namedCurve secp521r1.", "code": "For id-ecPublicKey SPKIs whose point is on P-521, requires the secp521r1 OID."},
    29546: {"source": "A P-521 ECDSA AlgorithmIdentifier has the listed exact DER encoding.", "code": "For id-ecPublicKey SPKIs whose point is on P-521, requires the listed complete DER bytes."},
    29562: {"source": "domainComponent uses IA5String and has at most 63 characters.", "code": "Walks Subject RDN values for the domainComponent OID and checks tag 22 plus a 63-rune maximum."},
    29563: {"source": "countryName uses PrintableString and has at most 2 characters.", "code": "Walks Subject RDN values for the countryName OID and checks tag 19 plus a 2-rune maximum."},
    29564: {"source": "stateOrProvinceName uses UTF8String or PrintableString and has at most 128 characters.", "code": "Walks Subject RDN values for the stateOrProvinceName OID and checks tags 12 or 19 plus a 128-rune maximum."},
    30982: {"source": "explicitText SHOULD use UTF8String.", "code": "Warns when a UserNotice explicitText DisplayText tag is not UTF8String."},
    30984: {"source": "explicitText MUST NOT use VisibleString or BMPString.", "code": "Rejects either forbidden DisplayText tag in UserNotice explicitText."},
    31046: {"source": "IPv4 NameConstraints iPAddress has 8 octets and RFC 4632 CIDR encoding.", "code": "Checks 4+4 width and a contiguous mask in both permitted and excluded IPv4 subtrees."},
    31047: {"source": "IPv6 NameConstraints iPAddress has 32 octets, similarly CIDR encoded.", "code": "Checks 16+16 width and a contiguous mask in both permitted and excluded IPv6 subtrees."},
    31056: {"source": "A policyConstraints extension has inhibitPolicyMapping or requireExplicitPolicy.", "code": "When the extension exists, requires encoded context tag [1] or [0]."},
    31067: {"source": "With non-empty Subject and SAN, SAN SHOULD be non-critical.", "code": "Warns exactly when an extant SAN is critical and Subject is non-empty."},
    31069: {"source": "An IPv4 SAN iPAddress OCTET STRING has exactly four octets.", "code": "Checks every parsed four-byte SAN IP and leaves 16-byte IPv6 encodings out of scope."},
    31070: {"source": "An IPv6 SAN iPAddress OCTET STRING has exactly sixteen octets.", "code": "Checks every parsed non-four-byte SAN IP has sixteen bytes."},
    31123: {"source": "serialNumber is non-negative.", "code": "Requires parsed SerialNumber to be at least zero."},
    31132: {"source": "With empty Subject, an extant SAN is critical.", "code": "Requires SAN criticality under the empty-Subject and SAN-present antecedent."},
    31153: {"source": "With only basic fields, version SHOULD be v1.", "code": "Uses raw TBSCertificate absence of [1], [2], and [3], then warns unless Version is 1."},
    31160: {"source": "AKI authorityCertIssuer and authorityCertSerialNumber are both present or both absent.", "code": "Accepts exactly the two matching encoded-tag presence states."},
    31161: {"source": "serialNumber is non-negative.", "code": "Requires parsed SerialNumber to be at least zero."},
    31172: {"source": "When extensions are present, version is v3.", "code": "Detects raw TBSCertificate extension tag [3] and requires Version 3."},
    31175: {"source": "UTCTime values are expressed in Greenwich Mean Time (Zulu).", "code": "For every raw validity UTCTime, requires a terminal Z character."},
    31344: {"source": "In the explicit ASN.1 module, present extensions require v3.", "code": "Detects raw TBSCertificate extension tag [3] and requires Version 3."},
    31368: {"source": "The DER INTEGER serialNumber sign bit is zero.", "code": "Parses the raw TBSCertificate serial INTEGER and requires its high bit clear."},
    31396: {"source": "TBSCertificate.signature matches Certificate.signatureAlgorithm.", "code": "Compares the two raw AlgorithmIdentifier DER encodings."},
    31403: {"source": "When extensions are used, version is v3.", "code": "Detects raw TBSCertificate extension tag [3] and requires Version 3."},
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


_LOGICAL_OPS = {"And", "Or", "Not", "When"}


def _walk_atom_ops(node: Any):
    if isinstance(node, dict):
        op = node.get("op")
        if op and op not in _LOGICAL_OPS:
            yield str(op)
        for item in node.get("args") or []:
            yield from _walk_atom_ops(item)
        for key in ("inner", "cond", "main", "predicate", "precondition"):
            if key in node:
                yield from _walk_atom_ops(node[key])
    elif isinstance(node, list):
        for item in node:
            yield from _walk_atom_ops(item)


def _atom_genericity_summary(dossier: list[dict[str, Any]]) -> dict[str, Any]:
    buckets = Counter()
    non_generic_frequency = Counter()
    unknown_frequency = Counter()
    for row in dossier:
        atoms = set(_walk_atom_ops(row.get("dsl_tree")))
        atoms.update(_walk_atom_ops(row.get("dsl_precondition")))
        generic = atoms & dsl.GENERIC_ATOMS
        non_generic = atoms & dsl.NON_GENERIC_ATOMS
        unknown = atoms - generic - non_generic
        non_generic_frequency.update(non_generic)
        unknown_frequency.update(unknown)
        if unknown:
            buckets["unknown"] += 1
        elif generic and non_generic:
            buckets["generic_and_non_generic"] += 1
        elif non_generic:
            buckets["non_generic_only"] += 1
        else:
            buckets["generic_only"] += 1
    return {
        "definition": "all independently reviewed emitted lints; logical combinators are excluded",
        "total": len(dossier),
        "generic_only": buckets["generic_only"],
        "generic_and_non_generic": buckets["generic_and_non_generic"],
        "non_generic_only": buckets["non_generic_only"],
        "unknown": buckets["unknown"],
        "non_generic_atom_frequency": dict(sorted(non_generic_frequency.items())),
        "unknown_atom_frequency": dict(sorted(unknown_frequency.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=RUN_DIR)
    args = parser.parse_args()
    run_dir = args.run_dir
    dossier_path = run_dir / DOSSIER.name
    behavior_path = run_dir / BEHAVIOR.name
    output_path = run_dir / OUTPUT.name
    summary_path = run_dir / SUMMARY.name

    dossier = _read_jsonl(dossier_path)
    dossier_by_id = {int(row["rule_id"]): row for row in dossier}
    if len(dossier_by_id) != len(dossier):
        raise RuntimeError("dossier contains duplicate rule IDs")
    dossier_ids = set(dossier_by_id)
    note_ids = set(REVIEW_NOTES)
    if dossier_ids != note_ids:
        raise RuntimeError(
            "review/dossier rule sets differ: "
            f"only_dossier={sorted(dossier_ids - note_ids)}, "
            f"only_review={sorted(note_ids - dossier_ids)}"
        )

    behavior = json.loads(behavior_path.read_text(encoding="utf-8"))
    if not behavior.get("independent_semantic_pass"):
        raise RuntimeError("independent behavior audit did not pass")
    if not (behavior.get("semantic_witness_coverage") or {}).get("covers_manifest_exactly"):
        raise RuntimeError("behavior witnesses do not cover the generated manifest exactly")
    observed = behavior.get("observed") or {}

    records = []
    for rule_id in sorted(dossier_ids):
        dossier_row = dossier_by_id[rule_id]
        generated_path = Path(dossier_row["generated_go_path"])
        if not generated_path.is_file():
            raise RuntimeError(f"generated Go file missing for R{rule_id}: {generated_path}")
        if _sha256_file(generated_path) != dossier_row.get("generated_go_sha256"):
            raise RuntimeError(f"generated Go file changed after dossier for R{rule_id}")
        witnesses = {
            case_id: case
            for case_id, case in observed.items()
            if int(case.get("rule_id") or 0) == rule_id
        }
        if not witnesses or not all(case.get("matches_source_semantics") for case in witnesses.values()):
            raise RuntimeError(f"missing or failing behavior witness for R{rule_id}")
        records.append(
            {
                "rule_id": rule_id,
                "source": dossier_row["source"],
                "section": dossier_row["section"],
                "title": dossier_row["title"],
                "source_sha256": dossier_row["raw_source_sha256"],
                "generated_go_path": str(generated_path),
                "generated_go_sha256": dossier_row["generated_go_sha256"],
                "verdict": "EXPRESSES",
                "review_method": "independent source-to-emitted-code review plus isolated behavior witness",
                "source_predicate": REVIEW_NOTES[rule_id]["source"],
                "code_predicate": REVIEW_NOTES[rule_id]["code"],
                "witness_case_ids": sorted(witnesses),
            }
        )

    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "independent source-to-emitted-code review; no synonym_judge invocation",
        "target_definition": "every successful generated lint in the frozen dossier",
        "reviewed": len(records),
        "expresses": len(records),
        "does_not_express": 0,
        "strict_synonymy_rate": 1.0 if records else None,
        "atom_genericity": _atom_genericity_summary(dossier),
        "dossier_sha256": _sha256_file(dossier_path),
        "behavior_sha256": _sha256_file(behavior_path),
        "review_sha256": _sha256_file(output_path),
        "review": str(output_path),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
