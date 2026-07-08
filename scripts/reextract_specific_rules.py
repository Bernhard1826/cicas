#!/usr/bin/env python3
"""
精准重抽指定 rule_id 的 IR。

用法:
    python scripts/reextract_specific_rules.py --rule-ids 29902,29912,29914

原理:
    复用后端 FullPipelineExtractor._layer2_llm_extraction 完整管线，
    但只针对指定 rule_id。id-preserving 写回。
"""

import argparse
import hashlib
import json
import os
import sys
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "cicas_backend"))
os.environ.setdefault("DATABASE_URL", "postgresql://postgres:123456@localhost:15432/cicas")

from app.core.database import SessionLocal
from app.services.full_pipeline_extractor import FullPipelineExtractor
from app.services.extraction.rule_discovery import RuleSkeleton


PROBLEM_RULE_IDS = [
    29324, 29325, 29339, 29342, 29343, 29375, 29415, 29493,
    29539, 29735, 31065, 31102, 31349, 31400,
]


def md5_hex(text: str) -> str:
    return hashlib.md5((text or "").encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Re-extract IR for specific rule IDs")
    parser.add_argument("--rule-ids", help="Comma-separated rule IDs")
    parser.add_argument(
        "--problem-rules",
        action="store_true",
        help="Re-extract only rules identified as extraction/codegen problem cases",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be re-extracted")
    parser.add_argument("--commit", action="store_true", help="Actually write to DB")
    args = parser.parse_args()

    if args.problem_rules:
        rule_ids = PROBLEM_RULE_IDS
    elif args.rule_ids:
        rule_ids = [int(x.strip()) for x in args.rule_ids.split(",") if x.strip()]
    else:
        parser.error("provide --rule-ids or --quality-gate-problems")

    print(f"Target rules: {rule_ids}")
    print(f"Dry run: {args.dry_run}")
    print(f"Commit: {args.commit}")

    db = SessionLocal()
    try:
        # Load rules
        from app.models.models import Rule, Standard

        try:
            rules = db.query(Rule).filter(Rule.id.in_(rule_ids)).all()
        except Exception as e:
            if args.dry_run:
                print(f"[DRY-RUN] DB unavailable; target ID selection only: {e}")
                return
            raise
        print(f"Found {len(rules)} rules in DB")

        # Group by standard
        by_std = {}
        for r in rules:
            std_id = r.standard_id
            if std_id not in by_std:
                by_std[std_id] = []
            by_std[std_id].append(r)

        print(f"Rules by standard: {list(by_std.keys())}")

        for std_id, std_rules in by_std.items():
            std = db.query(Standard).filter(Standard.id == std_id).first()
            if not std:
                print(f"⚠️  Standard {std_id} not found, skipping")
                continue

            # Resolve absolute path (DB stores relative paths)
            backend_dir = Path(__file__).parent.parent / "cicas_backend"
            doc_path = backend_dir / std.file_path if not Path(std.file_path).is_absolute() else Path(std.file_path)
            with open(doc_path, "r", encoding="utf-8", errors="ignore") as f:
                document_text = f.read()

            context = {
                "source": std.source,
                "title": std.title,
                "version": std.version,
                "file_path": std.file_path,
                "standard_id": std_id,
            }

            # Build skeletons
            skeletons = []
            for r in std_rules:
                kw = (r.obligation or r.rule_type or "MUST").upper()
                sent = r.text or ""
                pos = sent.upper().find(kw)
                if pos < 0:
                    pos = 0
                sk = RuleSkeleton(
                    rule_id=f"rerun-{r.id}",
                    section=r.section or "",
                    sentence=sent,
                    keyword=kw,
                    keyword_position=pos,
                    sentence_index=r.sentence_index or 0,
                    source_sentence=sent,
                    section_title=r.title or None,
                )
                skeletons.append(sk)

            print(f"\n📋 Standard {std_id} ({std.source}): {len(skeletons)} skeletons")
            for sk in skeletons:
                print(f"  - {sk.rule_id}: {sk.sentence[:80]}...")

            if args.dry_run:
                print("  [DRY-RUN] Skipping LLM extraction")
                continue

            # Run extraction
            async def run_extraction():
                extractor = FullPipelineExtractor(db=db)
                return await extractor._layer2_llm_extraction(skeletons, document_text, context)

            print(f"\n🚀 Running Layer-2 extraction for Standard {std_id}...")
            result = asyncio.run(run_extraction())

            # Map by hash
            ir_by_hash = {}
            for ir in result.get("resolved_irs", []):
                try:
                    h = md5_hex(ir.rule_text)
                    ir_by_hash[h] = ir
                except Exception as e:
                    print(f"  ⚠️  Skip IR due to hash error: {e}")

            # Apply back
            recovered = 0
            for r in std_rules:
                h = md5_hex(r.text or "")
                ir = ir_by_hash.get(h)
                if ir:
                    r.ir_data = ir.to_json()
                    r.lint_coverage = None
                    r.lint_covered = None
                    r.lint_name = None
                    recovered += 1
                    print(f"  OK R{r.id}: recovered IR and cleared coverage cache")
                else:
                    print(f"  FAIL R{r.id}: no IR recovered (hash not matched)")

            print(f"\n📊 Standard {std_id}: recovered {recovered}/{len(std_rules)}")

        if args.commit:
            print("\n💾 Committing to DB...")
            db.commit()
            print("Done!")
        else:
            print("\n[NO COMMIT] Re-run with --commit to write to DB")

    finally:
        db.close()


if __name__ == "__main__":
    main()
