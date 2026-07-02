"""
针对缺失 constraint_value 的规则进行定向重抽。

优先级：
1. enum 类型 (26条) - allowed_values 缺失 permitted values
2. numeric 类型 (8条) - in_range 缺失 min/max
3. cardinality 类型 (26条) - must_include/must_not_include 缺失 count

用法：
    python scripts/reextract_missing_constraint_values.py --dry-run
    python scripts/reextract_missing_constraint_values.py --limit 50
    python scripts/reextract_missing_constraint_values.py --commit --batch-size 40
"""
import argparse
import json
import hashlib
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import psycopg2
from psycopg2.extras import RealDictCursor
from collections import Counter


def get_db_connection():
    return psycopg2.connect('postgresql://postgres:123456@localhost:15432/cicas')


def load_rules_with_missing_constraint(db):
    """加载缺失 constraint_value 的 lintable 规则"""
    cur = db.cursor()

    # 高优先级：enum, numeric, cardinality 类型
    high_priority = []
    medium_priority = []
    low_priority = []

    cur.execute('''
        SELECT id, predicate, subject, spec_family, ir_data, rule_type, text
        FROM rules
        WHERE lintable = true
        AND ir_data::text LIKE '%\"ir\":%'
        AND (constraint_value IS NULL OR constraint_value = '' OR constraint_value = 'null')
        ORDER BY
            CASE
                WHEN ir_data::text LIKE '%\"type\":\"enum\"%' THEN 1
                WHEN ir_data::text LIKE '%\"type\":\"numeric\"%' THEN 2
                WHEN ir_data::text LIKE '%\"type\":\"cardinality\"%' THEN 3
                WHEN ir_data::text LIKE '%\"type\":\"length\"%' THEN 4
                ELSE 5
            END,
            id
    ''')

    for row in cur.fetchall():
        rule_id, predicate, subject, spec_family, ir_data_str, rule_type, text = row
        ir_data = json.loads(ir_data_str) if isinstance(ir_data_str, str) else ir_data_str
        ir = ir_data.get('ir', {})
        constraint = ir.get('constraint', {})
        constraint_type = constraint.get('type', 'unknown')
        desc = ir.get('description', '') or ''

        rule_info = {
            'id': rule_id,
            'predicate': predicate,
            'subject': subject,
            'spec_family': spec_family,
            'constraint_type': constraint_type,
            'description': desc,
            'text': text,
            'rule_type': rule_type,
            'ir_data': ir_data
        }

        if constraint_type in ('enum', 'numeric'):
            high_priority.append(rule_info)
        elif constraint_type in ('cardinality', 'length'):
            medium_priority.append(rule_info)
        else:
            low_priority.append(rule_info)

    cur.close()
    return high_priority, medium_priority, low_priority


def analyze_missing_values(rules):
    """分析缺失的具体内容"""
    for r in rules:
        constraint = r['ir_data'].get('ir', {}).get('constraint', {})
        r['missing_fields'] = []

        if constraint.get('type') in ('enum', 'numeric'):
            if constraint.get('value') is None:
                r['missing_fields'].append('value')
            if constraint.get('allowed_values') is None:
                r['missing_fields'].append('allowed_values')
            if constraint.get('min_value') is None and constraint.get('max_value') is None:
                r['missing_fields'].append('min/max_value')

        if constraint.get('type') == 'cardinality':
            if constraint.get('value') is None:
                r['missing_fields'].append('count_value')

    return rules


def print_summary(high, medium, low):
    print("=" * 60)
    print("缺失 constraint_value 规则分析")
    print("=" * 60)
    print(f"高优先级 (enum/numeric): {len(high)} 条")
    print(f"中优先级 (cardinality/length): {len(medium)} 条")
    print(f"低优先级 (presence/other): {len(low)} 条")
    print()

    # 按 spec_family 分组
    for name, rules in [("高优先级", high), ("中优先级", medium)]:
        if rules:
            spec_counts = Counter(r['spec_family'] for r in rules)
            pred_counts = Counter(r['predicate'] for r in rules)
            print(f"{name} - 按标准: {dict(spec_counts)}")
            print(f"{name} - 按谓词: {dict(pred_counts)}")
            print()


def reextract_rules_batch(rules, db_config, dry_run=True, batch_size=40):
    """
    对指定规则重新调用后端抽取逻辑。

    复用 FullPipelineExtractor._layer2_llm_extraction，
    id-preserving 写回。
    """
    if dry_run:
        print(f"\n[DRY-RUN] 将重抽 {len(rules)} 条规则")
        for r in rules[:10]:
            print(f"  Rule {r['id']}: {r['predicate']} - {r['subject']}")
            print(f"    constraint_type: {r['constraint_type']}")
            print(f"    missing: {r.get('missing_fields', [])}")
            print(f"    desc: {r['description'][:80]}...")
        if len(rules) > 10:
            print(f"  ... 还有 {len(rules) - 10} 条")
        return 0, len(rules)

    import asyncio
    from app.services.full_pipeline_extractor import FullPipelineExtractor
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        # 获取标准信息
        standards = set(r['spec_family'] for r in rules)
        standard_map = {}
        for cur in [db.cursor()]:
            cur.execute('SELECT id, source FROM standards')
            for row in cur:
                standard_map[row[1]] = row[0]
            cur.close()

        total_recovered = 0
        total_failed = 0

        # 按标准分组
        by_standard = {}
        for r in rules:
            spec = r['spec_family']
            if spec not in by_standard:
                by_standard[spec] = []
            by_standard[spec].append(r)

        for spec, spec_rules in by_standard.items():
            standard_id = standard_map.get(spec)
            if not standard_id:
                print(f"[WARN] Unknown standard: {spec}")
                continue

            standard = db.query(Standard).filter(Standard.id == standard_id).first()
            if not standard:
                continue

            with open(standard.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                document_text = f.read()

            context = {
                'source': standard.source,
                'title': standard.title,
                'version': standard.version,
                'file_path': standard.file_path,
                'standard_id': standard_id
            }

            # 分批处理
            for i in range(0, len(spec_rules), batch_size):
                chunk = spec_rules[i:i+batch_size]

                # 构建 skeletons
                from app.services.extraction.rule_discovery import RuleSkeleton
                skeletons = []
                for r in chunk:
                    kw = r.get('rule_type') or 'MUST'
                    sent = r.get('text') or ''
                    pos = sent.upper().find(kw.upper())
                    skeletons.append(RuleSkeleton(
                        rule_id=f"reextract-{r['id']}",
                        section='',
                        sentence=sent,
                        keyword=kw,
                        keyword_position=pos if pos >= 0 else 0,
                        sentence_index=0,
                        source_sentence=sent,
                        section_title=None,
                    ))

                # 调用 Layer-2
                extractor = FullPipelineExtractor(db=db)
                layer2 = asyncio.run(extractor._layer2_llm_extraction(skeletons, document_text, context))

                # 按 hash 映射
                ir_by_hash = {}
                for ir in layer2.get('resolved_irs', []):
                    try:
                        h = hashlib.md5(ir.rule_text.encode('utf-8')).hexdigest()
                        ir_by_hash[h] = ir
                    except Exception:
                        continue

                # 更新
                chunk_recovered = 0
                for r in chunk:
                    h = hashlib.md5((r.get('text') or '').encode('utf-8')).hexdigest()
                    new_ir = ir_by_hash.get(h)
                    if new_ir:
                        r['ir_data']['ir'] = json.loads(new_ir.to_json())['ir']
                        db.execute(
                            text("UPDATE rules SET ir_data = :ir_data WHERE id = :id"),
                            {'ir_data': json.dumps(r['ir_data']), 'id': r['id']}
                        )
                        chunk_recovered += 1

                db.commit()
                total_recovered += chunk_recovered
                total_failed += len(chunk) - chunk_recovered

                print(f"[{spec}] Chunk {i//batch_size + 1}: {chunk_recovered}/{len(chunk)} recovered")

        return total_recovered, total_failed

    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description='重抽缺失 constraint_value 的规则')
    parser.add_argument('--dry-run', action='store_true', default=True,
                        help='仅打印分析，不执行重抽')
    parser.add_argument('--commit', action='store_true',
                        help='实际执行重抽（默认 dry-run）')
    parser.add_argument('--limit', type=int, default=None,
                        help='最多处理多少条规则')
    parser.add_argument('--batch-size', type=int, default=40,
                        help='每批处理的规则数')
    parser.add_argument('--priority', choices=['high', 'medium', 'all'], default='all',
                        help='处理优先级')
    args = parser.parse_args()

    if args.commit:
        args.dry_run = False

    db = get_db_connection()
    try:
        high, medium, low = load_rules_with_missing_constraint(db)
        high = analyze_missing_values(high)
        medium = analyze_missing_values(medium)
        low = analyze_missing_values(low)

        print_summary(high, medium, low)

        # 选择要处理的规则
        if args.priority == 'high':
            rules_to_process = high
        elif args.priority == 'medium':
            rules_to_process = high + medium
        else:
            rules_to_process = high + medium + low

        if args.limit:
            rules_to_process = rules_to_process[:args.limit]

        print(f"\n将处理 {len(rules_to_process)} 条规则")

        recovered, failed = reextract_rules_batch(
            rules_to_process,
            'postgresql://postgres:123456@localhost:15432/cicas',
            dry_run=args.dry_run,
            batch_size=args.batch_size
        )

        if not args.dry_run:
            print(f"\n完成: 成功 {recovered}, 失败 {failed}")
        else:
            print(f"\n[DRY-RUN] 如执行将处理 {len(rules_to_process)} 条规则")

    finally:
        db.close()


if __name__ == '__main__':
    main()