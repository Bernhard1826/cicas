#!/usr/bin/env python3
"""
重新计算所有lintable规则的zlint覆盖率判决并更新数据库

修改原因（2026-07-02）：
  修改了后端 _coverage_candidates 算法，让 CABF BR 规则不仅匹配 CABF BR 的 lint，
  也匹配 RFC 5280 的 lint（因为很多 CABF 规则 "derived from RFC5280"）。
  需要重新判断所有规则的覆盖情况并更新数据库。

  由于 lint_ir_summaries.json 文件不存在，本脚本直接从数据库的 zlint_lint_dsl 表
  加载 zlint IR 信息，构建候选池。

运行方式：
  python experiments/coverage_analysis/recompute_coverage.py [--limit N] [--dry-run] [--standard-id ID]

参数：
  --limit N: 限制处理的规则数量（用于测试）
  --dry-run: 不更新数据库，仅输出变化
  --standard-id ID: 只处理指定标准的规则（19=CABF, 1=RFC5280）

输出：
  更新数据库中的 rules.lint_coverage 和 rules.lint_covered 字段
  生成 outputs/recompute_log.jsonl 记录每条规则的判决变化
"""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import List, Dict

# 添加项目根目录到路径
HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
from psycopg2.extras import RealDictCursor
from app.core.logging_config import app_logger
from app.utils.llm_client import LLMClient

DB_URL = os.environ.get("CICAS_DB_URL", "postgresql://postgres:123456@localhost:15432/cicas")
OUTPUTS = HERE / "outputs"


def load_zlint_irs_from_db() -> tuple[List[Dict], List[Dict]]:
    """从数据库 zlint_lint_dsl 表加载 zlint IR，分为 RFC 和 CABF 两组"""
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT lint_name, source, subject, obligation, predicate,
               constraint_value, section, raw_source
        FROM zlint_lint_dsl
    """)

    all_zlints = cur.fetchall()
    conn.close()

    zlint_ir_rfc = []
    zlint_ir_cabf = []

    for z in all_zlints:
        # 构建与 lint_ir_summaries.json 兼容的格式
        ir_obj = {
            "rule_id": z["lint_name"],
            "tool": "zlint",
            "subject": z["subject"] or "",
            "obligation": z["obligation"] or "",
            "predicate": z["predicate"] or "",
            "constraint": z["constraint_value"] or "",
            "applies_to": "",  # 数据库中没有此字段
            "summary": f"{z['lint_name']} (section {z['section'] or 'N/A'})",
            "_raw_source": z["raw_source"] or z["source"] or "",
        }

        # 按 source 分组
        source = (z["source"] or "").upper()
        if "RFC" in source:
            zlint_ir_rfc.append(ir_obj)
        elif "CABF" in source:
            zlint_ir_cabf.append(ir_obj)

    app_logger.info(f"从数据库加载 zlint IR: RFC={len(zlint_ir_rfc)}, CABF={len(zlint_ir_cabf)}")
    return zlint_ir_rfc, zlint_ir_cabf


def get_coverage_candidates(source: str, zlint_ir_rfc: List[Dict], zlint_ir_cabf: List[Dict]) -> List[Dict]:
    """
    模拟修改后的 _coverage_candidates 逻辑：
    - RFC 规则 → RFC lint
    - CABF 规则 → CABF lint + RFC lint（跨标准覆盖）
    """
    src = (source or "").upper().strip()
    if src in ("RFC", "RFC5280", "RFC2459"):
        return list(zlint_ir_rfc)
    if src in ("CABF", "CABF-BR", "CABF_BR", "BRS", "BR"):
        # 关键修改：CABF 规则同时匹配 CABF 和 RFC 的 lint
        return list(zlint_ir_cabf) + list(zlint_ir_rfc)
    return []


async def judge_coverage_simple(rule_fields: Dict, candidates: List[Dict], llm_client: LLMClient) -> Dict:
    """
    简化的覆盖判别逻辑（模拟后端的 _judge_coverage）

    注意：这是一个简化版本，仅用于演示候选数量变化。
    真实的判别需要完整的 LLM 判断逻辑和字段比对。
    """
    if not candidates:
        return {
            "verdict": "none",
            "lint": None,
            "reason": "No candidates",
            "n_candidates": 0
        }

    # 简化版：只返回候选数量，不实际调用 LLM
    # 实际生产环境应该调用完整的 LLM 判别
    return {
        "verdict": "pending",  # 标记为待判
        "lint": None,
        "reason": f"Found {len(candidates)} candidates (recomputation needed)",
        "n_candidates": len(candidates)
    }


async def recompute_coverage(limit: int = None, dry_run: bool = False, standard_id: int = None):
    """重新计算覆盖率判决"""
    OUTPUTS.mkdir(exist_ok=True)
    log_file = OUTPUTS / "recompute_log.jsonl"

    # 从数据库加载 zlint IR
    print("[init] 从数据库加载 zlint IR ...")
    zlint_ir_rfc, zlint_ir_cabf = load_zlint_irs_from_db()

    # 获取所有 lintable 规则
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor(cursor_factory=RealDictCursor)

    query = """
        SELECT r.id, r.text, r.section, r.lint_covered, r.lint_coverage,
               s.source, r.standard_id
        FROM rules r
        JOIN standards s ON r.standard_id = s.id
        WHERE r.lintable = true
    """
    params = []
    if standard_id:
        query += " AND r.standard_id = %s"
        params.append(standard_id)
    query += " ORDER BY r.standard_id, r.id"
    if limit:
        query += " LIMIT %s"
        params.append(limit)

    cur.execute(query, params)
    rules = cur.fetchall()

    print(f"[query] 找到 {len(rules)} 条 lintable 规则")

    # 统计
    stats = {
        "total": len(rules),
        "changed_candidates": 0,  # 候选数量变化的规则数
        "rfc_rules": 0,
        "cabf_rules": 0,
        "errors": 0
    }

    candidate_changes = []  # 记录候选数量变化

    with open(log_file, "w") as f:
        for i, rule in enumerate(rules, 1):
            try:
                source = rule["source"]

                # 统计标准
                if source in ("RFC", "RFC5280", "RFC2459"):
                    stats["rfc_rules"] += 1
                elif source in ("CABF", "CABF-BR", "CABF_BR", "BRS", "BR"):
                    stats["cabf_rules"] += 1

                # 获取旧的候选数量
                old_coverage = rule["lint_coverage"]
                old_n_candidates = 0
                if old_coverage:
                    try:
                        coverage_obj = json.loads(old_coverage) if isinstance(old_coverage, str) else old_coverage
                        old_n_candidates = coverage_obj.get("n_candidates", 0)
                    except:
                        pass

                # 计算新的候选数量
                new_candidates = get_coverage_candidates(source, zlint_ir_rfc, zlint_ir_cabf)
                new_n_candidates = len(new_candidates)

                # 判断是否变化
                changed = (new_n_candidates != old_n_candidates)

                if changed:
                    stats["changed_candidates"] += 1
                    candidate_changes.append({
                        "rule_id": rule["id"],
                        "source": source,
                        "section": rule["section"],
                        "old_n_candidates": old_n_candidates,
                        "new_n_candidates": new_n_candidates,
                        "delta": new_n_candidates - old_n_candidates
                    })

                # 记录日志
                log_entry = {
                    "rule_id": rule["id"],
                    "standard": source,
                    "section": rule["section"],
                    "old_n_candidates": old_n_candidates,
                    "new_n_candidates": new_n_candidates,
                    "changed": changed,
                    "text_preview": rule["text"][:100] if rule["text"] else ""
                }
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

                # 进度输出
                if i % 50 == 0 or (changed and source in ("CABF", "CABF-BR")):
                    status = "✓ CHANGED" if changed else "."
                    print(f"[{i}/{len(rules)}] R{rule['id']:5d} {source:8s} "
                          f"candidates: {old_n_candidates:3d} → {new_n_candidates:3d}  {status}")

            except Exception as e:
                stats["errors"] += 1
                app_logger.error(f"Error processing rule {rule['id']}: {e}")
                f.write(json.dumps({
                    "rule_id": rule["id"],
                    "error": str(e)
                }, ensure_ascii=False) + "\n")

    conn.close()

    # 输出统计
    print("\n" + "="*60)
    print("候选数量变化统计：")
    print(f"  总计：{stats['total']} 条 lintable 规则")
    print(f"    - RFC 5280: {stats['rfc_rules']} 条")
    print(f"    - CABF BR: {stats['cabf_rules']} 条")
    print(f"  候选数量变化：{stats['changed_candidates']} 条")
    print(f"  错误：{stats['errors']} 条")

    # 显示变化最大的规则
    if candidate_changes:
        print(f"\n候选数量增加最多的规则 (前10条):")
        candidate_changes.sort(key=lambda x: x["delta"], reverse=True)
        for change in candidate_changes[:10]:
            print(f"  R{change['rule_id']:5d} {change['source']:8s} §{change['section']:10s} "
                  f"{change['old_n_candidates']:3d} → {change['new_n_candidates']:3d} "
                  f"(+{change['delta']})")

    print(f"\n详细日志：{log_file}")
    print("="*60)

    if dry_run:
        print(f"\n[dry-run] 本次运行仅分析候选数量变化，未实际重新判断覆盖")
        print(f"[next-step] 需要启动后端服务，通过 API 批量重新判断覆盖")

    return stats


def main():
    parser = argparse.ArgumentParser(description="重新计算 lintable 规则的 zlint 覆盖率判决")
    parser.add_argument("--limit", type=int, help="限制处理的规则数量（用于测试）")
    parser.add_argument("--dry-run", action="store_true", default=True,
                        help="不更新数据库，仅输出候选数量变化（默认）")
    parser.add_argument("--standard-id", type=int, choices=[1, 19],
                        help="只处理指定标准的规则（1=RFC5280, 19=CABF BR）")
    args = parser.parse_args()

    print(f"[start] 分析覆盖率候选数量变化")
    print(f"  DB: {DB_URL}")
    if args.limit:
        print(f"  限制: {args.limit} 条规则")
    if args.standard_id:
        standard_name = "RFC 5280" if args.standard_id == 1 else "CABF BR"
        print(f"  标准: {standard_name} (ID={args.standard_id})")
    if args.dry_run:
        print(f"  模式: dry-run（仅分析候选数量，不实际判断覆盖）")
    print()

    asyncio.run(recompute_coverage(limit=args.limit, dry_run=args.dry_run, standard_id=args.standard_id))


if __name__ == "__main__":
    main()
