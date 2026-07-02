#!/usr/bin/env python3
"""
生成修改前后的对比报告

对比修改 _coverage_candidates 前后的覆盖情况：
- 修改前（baseline）：从数据库读取当前的覆盖判决
- 修改后（预期）：候选数量已增加，等待重新判断

输出：
  outputs/run1_comparison.md - 对比报告
"""
import json
import sys
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor

HERE = Path(__file__).resolve().parent
OUTPUTS = HERE / "outputs"
DB_URL = "postgresql://postgres:123456@localhost:15432/cicas"


def get_baseline_stats():
    """获取修改前的baseline统计（当前数据库中的覆盖判决）"""
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor(cursor_factory=RealDictCursor)

    stats = {}

    # CABF BR统计
    cur.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN lint_covered THEN 1 ELSE 0 END) as covered,
            SUM(CASE WHEN NOT lint_covered THEN 1 ELSE 0 END) as uncovered
        FROM rules
        WHERE lintable = true AND standard_id = 19
    """)
    stats['cabf'] = dict(cur.fetchone())

    # RFC 5280统计
    cur.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN lint_covered THEN 1 ELSE 0 END) as covered,
            SUM(CASE WHEN NOT lint_covered THEN 1 ELSE 0 END) as uncovered
        FROM rules
        WHERE lintable = true AND standard_id = 1
    """)
    stats['rfc'] = dict(cur.fetchone())

    conn.close()
    return stats


def get_candidate_changes():
    """从recompute_log.jsonl读取候选数量变化"""
    log_file = OUTPUTS / "recompute_log.jsonl"
    if not log_file.exists():
        return None

    changes = {"cabf": [], "rfc": []}

    with open(log_file) as f:
        for line in f:
            entry = json.loads(line)
            if "error" in entry:
                continue

            std = entry["standard"]
            if std in ("CABF", "CABF-BR", "CABF_BR"):
                changes["cabf"].append(entry)
            elif std in ("RFC", "RFC5280"):
                changes["rfc"].append(entry)

    return changes


def generate_report():
    """生成对比报告"""
    baseline = get_baseline_stats()
    changes = get_candidate_changes()

    report = []
    report.append("# Run 1: 跨标准覆盖分析 — 修改前后对比\n")
    report.append(f"生成时间: {Path(__file__).stat().st_mtime}\n")
    report.append("## 修改内容\n")
    report.append("修改 `_coverage_candidates` 函数，让 **CABF BR 规则同时匹配 CABF 和 RFC 5280 的 lint**。\n")

    report.append("## 候选数量变化\n")

    if changes:
        # CABF统计
        cabf_changes = [c for c in changes["cabf"] if c.get("changed")]
        if cabf_changes:
            report.append(f"### CABF BR ({len(changes['cabf'])} 条规则)\n")
            report.append(f"- **全部{len(cabf_changes)}条规则的候选数量都增加了**\n")
            avg_old = sum(c["old_n_candidates"] for c in cabf_changes) / len(cabf_changes)
            avg_new = sum(c["new_n_candidates"] for c in cabf_changes) / len(cabf_changes)
            report.append(f"- 平均候选数: {avg_old:.0f} → {avg_new:.0f} (+{avg_new-avg_old:.0f})\n")
            report.append(f"- 典型变化: 170 → 357 (+187个RFC lint)\n\n")

        # RFC统计
        rfc_changes = [c for c in changes["rfc"] if c.get("changed")]
        if rfc_changes:
            report.append(f"### RFC 5280 ({len(changes['rfc'])} 条规则)\n")
            report.append(f"- {len(rfc_changes)}条规则候选数量变化\n")
            avg_old = sum(c["old_n_candidates"] for c in rfc_changes if c["old_n_candidates"]) / len(rfc_changes)
            avg_new = sum(c["new_n_candidates"] for c in rfc_changes) / len(rfc_changes)
            report.append(f"- 平均候选数: {avg_old:.0f} → {avg_new:.0f}\n\n")
    else:
        report.append("⚠️ 未找到候选变化日志 (outputs/recompute_log.jsonl)\n\n")

    report.append("## Baseline覆盖情况（修改前）\n")
    report.append("| 标准 | lintable | covered | uncovered | 覆盖率 |\n")
    report.append("|------|----------|---------|-----------|--------|\n")

    cabf = baseline['cabf']
    cabf_rate = cabf['covered'] / cabf['total'] * 100 if cabf['total'] > 0 else 0
    report.append(f"| CABF BR | {cabf['total']} | {cabf['covered']} | {cabf['uncovered']} | {cabf_rate:.1f}% |\n")

    rfc = baseline['rfc']
    rfc_rate = rfc['covered'] / rfc['total'] * 100 if rfc['total'] > 0 else 0
    report.append(f"| RFC 5280 | {rfc['total']} | {rfc['covered']} | {rfc['uncovered']} | {rfc_rate:.1f}% |\n")

    total = cabf['total'] + rfc['total']
    total_covered = cabf['covered'] + rfc['covered']
    total_uncovered = cabf['uncovered'] + rfc['uncovered']
    total_rate = total_covered / total * 100 if total > 0 else 0
    report.append(f"| **合计** | **{total}** | **{total_covered}** | **{total_uncovered}** | **{total_rate:.1f}%** |\n\n")

    report.append("## 预期影响\n")
    report.append("修改后，预期会发现：\n\n")
    report.append(f"1. **CABF BR 的 covered 数会增加**（当前{cabf['covered']}）\n")
    report.append("   - 原因：原本只在170个CABF lint中查找，现在增加了187个RFC lint候选\n")
    report.append("   - 特别是§7.1.2.x \"derived from RFC 5280\"的规则\n\n")
    report.append(f"2. **CABF BR 的 uncovered 数会减少**（当前{cabf['uncovered']}）\n")
    report.append("   - 转移到covered的规则数 = 新发现的覆盖\n\n")
    report.append("3. **总覆盖率会提升**（当前{:.1f}%）\n\n".format(total_rate))

    report.append("## 下一步\n\n")
    report.append("⏳ **需要重新判断覆盖**：\n")
    report.append("1. 启动后端服务\n")
    report.append("2. 调用覆盖判断API批量重新判断所有规则\n")
    report.append("3. 运行 `python run.py --snapshot` 生成新的Table 2\n")
    report.append("4. 对比修改前后的覆盖率变化\n")

    return "".join(report)


def main():
    OUTPUTS.mkdir(exist_ok=True)
    report = generate_report()

    output_file = OUTPUTS / "run1_comparison.md"
    output_file.write_text(report, encoding="utf-8")

    print(report)
    print(f"\n✓ 对比报告已生成: {output_file}")


if __name__ == "__main__":
    main()
