"""
删除 evidence_ids 字段

原因：
- evidence_ids 字段从未被实际填充（一直是NULL）
- 代码中只做了RAG相似度匹配，没有收集和保存证据ID
- 移除未使用的字段可以简化数据模型

修改内容:
- 删除 rules.evidence_ids 字段
- 保留 document_verified 用于文档验证
- RAG功能通过 zlint_verified, zlint_similarity 等字段实现
"""

import psycopg2
import sys

def run_migration():
    """执行数据库迁移"""

    # 数据库连接配置
    db_config = {
        'host': 'localhost',
        'port': 5432,
        'database': 'pki_standards',
        'user': 'postgres',
        'password': '123456'
    }

    try:
        # 连接数据库
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()

        print("=" * 80)
        print("开始迁移：删除 evidence_ids 字段")
        print("=" * 80)

        # 1. 检查字段是否存在
        print("\n[1] 检查字段...")
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'rules'
            AND column_name = 'evidence_ids';
        """)
        existing_columns = [row[0] for row in cursor.fetchall()]
        print(f"    现有字段: {', '.join(existing_columns) if existing_columns else '无'}")

        # 2. 删除 evidence_ids 字段
        if 'evidence_ids' in existing_columns:
            print("\n[2] 删除 evidence_ids 字段...")
            cursor.execute("""
                ALTER TABLE rules
                DROP COLUMN IF EXISTS evidence_ids;
            """)
            print("    [OK] evidence_ids 已删除")
        else:
            print("\n[2] evidence_ids 字段不存在，跳过")

        # 提交事务
        conn.commit()

        print("\n" + "=" * 80)
        print("迁移完成！")
        print("=" * 80)
        print("\n变更摘要:")
        print("  ✅ 删除 evidence_ids (未使用，一直为NULL)")
        print("\n系统行为:")
        print("  - RAG证据功能: 通过 zlint_verified, zlint_similarity 实现")
        print("  - 文档验证: 通过 document_verified 字段实现")
        print("  - 质量评分: 通过 quality_score 字段实现")
        print("\n" + "=" * 80)

        cursor.close()
        conn.close()

        return True

    except Exception as e:
        print(f"\n[ERROR] 迁移失败: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False

def rollback_migration():
    """回滚迁移（恢复字段）"""

    db_config = {
        'host': 'localhost',
        'port': 5432,
        'database': 'pki_standards',
        'user': 'postgres',
        'password': '123456'
    }

    try:
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()

        print("=" * 80)
        print("开始回滚：恢复 evidence_ids 字段")
        print("=" * 80)

        # 1. 恢复 evidence_ids 字段
        print("\n[1] 恢复 evidence_ids 字段...")
        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN IF NOT EXISTS evidence_ids TEXT;
        """)
        print("    [OK] evidence_ids 已恢复")

        conn.commit()
        print("\n[OK] 回滚完成！")

        cursor.close()
        conn.close()

        return True

    except Exception as e:
        print(f"\n[ERROR] 回滚失败: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == 'rollback':
        rollback_migration()
    else:
        run_migration()
