"""
删除 extraction_method 字段

原因：
- extraction_method 字段已无意义，所有规则都由LLM提取
- Layer 1 (Regex) 已改为只提取文本块(chunks)，不再提取规则
- 数据库中所有规则的 extraction_method 都标记为 'regex'（默认值），但实际都是LLM提取
- 字段从未在保存时设置，导致数据与实际提取方法不符

修改内容:
- 删除 rules.extraction_method 字段及其索引
- 删除 Rule 模型中的字段定义
- 删除代码中的所有 extraction_method 使用
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
        print("开始迁移：删除 extraction_method 字段")
        print("=" * 80)

        # 1. 检查字段是否存在
        print("\n[1] 检查字段...")
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'rules'
            AND column_name = 'extraction_method';
        """)
        existing_columns = [row[0] for row in cursor.fetchall()]
        print(f"    现有字段: {', '.join(existing_columns) if existing_columns else '(不存在)'}")

        # 2. 检查是否有索引
        print("\n[2] 检查索引...")
        cursor.execute("""
            SELECT indexname
            FROM pg_indexes
            WHERE tablename = 'rules'
            AND indexdef LIKE '%extraction_method%';
        """)
        existing_indexes = [row[0] for row in cursor.fetchall()]
        if existing_indexes:
            print(f"    现有索引: {', '.join(existing_indexes)}")
        else:
            print("    没有相关索引")

        # 3. 统计当前值分布（用于确认删除的合理性）
        if 'extraction_method' in existing_columns:
            print("\n[3] 统计当前值分布...")
            cursor.execute("""
                SELECT extraction_method, COUNT(*) as count
                FROM rules
                GROUP BY extraction_method;
            """)
            distribution = cursor.fetchall()
            print("    当前值分布:")
            for value, count in distribution:
                print(f"      - {value or '(NULL)'}: {count} 条规则")

        # 4. 删除索引（如果存在）
        if existing_indexes:
            print("\n[4] 删除索引...")
            for idx_name in existing_indexes:
                cursor.execute(f"DROP INDEX IF EXISTS {idx_name};")
                print(f"    [OK] 删除索引: {idx_name}")
        else:
            print("\n[4] 没有需要删除的索引，跳过")

        # 5. 删除 extraction_method 字段
        if 'extraction_method' in existing_columns:
            print("\n[5] 删除 extraction_method 字段...")
            cursor.execute("""
                ALTER TABLE rules
                DROP COLUMN IF EXISTS extraction_method;
            """)
            print("    [OK] extraction_method 已删除")
        else:
            print("\n[5] extraction_method 字段不存在，跳过")

        # 提交事务
        conn.commit()

        print("\n" + "=" * 80)
        print("迁移完成！")
        print("=" * 80)
        print("\n变更摘要:")
        print("  ✅ 删除 extraction_method 字段（已无意义）")
        print("  ✅ 删除相关索引")
        print("\n原因:")
        print("  - 所有规则都由LLM提取（Layer 1只做文本分块）")
        print("  - 字段值与实际提取方法不符（都标记为'regex'但实际是LLM）")
        print("  - 代码中已删除所有 extraction_method 使用")
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
        print("开始回滚：恢复 extraction_method 字段")
        print("=" * 80)

        # 1. 恢复 extraction_method 字段
        print("\n[1] 恢复 extraction_method 字段...")
        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN IF NOT EXISTS extraction_method VARCHAR(50) DEFAULT 'regex';
        """)
        print("    [OK] extraction_method 已恢复")

        # 2. 重建索引
        print("\n[2] 重建索引...")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rules_extraction_method
            ON rules (extraction_method);
        """)
        print("    [OK] 索引已重建")

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
