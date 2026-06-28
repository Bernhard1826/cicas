"""
添加 extraction_confidence 字段到 rules 表

用途：分离字段提取原始置信度和综合置信度
- extraction_confidence: 字段提取时的原始置信度（仅基于字段识别质量）
- confidence_score: 综合置信度（包含RAG证据、文档验证等因素）

这样质疑系统可以使用原始提取置信度，不受后续评估影响
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

        print(" 开始迁移：添加 extraction_confidence 字段...")

        # 1. 添加字段
        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN IF NOT EXISTS extraction_confidence FLOAT;
        """)

        print("[OK] 已添加 extraction_confidence 字段")

        # 2. 为现有数据填充默认值
        # 对于已有的规则，将 confidence_score 复制到 extraction_confidence
        # （虽然不完全准确，但比 NULL 好）
        cursor.execute("""
            UPDATE rules
            SET extraction_confidence = confidence_score
            WHERE extraction_confidence IS NULL
              AND confidence_score IS NOT NULL;
        """)

        rows_updated = cursor.rowcount
        print(f"[OK] 已更新 {rows_updated} 条现有规则的 extraction_confidence")

        # 3. 添加注释
        cursor.execute("""
            COMMENT ON COLUMN rules.extraction_confidence IS
            '字段提取原始置信度 (0-1): 仅基于字段提取质量，不受RAG证据和文档验证影响';
        """)

        cursor.execute("""
            COMMENT ON COLUMN rules.confidence_score IS
            '综合置信度 (0-1): 基于证据强度、文档验证和提取方法的综合评估';
        """)

        print("[OK] 已添加字段注释")

        # 提交事务
        conn.commit()

        print("\n🎉 迁移完成！")
        print(f"   - 新增字段: extraction_confidence")
        print(f"   - 更新记录: {rows_updated} 条")

        cursor.close()
        conn.close()

        return True

    except Exception as e:
        print(f"[ERROR] 迁移失败: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False

def rollback_migration():
    """回滚迁移"""

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

        print(" 开始回滚：删除 extraction_confidence 字段...")

        cursor.execute("""
            ALTER TABLE rules
            DROP COLUMN IF EXISTS extraction_confidence;
        """)

        conn.commit()
        print("[OK] 回滚完成！")

        cursor.close()
        conn.close()

        return True

    except Exception as e:
        print(f"[ERROR] 回滚失败: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == 'rollback':
        rollback_migration()
    else:
        run_migration()
