"""
删除 extraction_confidence 和 confidence_score 字段

原因：
- 跨文档处理(引用和冲突检测)不应该依赖质量评分
- extraction_confidence 和 confidence_score 从未被填充(都是NULL)
- 保留 quality_score 用于显示和用户筛选,但不影响系统逻辑

修改内容:
- 删除 rules.extraction_confidence 字段
- 删除 rules.confidence_score 字段
- 保留 rules.quality_score 字段
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
        print("开始迁移：删除 extraction_confidence 和 confidence_score 字段")
        print("=" * 80)

        # 1. 检查字段是否存在
        print("\n[1] 检查字段...")
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'rules'
            AND column_name IN ('extraction_confidence', 'confidence_score', 'quality_score');
        """)
        existing_columns = [row[0] for row in cursor.fetchall()]
        print(f"    现有字段: {', '.join(existing_columns)}")

        # 2. 删除 extraction_confidence 字段
        if 'extraction_confidence' in existing_columns:
            print("\n[2] 删除 extraction_confidence 字段...")
            cursor.execute("""
                ALTER TABLE rules
                DROP COLUMN IF EXISTS extraction_confidence;
            """)
            print("    [OK] extraction_confidence 已删除")
        else:
            print("\n[2] extraction_confidence 字段不存在，跳过")

        # 3. 删除 confidence_score 字段
        if 'confidence_score' in existing_columns:
            print("\n[3] 删除 confidence_score 字段...")
            cursor.execute("""
                ALTER TABLE rules
                DROP COLUMN IF EXISTS confidence_score;
            """)
            print("    [OK] confidence_score 已删除")
        else:
            print("\n[3] confidence_score 字段不存在，跳过")

        # 4. 确认 quality_score 保留
        if 'quality_score' in existing_columns:
            print("\n[4] 确认 quality_score 字段保留...")
            print("    [OK] quality_score 保留（用于显示，不影响系统逻辑）")
        else:
            print("\n[4] WARNING: quality_score 字段不存在！")

        # 提交事务
        conn.commit()

        print("\n" + "=" * 80)
        print("迁移完成！")
        print("=" * 80)
        print("\n变更摘要:")
        print("  ✅ 删除 extraction_confidence (未使用，都是NULL)")
        print("  ✅ 删除 confidence_score (未使用，都是NULL)")
        print("  ✅ 保留 quality_score (用于显示)")
        print("\n系统行为:")
        print("  - 跨文档引用检测: 所有规则都参与")
        print("  - 跨文档冲突检测: 所有规则都参与")
        print("  - quality_score: 仅用于显示，不影响逻辑")
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
        print("开始回滚：恢复 extraction_confidence 和 confidence_score 字段")
        print("=" * 80)

        # 1. 恢复 extraction_confidence 字段
        print("\n[1] 恢复 extraction_confidence 字段...")
        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN IF NOT EXISTS extraction_confidence FLOAT;
        """)
        print("    [OK] extraction_confidence 已恢复")

        # 2. 恢复 confidence_score 字段
        print("\n[2] 恢复 confidence_score 字段...")
        cursor.execute("""
            ALTER TABLE rules
            ADD COLUMN IF NOT EXISTS confidence_score FLOAT;
        """)
        print("    [OK] confidence_score 已恢复")

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
