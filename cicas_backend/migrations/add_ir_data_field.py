"""
添加ir_data字段到rules表

Migration: 添加ir_data字段用于存储完整的IR对象（包含v2.0算法的新字段）
Date: 2025-12-16
"""
import psycopg2
import os

# 数据库配置
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/pki_rules')

def run_migration():
    """执行迁移"""
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()

    try:
        print("开始迁移：添加ir_data字段...")

        # 检查字段是否已存在
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name='rules' AND column_name='ir_data'
        """)

        if cursor.fetchone():
            print("字段ir_data已存在，跳过")
        else:
            # 添加字段
            cursor.execute("""
                ALTER TABLE rules
                ADD COLUMN ir_data TEXT NULL
            """)
            print("[OK] 添加ir_data字段")

        # 添加字段注释
        cursor.execute("""
            COMMENT ON COLUMN rules.ir_data IS
            '完整的IR对象(JSON)，包含assertion_subject, external_dependency, determinism, zlint_lintability等v2.0算法字段'
        """)
        print("[OK] 添加字段注释")

        conn.commit()
        print("\n迁移成功完成！")
        print("\n说明：")
        print("  - ir_data存储完整的中间表示(IR)对象")
        print("  - 包含新版v2.0 lintability判断算法的所有字段")
        print("  - 字段包括：assertion_subject, external_dependency, determinism, zlint_lintability")
        print("  - 使用JSON格式存储以保持灵活性")

    except Exception as e:
        conn.rollback()
        print(f"迁移失败: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def rollback_migration():
    """回滚迁移"""
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()

    try:
        print("回滚迁移：删除ir_data字段...")

        cursor.execute("""
            ALTER TABLE rules
            DROP COLUMN IF EXISTS ir_data
        """)

        conn.commit()
        print("回滚成功！")

    except Exception as e:
        conn.rollback()
        print(f"回滚失败: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'rollback':
        rollback_migration()
    else:
        run_migration()
