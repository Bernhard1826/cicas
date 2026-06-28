"""
添加zlint验证字段到ct_certificate_idn_results表

Migration: 添加zlint合规性检查相关字段
Date: 2025-01-10
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
        print("开始迁移：添加zlint验证字段到ct_certificate_idn_results表...")

        # 检查字段是否已存在
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name='ct_certificate_idn_results' AND column_name='is_zlint_compliant'
        """)

        if cursor.fetchone():
            print("字段is_zlint_compliant已存在，跳过")
        else:
            # 添加is_zlint_compliant字段
            cursor.execute("""
                ALTER TABLE ct_certificate_idn_results
                ADD COLUMN is_zlint_compliant BOOLEAN DEFAULT TRUE
            """)
            print("[OK] 添加is_zlint_compliant字段")

            # 添加zlint_violations字段
            cursor.execute("""
                ALTER TABLE ct_certificate_idn_results
                ADD COLUMN zlint_violations TEXT NULL
            """)
            print("[OK] 添加zlint_violations字段")

            # 添加zlint_violation_count字段
            cursor.execute("""
                ALTER TABLE ct_certificate_idn_results
                ADD COLUMN zlint_violation_count INTEGER DEFAULT 0
            """)
            print("[OK] 添加zlint_violation_count字段")

            # 创建索引
            cursor.execute("""
                CREATE INDEX idx_ct_idn_zlint_compliant
                ON ct_certificate_idn_results(is_zlint_compliant)
            """)
            print("[OK] 创建is_zlint_compliant索引")

        # 添加字段注释
        cursor.execute("""
            COMMENT ON COLUMN ct_certificate_idn_results.is_zlint_compliant IS
            'zlint合规性检查结果，使用zlint内置的2600+规则'
        """)
        cursor.execute("""
            COMMENT ON COLUMN ct_certificate_idn_results.zlint_violations IS
            'zlint违规详情，JSON数组格式'
        """)
        cursor.execute("""
            COMMENT ON COLUMN ct_certificate_idn_results.zlint_violation_count IS
            'zlint违规数量'
        """)
        print("[OK] 添加字段注释")

        conn.commit()
        print("\n迁移成功完成！")

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
        print("回滚迁移：删除zlint验证字段...")

        # 删除索引
        cursor.execute("""
            DROP INDEX IF EXISTS idx_ct_idn_zlint_compliant
        """)
        print("[OK] 删除is_zlint_compliant索引")

        # 删除字段
        cursor.execute("""
            ALTER TABLE ct_certificate_idn_results
            DROP COLUMN IF EXISTS is_zlint_compliant,
            DROP COLUMN IF EXISTS zlint_violations,
            DROP COLUMN IF EXISTS zlint_violation_count
        """)
        print("[OK] 删除zlint字段")

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
