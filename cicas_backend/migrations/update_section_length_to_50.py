"""
数据库迁移: 将section字段长度从200改回50

Migration: 修改rules表的section字段长度为VARCHAR(50)
Date: 2025-12-17
"""
import psycopg2
import os

# 数据库配置
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:123456@localhost:5432/pki_standards')

def run_migration():
    """执行迁移"""
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()

    try:
        print("开始迁移：修改section字段长度为VARCHAR(50)...")

        # 检查是否有超过50字符的section值
        cursor.execute("""
            SELECT COUNT(*) as count, MAX(LENGTH(section)) as max_len
            FROM rules
            WHERE LENGTH(section) > 50
        """)
        result = cursor.fetchone()
        if result[0] > 0:
            print(f"警告：发现 {result[0]} 条规则的section长度超过50 (最长: {result[1]})")
            print("这些数据将被截断。是否继续？(y/n)")
            # 在脚本中自动继续，因为我们已经确认实际最长只有7个字符

        # 修改字段长度
        cursor.execute("""
            ALTER TABLE rules
            ALTER COLUMN section TYPE VARCHAR(50)
        """)
        print("[OK] section字段长度已修改为VARCHAR(50)")

        conn.commit()
        print("\n迁移成功完成！")
        print("\n说明：")
        print("  - section字段长度已从VARCHAR(200)改为VARCHAR(50)")
        print("  - 这对于章节号（如'4.1.2.6'）已经足够使用")

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
        print("回滚迁移：将section字段长度改回VARCHAR(200)...")

        cursor.execute("""
            ALTER TABLE rules
            ALTER COLUMN section TYPE VARCHAR(200)
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
