"""
添加zlint_similarity字段到rules表

Migration: 添加zlint_similarity字段用于存储RAG语义相似度
Date: 2025-11-27
"""
import psycopg2
import os
from pathlib import Path

# 数据库配置
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/pki_rules')

def run_migration():
    """执行迁移"""
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()

    try:
        print("开始迁移：添加zlint_similarity字段...")

        # 检查字段是否已存在
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name='rules' AND column_name='zlint_similarity'
        """)

        if cursor.fetchone():
            print("字段zlint_similarity已存在，跳过")
        else:
            # 添加字段
            cursor.execute("""
                ALTER TABLE rules
                ADD COLUMN zlint_similarity FLOAT NULL
            """)
            print("✓ 添加zlint_similarity字段")

        # 更新zlint_match_method字段注释
        cursor.execute("""
            COMMENT ON COLUMN rules.zlint_similarity IS
            '与zlint规则的语义相似度 (0-1)，基于RAG embedding cosine similarity'
        """)
        print("✓ 添加字段注释")

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
        print("回滚迁移：删除zlint_similarity字段...")

        cursor.execute("""
            ALTER TABLE rules
            DROP COLUMN IF EXISTS zlint_similarity
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
