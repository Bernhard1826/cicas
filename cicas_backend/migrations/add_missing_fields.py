"""
添加所有缺失的字段到rules表
这个脚本添加模型中定义但数据库中缺失的字段
"""
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import text
from app.core.database import engine
from app.core.logging_config import app_logger


def migrate():
    """执行数据库迁移"""

    with engine.connect() as conn:
        app_logger.info("开始添加缺失的字段...")

        try:
            # 添加规则拆分追踪字段
            app_logger.info("添加规则拆分追踪字段...")
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS sentence_index INTEGER,
                ADD COLUMN IF NOT EXISTS sentence_hash VARCHAR(64)
            """))
            conn.commit()

            # 添加索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_sentence_index
                ON rules(sentence_index)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_sentence_hash
                ON rules(sentence_hash)
            """))
            conn.commit()
            app_logger.info("[OK] 规则拆分追踪字段添加完成")

            # 添加规则来源字段
            app_logger.info("添加规则来源字段...")
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS origin VARCHAR(50),
                ADD COLUMN IF NOT EXISTS derived_from INTEGER,
                ADD COLUMN IF NOT EXISTS derivation_type VARCHAR(50),
                ADD COLUMN IF NOT EXISTS derivation_justification TEXT
            """))
            conn.commit()
            app_logger.info("[OK] 规则来源字段添加完成")

            # 添加规则属性字段（用于可执行性判断）
            app_logger.info("添加规则属性字段...")
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS executability VARCHAR(50),
                ADD COLUMN IF NOT EXISTS execution_target VARCHAR(100),
                ADD COLUMN IF NOT EXISTS observability VARCHAR(50),
                ADD COLUMN IF NOT EXISTS self_contained BOOLEAN,
                ADD COLUMN IF NOT EXISTS determinism VARCHAR(50),
                ADD COLUMN IF NOT EXISTS formalized BOOLEAN,
                ADD COLUMN IF NOT EXISTS subjective_terms TEXT
            """))
            conn.commit()
            app_logger.info("[OK] 规则属性字段添加完成")

            # 添加裁决字段
            app_logger.info("添加裁决字段...")
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS adjudicated_at TIMESTAMP,
                ADD COLUMN IF NOT EXISTS adjudication_version VARCHAR(50)
            """))
            conn.commit()
            app_logger.info("[OK] 裁决字段添加完成")

            app_logger.info("========================================")
            app_logger.info("[OK] 所有缺失字段添加完成！")
            app_logger.info("========================================")

        except Exception as e:
            app_logger.error(f"数据库迁移失败: {e}")
            conn.rollback()
            raise


if __name__ == "__main__":
    migrate()
