"""
数据库迁移: 添加Semantic IR字段支持

Semantic IR (中间表示) 格式用于规则发现和完整建模，而非仅可执行规则提取。
新增字段：
- modality: 模态（MUST, SHOULD, MAY, MUST_NOT, SHOULD_NOT）
- condition: 单个条件文本（向后兼容）
- conditions: 条件列表（JSON数组）
- subject_role: 主体角色（CA, Subscriber, Relying Party等）

运行方式:
    python migrations/add_semantic_ir_fields.py
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
        app_logger.info("开始数据库迁移: 添加Semantic IR字段...")

        try:
            # ========== 添加 Rule 表的Semantic IR字段 ==========
            app_logger.info("添加 Rule 表的Semantic IR字段...")

            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS modality VARCHAR(50),
                ADD COLUMN IF NOT EXISTS condition TEXT,
                ADD COLUMN IF NOT EXISTS conditions TEXT,
                ADD COLUMN IF NOT EXISTS subject_role VARCHAR(100)
            """))
            conn.commit()
            app_logger.info("[OK] Semantic IR字段添加完成")

            # ========== 创建索引（提升查询性能） ==========
            app_logger.info("创建索引...")

            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_modality
                ON rules(modality)
            """))

            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_subject_role
                ON rules(subject_role)
            """))

            conn.commit()
            app_logger.info("[OK] 索引创建完成")

            # ========== 初始化现有规则的modality字段（从rule_type复制） ==========
            app_logger.info("初始化现有规则的modality字段...")

            # 将现有的rule_type值复制到modality字段
            # 这样旧规则也能受益于Semantic IR结构
            conn.execute(text("""
                UPDATE rules
                SET modality = rule_type
                WHERE modality IS NULL AND rule_type IS NOT NULL
            """))
            conn.commit()
            app_logger.info("[OK] 现有规则modality字段初始化完成")

            app_logger.info("========================================")
            app_logger.info("[OK] 数据库迁移成功完成！")
            app_logger.info("========================================")
            app_logger.info("新增功能:")
            app_logger.info("  - Semantic IR支持:")
            app_logger.info("    * modality: 模态（MUST, SHOULD, MAY等）")
            app_logger.info("    * condition: 单个条件文本")
            app_logger.info("    * conditions: 条件列表（JSON数组）")
            app_logger.info("    * subject_role: 主体角色（CA, Subscriber等）")
            app_logger.info("")
            app_logger.info("  - 向后兼容:")
            app_logger.info("    * 旧字段保留: affected_field, operation, expected_value")
            app_logger.info("    * 现有规则的modality已从rule_type初始化")
            app_logger.info("========================================")

        except Exception as e:
            app_logger.error(f"数据库迁移失败: {e}")
            conn.rollback()
            raise


if __name__ == "__main__":
    migrate()
