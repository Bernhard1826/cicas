"""
数据库迁移: 添加RAG证据系统和质量评分字段

运行方式:
    python migrations/add_evidence_and_quality_fields.py
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
        app_logger.info("开始数据库迁移: 添加RAG证据和质量评分字段...")

        try:
            # ========== 添加 Rule 表的新字段 ==========
            app_logger.info("添加 Rule 表的新字段...")

            # RAG证据系统字段
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS evidence_ids TEXT,
                ADD COLUMN IF NOT EXISTS confidence_score FLOAT,
                ADD COLUMN IF NOT EXISTS document_verified BOOLEAN DEFAULT FALSE
            """))
            conn.commit()
            app_logger.info("[OK] RAG证据系统字段添加完成")

            # 质量评分和进化系统字段
            conn.execute(text("""
                ALTER TABLE rules
                ADD COLUMN IF NOT EXISTS quality_score FLOAT DEFAULT 0.5,
                ADD COLUMN IF NOT EXISTS human_approved BOOLEAN,
                ADD COLUMN IF NOT EXISTS rejection_reason TEXT,
                ADD COLUMN IF NOT EXISTS usage_count INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP
            """))
            conn.commit()
            app_logger.info("[OK] 质量评分系统字段添加完成")

            # ========== 创建 RuleAuditLog 表 ==========
            app_logger.info("创建 RuleAuditLog 表...")

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS rule_audit_logs (
                    id SERIAL PRIMARY KEY,
                    rule_id INTEGER NOT NULL REFERENCES rules(id),

                    -- 审核操作
                    action VARCHAR(50) NOT NULL,
                    previous_status VARCHAR(50),
                    new_status VARCHAR(50),

                    -- 审核反馈
                    human_approved BOOLEAN,
                    rejection_reason TEXT,

                    -- 修改内容
                    field_changed VARCHAR(100),
                    old_value TEXT,
                    new_value TEXT,

                    -- 审核元数据
                    auditor_note TEXT,
                    confidence_before FLOAT,
                    confidence_after FLOAT,
                    quality_score_before FLOAT,
                    quality_score_after FLOAT,

                    -- 时间戳
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
            app_logger.info("[OK] RuleAuditLog 表创建完成")

            # ========== 创建索引 ==========
            app_logger.info("创建索引...")

            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_audit_log_rule
                ON rule_audit_logs(rule_id)
            """))

            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_audit_log_action
                ON rule_audit_logs(action, created_at)
            """))

            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_quality_score
                ON rules(quality_score)
            """))

            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_rule_confidence_score
                ON rules(confidence_score)
            """))

            conn.commit()
            app_logger.info("[OK] 索引创建完成")

            # ========== 初始化现有规则的默认值 ==========
            app_logger.info("初始化现有规则的默认值...")

            conn.execute(text("""
                UPDATE rules
                SET
                    quality_score = 0.5,
                    usage_count = 0,
                    document_verified = FALSE
                WHERE quality_score IS NULL
            """))
            conn.commit()
            app_logger.info("[OK] 现有规则默认值初始化完成")

            app_logger.info("========================================")
            app_logger.info("[OK] 数据库迁移成功完成！")
            app_logger.info("========================================")
            app_logger.info("新增功能:")
            app_logger.info("  - RAG证据系统 (evidence_ids, confidence_score, document_verified)")
            app_logger.info("  - 质量评分系统 (quality_score, human_approved, rejection_reason)")
            app_logger.info("  - 使用统计 (usage_count, last_used_at)")
            app_logger.info("  - 审核日志表 (rule_audit_logs)")
            app_logger.info("========================================")

        except Exception as e:
            app_logger.error(f"数据库迁移失败: {e}")
            conn.rollback()
            raise


if __name__ == "__main__":
    migrate()
