"""
Migration: Add adversarial optimization tables

Creates:
1. adversarial_optimization_config - 存储动态优化的配置
2. adversarial_feedback - 存储反馈数据用于参数优化

Run with: python migrations/add_adversarial_optimization_tables.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.core.database import engine


def migrate():
    """Create adversarial optimization tables"""

    with engine.connect() as conn:
        # 1. Create adversarial_optimization_config table
        print("Creating adversarial_optimization_config table...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS adversarial_optimization_config (
                id SERIAL PRIMARY KEY,
                config_type VARCHAR(50) NOT NULL,
                version INTEGER DEFAULT 1,
                is_active BOOLEAN DEFAULT TRUE,

                -- 动态阈值配置
                zlint_coverage_threshold FLOAT DEFAULT 0.95,
                quality_auto_approve_threshold FLOAT DEFAULT 0.90,
                rag_quality_threshold FLOAT DEFAULT 0.9,
                rag_min_similarity FLOAT DEFAULT 0.3,

                -- Prompt优化配置 (JSON)
                ignore_patterns TEXT,
                extraction_hints TEXT,
                field_mapping_rules TEXT,

                -- 反馈统计 (JSON)
                feedback_stats TEXT,
                performance_metrics TEXT,

                -- 优化效果追踪
                total_extractions INTEGER DEFAULT 0,
                avg_quality_score FLOAT,
                auto_approve_rate FLOAT,
                false_positive_rate FLOAT,
                false_negative_rate FLOAT,

                -- 学习元数据
                learning_source VARCHAR(100),
                optimization_note TEXT,

                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """))

        # Create indexes for adversarial_optimization_config
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_adv_config_type
            ON adversarial_optimization_config(config_type)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_adv_config_active
            ON adversarial_optimization_config(is_active)
        """))

        # 2. Create adversarial_feedback table
        print("Creating adversarial_feedback table...")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS adversarial_feedback (
                id SERIAL PRIMARY KEY,

                -- 关联信息
                extraction_batch_id VARCHAR(100),
                rule_id INTEGER REFERENCES rules(id),

                -- 反馈类型
                feedback_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20),

                -- 问题详情
                issue_category VARCHAR(100),
                issue_description TEXT,

                -- 原始数据和修正数据
                original_data TEXT,
                corrected_data TEXT,

                -- 影响的配置
                affected_config_type VARCHAR(50),
                suggested_threshold FLOAT,
                suggested_prompt_change TEXT,

                -- 处理状态
                is_processed BOOLEAN DEFAULT FALSE,
                applied_to_config_id INTEGER REFERENCES adversarial_optimization_config(id),

                created_at TIMESTAMP DEFAULT NOW()
            )
        """))

        # Create indexes for adversarial_feedback
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_adv_feedback_type
            ON adversarial_feedback(feedback_type)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_adv_feedback_processed
            ON adversarial_feedback(is_processed)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_adv_feedback_batch
            ON adversarial_feedback(extraction_batch_id)
        """))

        # 3. 插入默认配置
        print("Inserting default optimization config...")
        conn.execute(text("""
            INSERT INTO adversarial_optimization_config
            (config_type, version, is_active, learning_source, optimization_note)
            VALUES
            ('threshold', 1, TRUE, 'manual', 'Initial default configuration')
            ON CONFLICT DO NOTHING
        """))

        conn.commit()
        print("✅ Successfully created adversarial optimization tables")


def rollback():
    """Rollback: Drop adversarial optimization tables"""

    with engine.connect() as conn:
        print("Dropping adversarial_feedback table...")
        conn.execute(text("DROP TABLE IF EXISTS adversarial_feedback CASCADE"))

        print("Dropping adversarial_optimization_config table...")
        conn.execute(text("DROP TABLE IF EXISTS adversarial_optimization_config CASCADE"))

        conn.commit()
        print("✅ Successfully dropped adversarial optimization tables")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migration for adversarial optimization")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        rollback()
    else:
        migrate()
