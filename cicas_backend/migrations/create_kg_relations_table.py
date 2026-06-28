"""
创建知识图谱关系表（kg_relations）

这是重构后唯一存储规则关系的表
所有推理结果（引用、冲突、依赖等）都存储在这里
"""
from sqlalchemy import text
from app.core.database import engine
from app.core.logging_config import app_logger


def upgrade():
    """创建 kg_relations 表"""

    with engine.connect() as conn:
        # 创建表
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS kg_relations (
                id SERIAL PRIMARY KEY,

                -- 关系的两端
                source_rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
                target_rule_id INTEGER REFERENCES rules(id) ON DELETE CASCADE,
                target_section VARCHAR(50),  -- 如果 target 是 section 而不是 rule

                -- 关系类型
                relation_type VARCHAR(50) NOT NULL,
                -- 'refers_to': 引用（事实层）
                -- 'CITES': 引用规则（结构映射）
                -- 'DEPENDS_ON': 依赖（推理层）
                -- 'CONFLICTS_WITH': 冲突（推理层）
                -- 'STRICTER_THAN': 更严格（推理层）
                -- 'OVERRIDES': 覆盖（推理层）
                -- 'POSSIBLE_CONFLICT': 可能冲突（不确定层）
                -- 'POSSIBLE_DEPENDENCY': 可能依赖（不确定层）
                -- 'REASONING_FAILED': 推理失败（失败层）

                -- 可追溯性（必填）
                algorithm_version VARCHAR(100) NOT NULL,  -- 'stage_c_v1.0', 'reasoning_v2.0'
                confidence FLOAT DEFAULT 1.0,
                reason JSONB,  -- 结构化原因

                -- 引用相关（仅 refers_to 类型需要）
                raw_reference_text TEXT,  -- 原始引用文本
                resolution_method VARCHAR(50),  -- 'structural_match_only', 'contextual', etc.

                -- 不确定性标记（仅 POSSIBLE_* 类型需要）
                is_uncertain BOOLEAN DEFAULT FALSE,
                missing_dimensions JSONB,  -- ['scope', 'condition']

                -- 失败标记（仅 REASONING_FAILED 类型需要）
                is_failure BOOLEAN DEFAULT FALSE,
                error_type VARCHAR(50),
                error_message TEXT,
                stage VARCHAR(50),  -- 'conflict_detection', 'dependency_inference'

                -- 时间戳
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
        """))

        # 创建索引（性能优化）
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_kg_relations_source
            ON kg_relations(source_rule_id);
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_kg_relations_target
            ON kg_relations(target_rule_id);
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_kg_relations_type
            ON kg_relations(relation_type);
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_kg_relations_algorithm
            ON kg_relations(algorithm_version);
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_kg_relations_uncertain
            ON kg_relations(is_uncertain)
            WHERE is_uncertain = TRUE;
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_kg_relations_failure
            ON kg_relations(is_failure)
            WHERE is_failure = TRUE;
        """))

        conn.commit()

    app_logger.info("[Migration] kg_relations table created successfully")


def downgrade():
    """删除 kg_relations 表"""

    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS kg_relations CASCADE;"))
        conn.commit()

    app_logger.info("[Migration] kg_relations table dropped")


if __name__ == "__main__":
    print("Creating kg_relations table...")
    upgrade()
    print("Done!")
