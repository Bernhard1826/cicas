"""
数据库迁移: 添加RuleChunk表（Layer1输出存储）

运行方式:
    python migrations/add_rule_chunks_table.py
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
        app_logger.info("开始数据库迁移: 添加RuleChunk表...")

        try:
            # ========== 创建 rule_chunks 表 ==========
            app_logger.info("创建 rule_chunks 表...")

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS rule_chunks (
                    id SERIAL PRIMARY KEY,

                    -- Chunk标识
                    chunk_id VARCHAR(100) NOT NULL UNIQUE,
                    doc_id VARCHAR(100) NOT NULL,
                    section VARCHAR(100),

                    -- Chunk位置
                    start_line INTEGER NOT NULL,
                    end_line INTEGER NOT NULL,

                    -- Chunk内容
                    text TEXT NOT NULL,
                    text_hash VARCHAR(64) NOT NULL,

                    -- 锚点信息
                    anchor VARCHAR(50) NOT NULL,

                    -- 处理状态
                    status VARCHAR(50) DEFAULT 'pending',
                    processed_by VARCHAR(50),

                    -- 提取结果
                    rules_extracted_count INTEGER DEFAULT 0,
                    extracted_rule_ids TEXT,

                    -- 质量标记
                    is_noise BOOLEAN DEFAULT FALSE,
                    noise_reason VARCHAR(200),

                    -- 元数据
                    standard_id INTEGER REFERENCES standards(id),
                    created_by VARCHAR(50) DEFAULT 'regex_layer',

                    -- 时间戳
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
            app_logger.info("[OK] rule_chunks 表创建完成")

            # ========== 创建索引 ==========
            app_logger.info("创建索引...")

            # 主键索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_chunk_id
                ON rule_chunks(chunk_id)
            """))

            # 文档ID索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_chunk_doc_id
                ON rule_chunks(doc_id)
            """))

            # 文档+章节组合索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_chunk_doc_section
                ON rule_chunks(doc_id, section)
            """))

            # 状态索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_chunk_status
                ON rule_chunks(status, created_at)
            """))

            # 锚点索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_chunk_anchor
                ON rule_chunks(anchor, status)
            """))

            # 文本hash索引（用于去重）
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_chunk_text_hash
                ON rule_chunks(text_hash)
            """))

            # 噪音标记索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_chunk_is_noise
                ON rule_chunks(is_noise)
            """))

            # Standard ID索引
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_chunk_standard_id
                ON rule_chunks(standard_id)
            """))

            conn.commit()
            app_logger.info("[OK] 索引创建完成")

            app_logger.info("========================================")
            app_logger.info("[OK] 数据库迁移成功完成！")
            app_logger.info("========================================")
            app_logger.info("新增内容:")
            app_logger.info("  - rule_chunks 表 (存储Layer1切分的chunks)")
            app_logger.info("  - 支持chunk去重 (text_hash)")
            app_logger.info("  - 支持噪音过滤 (is_noise, noise_reason)")
            app_logger.info("  - 支持追踪提取结果 (rules_extracted_count, extracted_rule_ids)")
            app_logger.info("========================================")

        except Exception as e:
            app_logger.error(f"数据库迁移失败: {e}")
            conn.rollback()
            raise


if __name__ == "__main__":
    migrate()
