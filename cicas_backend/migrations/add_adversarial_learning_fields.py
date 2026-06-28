"""
添加 zlint 对抗学习相关字段

Revision ID: add_adversarial_learning_fields
Create Date: 2025-11-14
"""
from alembic import op
import sqlalchemy as sa


def upgrade():
    """添加 zlint 对抗学习相关字段到 rules 表"""

    # 添加 zlint 验证相关字段
    op.add_column('rules', sa.Column('zlint_verified', sa.Boolean(), nullable=True, default=False))
    op.add_column('rules', sa.Column('zlint_lint_name', sa.String(200), nullable=True))
    op.add_column('rules', sa.Column('zlint_match_confidence', sa.Float(), nullable=True))
    op.add_column('rules', sa.Column('zlint_match_method', sa.String(50), nullable=True))

    # 添加审核员备注字段（如果不存在）
    op.add_column('rules', sa.Column('auditor_note', sa.Text(), nullable=True))

    # 创建索引
    op.create_index('idx_rule_zlint_verified', 'rules', ['zlint_verified'])
    op.create_index('idx_rule_zlint_lint_name', 'rules', ['zlint_lint_name'])


def downgrade():
    """回滚：删除 zlint 对抗学习相关字段"""

    # 删除索引
    op.drop_index('idx_rule_zlint_verified', 'rules')
    op.drop_index('idx_rule_zlint_lint_name', 'rules')

    # 删除字段
    op.drop_column('rules', 'zlint_verified')
    op.drop_column('rules', 'zlint_lint_name')
    op.drop_column('rules', 'zlint_match_confidence')
    op.drop_column('rules', 'zlint_match_method')
    op.drop_column('rules', 'auditor_note')
