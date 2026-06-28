"""
模块 A: 文档预处理 - 文档分块器
实现超级提示词规范中的 split_document_into_blocks()
"""
from typing import List, Dict, Optional
from app.core.logging_config import app_logger


class Block:
    """文档块数据结构"""

    def __init__(
        self,
        text: str,
        block_type: str,  # heading | paragraph | list | code | table
        level: int = 0,    # 标题级别（0=非标题）
        metadata: Optional[Dict] = None
    ):
        self.text = text
        self.block_type = block_type
        self.level = level
        self.metadata = metadata or {}

    def to_dict(self) -> Dict:
        return {
            "text": self.text,
            "block_type": self.block_type,
            "level": self.level,
            "metadata": self.metadata
        }


class DocumentSplitter:
    """
    文档智能分块器

    功能：
    1. 按 heading 层级切分
    2. 识别段落、列表、代码块
    3. 保留上下文信息
    """

    def __init__(self):
        self.heading_patterns = [
            r'^#{1,6}\s+(.+)',      # Markdown heading
            r'^\d+\.\s+(.+)',       # 数字编号
            r'^[A-Z][a-z]+:',       # 冒号标题
        ]

    def split_document_into_blocks(
        self,
        document_text: str,
        max_block_size: int = 500
    ) -> List[Block]:
        """
        将文档拆分为可处理的块

        Args:
            document_text: 原始文档文本
            max_block_size: 最大块大小（字符数）

        Returns:
            Block 对象列表
        """
        app_logger.info("Starting document splitting...")

        blocks = []

        # Step 1: 按行拆分
        lines = document_text.split('\n')

        # Step 2: 识别结构
        current_block = []
        current_type = 'paragraph'
        current_level = 0

        for line in lines:
            line = line.strip()

            if not line:
                # 空行作为块分隔符
                if current_block:
                    block_text = '\n'.join(current_block)
                    blocks.append(Block(
                        text=block_text,
                        block_type=current_type,
                        level=current_level
                    ))
                    current_block = []
                continue

            # 检测标题
            detected_heading, heading_level = self._detect_heading(line)

            if detected_heading:
                # 保存前一块
                if current_block:
                    block_text = '\n'.join(current_block)
                    blocks.append(Block(
                        text=block_text,
                        block_type=current_type,
                        level=current_level
                    ))

                # 开始新的标题块
                current_block = [line]
                current_type = 'heading'
                current_level = heading_level
            else:
                # 继续当前块
                current_block.append(line)

                # 检查是否超过最大长度
                if len('\n'.join(current_block)) > max_block_size:
                    block_text = '\n'.join(current_block)
                    blocks.append(Block(
                        text=block_text,
                        block_type=current_type,
                        level=current_level
                    ))
                    current_block = []

        # 保存最后一块
        if current_block:
            block_text = '\n'.join(current_block)
            blocks.append(Block(
                text=block_text,
                block_type=current_type,
                level=current_level
            ))

        app_logger.info(f"Document split into {len(blocks)} blocks")
        return blocks

    def _detect_heading(self, line: str) -> tuple[bool, int]:
        """
        检测是否是标题

        Returns:
            (is_heading, level)
        """
        import re

        # Markdown 风格 (#, ##, ###)
        if match := re.match(r'^(#{1,6})\s+', line):
            return True, len(match.group(1))

        # 数字编号 (4.2.1.3)
        if match := re.match(r'^(\d+(\.\d+)*)\s+', line):
            level = len(match.group(1).split('.'))
            return True, level

        # 大写字母开头 + 冒号
        if re.match(r'^[A-Z][a-z]+:\s*$', line):
            return True, 1

        return False, 0

    def merge_small_blocks(
        self,
        blocks: List[Block],
        min_size: int = 50
    ) -> List[Block]:
        """
        合并过小的块

        Args:
            blocks: 块列表
            min_size: 最小块大小（字符数）

        Returns:
            合并后的块列表
        """
        merged = []
        buffer = []

        for block in blocks:
            if len(block.text) < min_size and block.block_type != 'heading':
                buffer.append(block)
            else:
                if buffer:
                    # 合并 buffer
                    merged_text = '\n'.join(b.text for b in buffer)
                    merged.append(Block(
                        text=merged_text,
                        block_type='paragraph',
                        level=0
                    ))
                    buffer = []

                merged.append(block)

        # 处理剩余 buffer
        if buffer:
            merged_text = '\n'.join(b.text for b in buffer)
            merged.append(Block(
                text=merged_text,
                block_type='paragraph',
                level=0
            ))

        app_logger.info(f"Merged {len(blocks)} blocks into {len(merged)} blocks")
        return merged
