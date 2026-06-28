"""
优先级过滤器 (Priority Filter)

职责：
1. 定义检索优先级
2. 过滤和排序检索结果
3. 实现截断策略

设计原则：
- 优先级：Definition > Field > Other rules
- 截断策略：drop_lowest_priority
- 不做跨规范泛化
"""
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import IntEnum

from app.core.logging_config import app_logger


class Priority(IntEnum):
    """优先级定义（数字越小优先级越高）"""
    DEFINITION = 1      # 术语定义
    FIELD = 2           # 证书字段
    RELATED_SECTION = 3 # 相关章节
    RULE = 4            # 相关规则
    OTHER = 99          # 其他


@dataclass
class PriorityItem:
    """带优先级的项目"""
    content: str
    priority: Priority
    source: str = ""
    token_estimate: int = 0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.token_estimate == 0:
            self.token_estimate = len(self.content) // 4


class PriorityFilter:
    """
    优先级过滤器

    根据 token budget 和优先级过滤内容。
    """

    # 默认配置
    DEFAULT_MAX_TOKENS = 2000

    # 优先级顺序
    PRIORITY_ORDER = [
        Priority.DEFINITION,
        Priority.FIELD,
        Priority.RELATED_SECTION,
        Priority.RULE,
        Priority.OTHER,
    ]

    def __init__(
        self,
        max_tokens: int = None,
        truncation_strategy: str = "drop_lowest_priority"
    ):
        """
        初始化优先级过滤器

        Args:
            max_tokens: 最大 token 数
            truncation_strategy: 截断策略
                - "drop_lowest_priority": 丢弃最低优先级的项目
                - "proportional": 按比例截断各优先级
        """
        self.max_tokens = max_tokens or self.DEFAULT_MAX_TOKENS
        self.truncation_strategy = truncation_strategy

    def filter(self, items: List[PriorityItem]) -> List[PriorityItem]:
        """
        过滤和排序项目

        Args:
            items: 待过滤的项目列表

        Returns:
            过滤后的项目列表
        """
        if not items:
            return []

        # 按优先级排序
        sorted_items = sorted(items, key=lambda x: x.priority)

        # 应用截断策略
        if self.truncation_strategy == "drop_lowest_priority":
            return self._drop_lowest_priority(sorted_items)
        elif self.truncation_strategy == "proportional":
            return self._proportional_truncate(sorted_items)
        else:
            return self._drop_lowest_priority(sorted_items)

    def _drop_lowest_priority(
        self,
        sorted_items: List[PriorityItem]
    ) -> List[PriorityItem]:
        """
        丢弃最低优先级的项目

        从最高优先级开始添加，直到达到 token budget。
        """
        result = []
        current_tokens = 0

        for item in sorted_items:
            if current_tokens + item.token_estimate <= self.max_tokens:
                result.append(item)
                current_tokens += item.token_estimate
            else:
                # 尝试截断当前项目
                remaining = self.max_tokens - current_tokens
                if remaining > 50:  # 至少保留 50 tokens
                    truncated_content = item.content[:remaining * 4 - 3] + "..."
                    truncated_item = PriorityItem(
                        content=truncated_content,
                        priority=item.priority,
                        source=item.source,
                        token_estimate=remaining,
                        metadata={**item.metadata, "truncated": True},
                    )
                    result.append(truncated_item)
                break

        return result

    def _proportional_truncate(
        self,
        sorted_items: List[PriorityItem]
    ) -> List[PriorityItem]:
        """
        按比例截断各优先级

        为每个优先级分配 token 配额，然后在配额内选择项目。
        """
        # 统计各优先级的项目
        by_priority: Dict[Priority, List[PriorityItem]] = {}
        for item in sorted_items:
            if item.priority not in by_priority:
                by_priority[item.priority] = []
            by_priority[item.priority].append(item)

        # 分配配额（优先级越高，配额越大）
        total_weight = sum(len(self.PRIORITY_ORDER) - i for i in range(len(by_priority)))
        quotas = {}

        for i, priority in enumerate(self.PRIORITY_ORDER):
            if priority in by_priority:
                weight = len(self.PRIORITY_ORDER) - i
                quotas[priority] = int(self.max_tokens * weight / total_weight)

        # 在配额内选择项目
        result = []
        for priority in self.PRIORITY_ORDER:
            if priority not in by_priority:
                continue

            quota = quotas.get(priority, 0)
            current_tokens = 0

            for item in by_priority[priority]:
                if current_tokens + item.token_estimate <= quota:
                    result.append(item)
                    current_tokens += item.token_estimate

        return result

    def create_item(
        self,
        content: str,
        item_type: str,
        source: str = "",
        metadata: Dict[str, Any] = None
    ) -> PriorityItem:
        """
        创建优先级项目

        Args:
            content: 内容
            item_type: 类型（"definition", "field", "section", "rule"）
            source: 来源
            metadata: 元数据

        Returns:
            PriorityItem
        """
        priority_map = {
            "definition": Priority.DEFINITION,
            "field": Priority.FIELD,
            "section": Priority.RELATED_SECTION,
            "rule": Priority.RULE,
        }

        priority = priority_map.get(item_type.lower(), Priority.OTHER)

        return PriorityItem(
            content=content,
            priority=priority,
            source=source,
            metadata=metadata or {},
        )

    def get_statistics(self, items: List[PriorityItem]) -> Dict[str, Any]:
        """获取项目统计"""
        total_tokens = sum(item.token_estimate for item in items)

        by_priority = {}
        for item in items:
            priority_name = item.priority.name
            if priority_name not in by_priority:
                by_priority[priority_name] = {"count": 0, "tokens": 0}
            by_priority[priority_name]["count"] += 1
            by_priority[priority_name]["tokens"] += item.token_estimate

        return {
            "total_items": len(items),
            "total_tokens": total_tokens,
            "within_budget": total_tokens <= self.max_tokens,
            "by_priority": by_priority,
        }
