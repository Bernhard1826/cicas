"""
语义搜索配置
集中管理相似度阈值、查询扩展等配置
"""

class SemanticSearchConfig:
    """语义搜索配置类"""

    # ===== 相似度阈值配置 =====
    class Similarity:
        """相似度阈值"""
        DEFAULT = 0.5              # 默认阈值：50%
        MIN = 0.1                  # 最小阈值：10%
        MAX = 0.9                  # 最大阈值：90%

        # 相似度分级
        HIGH_THRESHOLD = 0.7       # 高相关：≥70%
        MEDIUM_THRESHOLD = 0.6     # 中等相关：60-70%
        FAIR_THRESHOLD = 0.5       # 一般相关：50-60%
        # <50% 为低相关

    # ===== 查询扩展配置 =====
    class QueryExpansion:
        """查询扩展配置"""
        ENABLED_BY_DEFAULT = True  # 默认启用查询扩展
        MAX_SYNONYMS = 3           # 最多使用3个同义词进行扩展

    # ===== 搜索限制配置 =====
    class Limits:
        """搜索结果数量限制"""
        DEFAULT = 20               # 默认返回20条
        MIN = 1                    # 最少1条
        MAX = 1000                 # 最多1000条（与其他搜索功能保持一致）

    # ===== 质量警告阈值 =====
    class QualityWarnings:
        """搜索结果质量警告"""
        LOW_QUALITY_THRESHOLD = 0.5    # 最高相似度<50%时警告
        MEDIUM_QUALITY_THRESHOLD = 0.6 # 最高相似度50-60%时提示

    @classmethod
    def get_similarity_level(cls, similarity: float) -> str:
        """
        获取相似度级别

        Args:
            similarity: 相似度分数 (0-1)

        Returns:
            相似度级别: 'high', 'medium', 'fair', 'low'
        """
        if similarity >= cls.Similarity.HIGH_THRESHOLD:
            return 'high'
        elif similarity >= cls.Similarity.MEDIUM_THRESHOLD:
            return 'medium'
        elif similarity >= cls.Similarity.FAIR_THRESHOLD:
            return 'fair'
        else:
            return 'low'

    @classmethod
    def validate_threshold(cls, threshold: float) -> float:
        """
        验证并规范化阈值

        Args:
            threshold: 输入的阈值

        Returns:
            规范化后的阈值

        Raises:
            ValueError: 阈值超出有效范围
        """
        if threshold < cls.Similarity.MIN or threshold > cls.Similarity.MAX:
            raise ValueError(
                f"Threshold must be between {cls.Similarity.MIN} and {cls.Similarity.MAX}, "
                f"got {threshold}"
            )
        return threshold

    @classmethod
    def validate_limit(cls, limit: int) -> int:
        """
        验证并规范化结果数量限制

        Args:
            limit: 输入的限制数量

        Returns:
            规范化后的限制数量

        Raises:
            ValueError: 限制数量超出有效范围
        """
        if limit < cls.Limits.MIN or limit > cls.Limits.MAX:
            raise ValueError(
                f"Limit must be between {cls.Limits.MIN} and {cls.Limits.MAX}, "
                f"got {limit}"
            )
        return limit


# 导出配置实例供其他模块使用
CONFIG = SemanticSearchConfig()
