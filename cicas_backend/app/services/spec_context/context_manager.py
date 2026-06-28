"""
规范上下文管理器 (Specification Context Manager)

职责：
1. 自动检测规范体系（RFC/CABF/ETSI）
2. 确定适用范围（issuance/validation/processing）
3. 加载对应的规范上下文

设计原则：
- 基于规则检测，不依赖 LLM
- 支持多规范体系共存
- 上下文加载按需进行
"""
import re
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from enum import Enum

from app.core.logging_config import app_logger


class SpecFamily(str, Enum):
    """规范体系"""
    RFC = "RFC"      # IETF RFC 系列（RFC 5280, RFC 6818 等）
    CABF = "CABF"    # CA/Browser Forum（BR, EVG, SMIME BR 等）
    ETSI = "ETSI"    # ETSI 标准（EN 319 411 等）
    MOZILLA = "Mozilla"  # Mozilla Root Store Policy
    APPLE = "Apple"  # Apple Root Certificate Program
    CHROME = "Chrome"  # Chrome Root Program
    OTHER = "Other"  # 其他规范


class Scope(str, Enum):
    """适用范围"""
    ISSUANCE = "issuance"        # 证书签发
    VALIDATION = "validation"    # 证书验证
    PROCESSING = "processing"    # 证书处理
    REVOCATION = "revocation"    # 证书撤销
    GENERAL = "general"          # 通用


@dataclass
class SpecContext:
    """规范上下文"""
    spec_family: SpecFamily
    spec_id: str  # 如 "RFC5280", "CABF-BR-2.0.0"
    spec_version: Optional[str] = None
    scope: Scope = Scope.GENERAL
    definitions: Dict[str, str] = field(default_factory=dict)
    related_sections: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SpecificationContextManager:
    """
    规范上下文管理器

    职责：
    1. 检测文本所属的规范体系
    2. 确定适用范围
    3. 加载相关的规范上下文
    """

    # RFC 模式
    RFC_PATTERNS = [
        r'\bRFC\s*(\d+)\b',                    # RFC 5280
        r'\bRFC-?(\d+)\b',                     # RFC-5280
        r'\bIETF\s+RFC\b',                     # IETF RFC
        r'\bInternet\s+Standard\b',            # Internet Standard
        r'\bBest\s+Current\s+Practice\b',      # BCP
    ]

    # CABF 模式
    CABF_PATTERNS = [
        r'\bCA/Browser\s+Forum\b',             # CA/Browser Forum
        r'\bCA/B\s+Forum\b',                   # CA/B Forum
        r'\bBaseline\s+Requirements\b',        # Baseline Requirements
        r'\bBR\s+Section\b',                   # BR Section
        r'\bEV\s+Guidelines\b',                # EV Guidelines
        r'\bEVG\s+Section\b',                  # EVG Section
        r'\bS/MIME\s+BR\b',                    # S/MIME BR
        r'\bTLS\s+BR\b',                       # TLS BR
        r'\bCode\s+Signing\s+BR\b',            # Code Signing BR
        r'\bCABF\b',                           # CABF
    ]

    # ETSI 模式
    ETSI_PATTERNS = [
        r'\bETSI\s+EN\s+\d+\b',                # ETSI EN 319
        r'\bETSI\s+TS\s+\d+\b',                # ETSI TS
        r'\bETSI\s+TR\s+\d+\b',                # ETSI TR
        r'\bEN\s+319\s+\d+\b',                 # EN 319 411
    ]

    # Mozilla 模式
    MOZILLA_PATTERNS = [
        r'\bMozilla\s+Root\s+Store\b',         # Mozilla Root Store
        r'\bMozilla\s+Policy\b',               # Mozilla Policy
        r'\bMRSP\b',                           # MRSP
    ]

    # Apple 模式
    APPLE_PATTERNS = [
        r'\bApple\s+Root\s+Certificate\b',     # Apple Root Certificate
        r'\bApple\s+Root\s+Program\b',         # Apple Root Program
    ]

    # Chrome 模式
    CHROME_PATTERNS = [
        r'\bChrome\s+Root\s+Program\b',        # Chrome Root Program
        r'\bCCASC\b',                          # CCASC
    ]

    # 范围检测模式
    ISSUANCE_PATTERNS = [
        r'\bissue\b', r'\bissuance\b', r'\bissuing\b',
        r'\bCA\s+MUST\b', r'\bCA\s+SHALL\b',
        r'\bgenerate\b', r'\bcreate\b',
    ]

    VALIDATION_PATTERNS = [
        r'\bvalidat(?:e|ion|ing)\b',
        r'\bverif(?:y|ication|ying)\b',
        r'\brelying\s+party\b', r'\bRP\b',
        r'\bpath\s+validation\b',
    ]

    PROCESSING_PATTERNS = [
        r'\bprocess(?:ing)?\b',
        r'\bpars(?:e|ing)\b',
        r'\binterpret(?:ation)?\b',
        r'\bhandl(?:e|ing)\b',
    ]

    REVOCATION_PATTERNS = [
        r'\brevok(?:e|ation|ing)\b',
        r'\bCRL\b', r'\bOCSP\b',
        r'\bsuspend\b',
    ]

    def __init__(self, knowledge_graph=None, corpus_loader=None):
        """
        初始化规范上下文管理器

        Args:
            knowledge_graph: 知识图谱实例（用于加载上下文）
            corpus_loader: 语料库加载器（用于加载规范文档）
        """
        self.kg = knowledge_graph
        self.corpus_loader = corpus_loader

        # 编译正则表达式
        self._compile_patterns()

        # 上下文缓存
        self._context_cache: Dict[str, SpecContext] = {}

    def _compile_patterns(self):
        """编译所有正则表达式"""
        self._rfc_patterns = [re.compile(p, re.IGNORECASE) for p in self.RFC_PATTERNS]
        self._cabf_patterns = [re.compile(p, re.IGNORECASE) for p in self.CABF_PATTERNS]
        self._etsi_patterns = [re.compile(p, re.IGNORECASE) for p in self.ETSI_PATTERNS]
        self._mozilla_patterns = [re.compile(p, re.IGNORECASE) for p in self.MOZILLA_PATTERNS]
        self._apple_patterns = [re.compile(p, re.IGNORECASE) for p in self.APPLE_PATTERNS]
        self._chrome_patterns = [re.compile(p, re.IGNORECASE) for p in self.CHROME_PATTERNS]

        self._issuance_patterns = [re.compile(p, re.IGNORECASE) for p in self.ISSUANCE_PATTERNS]
        self._validation_patterns = [re.compile(p, re.IGNORECASE) for p in self.VALIDATION_PATTERNS]
        self._processing_patterns = [re.compile(p, re.IGNORECASE) for p in self.PROCESSING_PATTERNS]
        self._revocation_patterns = [re.compile(p, re.IGNORECASE) for p in self.REVOCATION_PATTERNS]

    def detect_spec_family(self, text: str) -> SpecFamily:
        """
        检测文本所属的规范体系

        Args:
            text: 输入文本

        Returns:
            SpecFamily 枚举值
        """
        # 统计各规范体系的匹配次数
        scores = {
            SpecFamily.RFC: 0,
            SpecFamily.CABF: 0,
            SpecFamily.ETSI: 0,
            SpecFamily.MOZILLA: 0,
            SpecFamily.APPLE: 0,
            SpecFamily.CHROME: 0,
        }

        # 检测 RFC
        for pattern in self._rfc_patterns:
            scores[SpecFamily.RFC] += len(pattern.findall(text))

        # 检测 CABF
        for pattern in self._cabf_patterns:
            scores[SpecFamily.CABF] += len(pattern.findall(text))

        # 检测 ETSI
        for pattern in self._etsi_patterns:
            scores[SpecFamily.ETSI] += len(pattern.findall(text))

        # 检测 Mozilla
        for pattern in self._mozilla_patterns:
            scores[SpecFamily.MOZILLA] += len(pattern.findall(text))

        # 检测 Apple
        for pattern in self._apple_patterns:
            scores[SpecFamily.APPLE] += len(pattern.findall(text))

        # 检测 Chrome
        for pattern in self._chrome_patterns:
            scores[SpecFamily.CHROME] += len(pattern.findall(text))

        # 返回得分最高的规范体系
        max_score = max(scores.values())
        if max_score == 0:
            return SpecFamily.OTHER

        for family, score in scores.items():
            if score == max_score:
                return family

        return SpecFamily.OTHER

    def get_applicable_scope(self, text: str, section: Optional[str] = None) -> Scope:
        """
        确定文本的适用范围

        Args:
            text: 输入文本
            section: 章节号（可选，用于更精确的判断）

        Returns:
            Scope 枚举值
        """
        # 统计各范围的匹配次数
        scores = {
            Scope.ISSUANCE: 0,
            Scope.VALIDATION: 0,
            Scope.PROCESSING: 0,
            Scope.REVOCATION: 0,
        }

        # 检测签发
        for pattern in self._issuance_patterns:
            scores[Scope.ISSUANCE] += len(pattern.findall(text))

        # 检测验证
        for pattern in self._validation_patterns:
            scores[Scope.VALIDATION] += len(pattern.findall(text))

        # 检测处理
        for pattern in self._processing_patterns:
            scores[Scope.PROCESSING] += len(pattern.findall(text))

        # 检测撤销
        for pattern in self._revocation_patterns:
            scores[Scope.REVOCATION] += len(pattern.findall(text))

        # 基于章节号的启发式判断
        if section:
            section_lower = section.lower()
            if any(kw in section_lower for kw in ['issuance', 'issuing', 'ca']):
                scores[Scope.ISSUANCE] += 2
            elif any(kw in section_lower for kw in ['validation', 'verify', 'rp']):
                scores[Scope.VALIDATION] += 2
            elif any(kw in section_lower for kw in ['crl', 'ocsp', 'revoc']):
                scores[Scope.REVOCATION] += 2

        # 返回得分最高的范围
        max_score = max(scores.values())
        if max_score == 0:
            return Scope.GENERAL

        for scope, score in scores.items():
            if score == max_score:
                return scope

        return Scope.GENERAL

    def extract_spec_id(self, text: str) -> Optional[str]:
        """
        从文本中提取规范 ID

        Args:
            text: 输入文本

        Returns:
            规范 ID（如 "RFC5280"）或 None
        """
        # 尝试提取 RFC 编号
        rfc_match = re.search(r'\bRFC\s*(\d+)\b', text, re.IGNORECASE)
        if rfc_match:
            return f"RFC{rfc_match.group(1)}"

        # 尝试提取 ETSI 编号
        etsi_match = re.search(r'\bETSI\s+(EN|TS|TR)\s+(\d+)\b', text, re.IGNORECASE)
        if etsi_match:
            return f"ETSI-{etsi_match.group(1)}-{etsi_match.group(2)}"

        return None

    def load_context(self, spec_id: str) -> Optional[SpecContext]:
        """
        加载规范上下文

        Args:
            spec_id: 规范 ID（如 "RFC5280"）

        Returns:
            SpecContext 或 None
        """
        # 检查缓存
        if spec_id in self._context_cache:
            return self._context_cache[spec_id]

        # 确定规范体系
        spec_family = self._infer_family_from_id(spec_id)

        # 创建上下文
        context = SpecContext(
            spec_family=spec_family,
            spec_id=spec_id,
        )

        # 从知识图谱加载定义（如果可用）
        if self.kg:
            definitions = self._load_definitions_from_kg(spec_id)
            context.definitions = definitions

        # 缓存
        self._context_cache[spec_id] = context

        return context

    def _infer_family_from_id(self, spec_id: str) -> SpecFamily:
        """从规范 ID 推断规范体系"""
        spec_id_upper = spec_id.upper()

        if spec_id_upper.startswith("RFC"):
            return SpecFamily.RFC
        elif spec_id_upper.startswith("CABF") or spec_id_upper.startswith("BR"):
            return SpecFamily.CABF
        elif spec_id_upper.startswith("ETSI"):
            return SpecFamily.ETSI
        elif "MOZILLA" in spec_id_upper:
            return SpecFamily.MOZILLA
        elif "APPLE" in spec_id_upper:
            return SpecFamily.APPLE
        elif "CHROME" in spec_id_upper:
            return SpecFamily.CHROME
        else:
            return SpecFamily.OTHER

    def _load_definitions_from_kg(self, spec_id: str) -> Dict[str, str]:
        """从知识图谱加载定义"""
        if not self.kg:
            return {}

        definitions = {}

        # 查找规范节点
        spec_node_id = f"spec:{spec_id}"
        spec_node = self.kg.get_node(spec_node_id)

        if not spec_node:
            return {}

        # 获取定义邻居
        neighbors = self.kg.get_neighbors(
            spec_node_id,
            relation_type="DEFINES",
            direction="out"
        )

        for neighbor_id, neighbor_data in neighbors:
            if neighbor_data.get("node_type") == "Definition":
                props = neighbor_data.get("properties", {})
                term = props.get("term", "")
                definition = props.get("definition", "")
                if term and definition:
                    definitions[term] = definition

        return definitions

    def get_minimal_context(
        self,
        text: str,
        max_tokens: int = 2000,
        source_text: Optional[str] = None
    ) -> str:
        """
        获取最小上下文（用于 LLM 提示词）

        Args:
            text: 输入文本
            max_tokens: 最大 token 数（粗略估计）
            source_text: 可选的源文档全文，用于基于关键词的文本检索（模拟向量RAG）

        Returns:
            格式化的上下文字符串
        """
        # 检测规范体系
        spec_family = self.detect_spec_family(text)

        # 提取规范 ID
        spec_id = self.extract_spec_id(text)

        # 加载上下文
        context = None
        if spec_id:
            context = self.load_context(spec_id)

        # 构建上下文字符串
        parts = []

        parts.append(f"Specification Family: {spec_family.value}")

        if spec_id:
            parts.append(f"Specification ID: {spec_id}")

        if context and context.definitions:
            parts.append("\nRelevant Definitions:")
            # 限制定义数量以符合 token 预算
            for i, (term, definition) in enumerate(context.definitions.items()):
                if i >= 5:  # 最多 5 个定义
                    break
                parts.append(f"- {term}: {definition[:200]}...")

        # 基于关键词的文本检索（模拟向量RAG）
        if source_text and not (context and context.definitions):
            retrieved = self._keyword_retrieve(text, source_text, max_tokens=max_tokens)
            if retrieved:
                parts.append("\nRelevant passages from specification:")
                parts.append(retrieved)

        return "\n".join(parts)

    def _keyword_retrieve(
        self,
        query: str,
        source_text: str,
        max_tokens: int = 2000
    ) -> str:
        """
        基于关键词重叠的文本检索，模拟向量RAG行为。

        将源文档分段，按关键词重叠度排序，返回最相关的段落。

        Args:
            query: 查询文本（规范句子）
            source_text: 源文档全文
            max_tokens: 最大token预算（粗略按4字符/token估计）

        Returns:
            检索到的相关段落文本
        """
        # 提取查询关键词（去除停用词和短词）
        stopwords = {
            'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
            'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
            'shall', 'should', 'may', 'must', 'can', 'could', 'would',
            'of', 'in', 'to', 'for', 'with', 'on', 'at', 'by', 'from',
            'as', 'into', 'through', 'during', 'before', 'after', 'and',
            'but', 'or', 'not', 'no', 'if', 'then', 'that', 'this',
            'these', 'those', 'it', 'its', 'each', 'such', 'when',
        }

        query_words = set()
        for word in re.split(r'[\s,;:.()\[\]{}]+', query.lower()):
            if len(word) > 2 and word not in stopwords:
                query_words.add(word)

        if not query_words:
            return ""

        # 将源文档分成段落（按双换行或单换行+缩进分割）
        paragraphs = re.split(r'\n\s*\n', source_text)
        paragraphs = [p.strip() for p in paragraphs if len(p.strip()) > 30]

        # 计算每个段落的关键词重叠得分
        scored = []
        for para in paragraphs:
            para_lower = para.lower()
            para_words = set(re.split(r'[\s,;:.()\[\]{}]+', para_lower))
            overlap = len(query_words & para_words)
            # 加权：对技术术语（长词）给更高权重
            weighted = sum(
                2 if len(w) > 6 else 1
                for w in query_words
                if w in para_lower
            )
            if weighted > 0:
                scored.append((weighted, para))

        # 按得分降序排列
        scored.sort(key=lambda x: x[0], reverse=True)

        # 拼接直到达到token预算
        max_chars = max_tokens * 4  # 粗略估计
        result_parts = []
        char_count = 0

        for score, para in scored[:5]:  # 最多5个段落
            if char_count + len(para) > max_chars:
                break
            result_parts.append(para)
            char_count += len(para)

        return "\n\n".join(result_parts)


# 便捷函数
def detect_spec_family(text: str) -> SpecFamily:
    """检测规范体系"""
    manager = SpecificationContextManager()
    return manager.detect_spec_family(text)


def get_applicable_scope(text: str, section: Optional[str] = None) -> Scope:
    """获取适用范围"""
    manager = SpecificationContextManager()
    return manager.get_applicable_scope(text, section)
