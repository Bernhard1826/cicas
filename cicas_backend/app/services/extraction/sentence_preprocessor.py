"""
句子预处理器 (Sentence Preprocessor)

职责：
1. 做轻量预清理
2. 识别明显的多规则候选片段供上游参考
3. 保留 provenance 关系

设计原则：
- RuleDiscovery 负责 assertion 原子性
- 这里不保证 one-call = one-rule
- 仅提供保守的候选切分，避免破坏 assertion cardinality
"""
import re
from typing import List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .chunk_types import REQUIREMENT_KEYWORD_PHRASES, REQUIREMENT_KEYWORD_REGEX


class SplitReason(str, Enum):
    """拆分原因"""
    MULTIPLE_MODAL_VERBS = "multiple_modal_verbs"  # 多个情态动词
    CONJUNCTION_SPLIT = "conjunction_split"        # 连词拆分
    SEMICOLON_SPLIT = "semicolon_split"           # 分号拆分
    ENUMERATION_SPLIT = "enumeration_split"       # 枚举拆分


@dataclass
class AtomicSentence:
    """轻量候选片段，不保证最终 assertion 原子性"""
    text: str
    original_text: str
    original_index: int  # 在原始句子中的位置
    split_reason: Optional[SplitReason] = None
    provenance: Optional[dict] = None


@dataclass
class PreprocessResult:
    """预处理结果（候选片段级）"""
    original_text: str
    needs_split: bool
    sentences: List[AtomicSentence]
    split_reason: Optional[SplitReason] = None


class SentencePreprocessor:
    """
    句子预处理器

    检测多规则句子并拆分为原子句子。
    保持"一次调用 = 一条 IR"的原则。
    """

    MODAL_KEYWORDS = [kw for kw in REQUIREMENT_KEYWORD_PHRASES if kw != "OPTIONAL"]
    MODAL_PATTERN = r'\b(?:' + '|'.join(re.escape(keyword) for keyword in MODAL_KEYWORDS) + r')\b'

    # 连词模式（用于拆分）
    CONJUNCTIONS = [
        r'\s+and\s+',
        r'\s+or\s+',
        r';\s*and\s+',
        r';\s*or\s+',
    ]

    # 拆分点模式
    SPLIT_PATTERNS = [
        (rf';\s*(?=(?:(?i:the|each|such|these|those|this)\s+)?(?:certificate|certificates|extension|extensions|field|fields|ca|cas|issuer|issuers|subject|subjects|implementations?|relying\s+part(?:y|ies)|attributes?|entries?|values?)?\s*{MODAL_PATTERN})',
         SplitReason.SEMICOLON_SPLIT),
        (rf',?\s+and\s+(?=(?:(?i:the|each|such|these|those|this)\s+)?(?:certificate|certificates|extension|extensions|field|fields|ca|cas|issuer|issuers|subject|subjects|implementations?|relying\s+part(?:y|ies)|attributes?|entries?|values?)?\s*{MODAL_PATTERN})',
         SplitReason.CONJUNCTION_SPLIT),
        (rf'\.\s+(?=(?:(?i:the|each|such|these|those|this)\s+)?(?:certificate|certificates|extension|extensions|field|fields|ca|cas|issuer|issuers|subject|subjects|implementations?|relying\s+part(?:y|ies)|attributes?|entries?|values?)?\s*{MODAL_PATTERN})',
         SplitReason.ENUMERATION_SPLIT),
    ]

    def __init__(self):
        # 编译情态动词正则
        self.modal_pattern = re.compile(self.MODAL_PATTERN, re.IGNORECASE)
        self.requirement_keyword_regex = REQUIREMENT_KEYWORD_REGEX

    def detect_needs_split(self, text: str) -> Tuple[bool, Optional[SplitReason]]:
        """
        检测句子是否需要拆分

        Args:
            text: 输入文本

        Returns:
            (needs_split, split_reason)
        """
        # 查找所有情态动词
        matches = list(self.modal_pattern.finditer(text))

        if len(matches) <= 1:
            return False, None

        # 检查情态动词是否在不同的子句中
        separators = [';', ' and ', ' or ', '. ']

        for i in range(len(matches) - 1):
            start = matches[i].end()
            end = matches[i + 1].start()
            between = text[start:end].lower()

            for sep in separators:
                if sep in between:
                    return True, SplitReason.MULTIPLE_MODAL_VERBS

        return False, None

    def split_multi_requirement_sentence(self, text: str) -> PreprocessResult:
        """
        拆分多规则句子

        Args:
            text: 输入文本

        Returns:
            PreprocessResult 包含拆分后的原子句子
        """
        needs_split, split_reason = self.detect_needs_split(text)

        if not needs_split:
            # 不需要拆分，返回原句
            return PreprocessResult(
                original_text=text,
                needs_split=False,
                sentences=[
                    AtomicSentence(
                        text=text.strip(),
                        original_text=text,
                        original_index=0
                    )
                ]
            )

        # 尝试拆分
        sentences = self._split_sentence(text)

        if len(sentences) <= 1:
            # 拆分失败，返回原句
            return PreprocessResult(
                original_text=text,
                needs_split=True,
                sentences=[
                    AtomicSentence(
                        text=text.strip(),
                        original_text=text,
                        original_index=0,
                        split_reason=split_reason
                    )
                ],
                split_reason=split_reason
            )

        # 拆分成功
        return PreprocessResult(
            original_text=text,
            needs_split=True,
            sentences=sentences,
            split_reason=split_reason
        )

    def _split_sentence(self, text: str) -> List[AtomicSentence]:
        """
        执行句子拆分

        拆分策略：
        1. 首先尝试分号拆分
        2. 然后尝试连词拆分
        3. 每个片段必须包含情态动词才被保留
        """
        sentences = []

        # 策略1: 分号拆分
        parts = self._split_by_semicolon(text)
        if len(parts) > 1:
            for i, part in enumerate(parts):
                if self._contains_modal_verb(part):
                    sentences.append(AtomicSentence(
                        text=self._clean_fragment(part),
                        original_text=text,
                        original_index=i,
                        split_reason=SplitReason.SEMICOLON_SPLIT
                    ))
            if len(sentences) > 1:
                return sentences

        # 策略2: 连词拆分（"and" + 情态动词）
        parts = self._split_by_conjunction(text)
        if len(parts) > 1:
            sentences = []
            for i, part in enumerate(parts):
                if self._contains_modal_verb(part):
                    sentences.append(AtomicSentence(
                        text=self._clean_fragment(part),
                        original_text=text,
                        original_index=i,
                        split_reason=SplitReason.CONJUNCTION_SPLIT
                    ))
            if len(sentences) > 1:
                return sentences

        # 策略3: 句号拆分（多个独立句子）
        parts = self._split_by_period(text)
        if len(parts) > 1:
            sentences = []
            for i, part in enumerate(parts):
                if self._contains_modal_verb(part):
                    sentences.append(AtomicSentence(
                        text=self._clean_fragment(part),
                        original_text=text,
                        original_index=i,
                        split_reason=SplitReason.ENUMERATION_SPLIT
                    ))
            if len(sentences) > 1:
                return sentences

        # 无法拆分
        return []

    def _split_by_semicolon(self, text: str) -> List[str]:
        """按分号拆分"""
        parts = re.split(r';\s*(?:and\s+|or\s+)?', text, flags=re.IGNORECASE)
        return [p.strip() for p in parts if p.strip()]

    def _split_by_conjunction(self, text: str) -> List[str]:
        """按连词拆分（仅当后面跟情态动词时）"""
        pattern = rf',?\s+and\s+(?=(?:(?:the|each|such|these|those|this)\s+)?(?:certificate|certificates|extension|extensions|field|fields|ca|cas|issuer|issuers|subject|subjects|implementations?|relying\s+part(?:y|ies)|attributes?|entries?|values?)?\s*{self.MODAL_PATTERN})'
        parts = re.split(pattern, text, flags=re.IGNORECASE)
        return [p.strip() for p in parts if p.strip()]

    def _split_by_period(self, text: str) -> List[str]:
        """按句号拆分（但保留缩写中的句号）"""
        parts = re.split(r'\.\s+(?=[A-Za-z])', text)
        return [p.strip() for p in parts if p.strip()]

    def _contains_modal_verb(self, text: str) -> bool:
        """检查文本是否包含情态动词"""
        return bool(self.modal_pattern.search(text))

    def _clean_fragment(self, text: str) -> str:
        """清理片段文本"""
        text = text.strip()
        text = re.sub(r'^(?:and|or|but)\s+', '', text, flags=re.IGNORECASE)
        if text and text[0].islower():
            text = text[0].upper() + text[1:]
        return text

    def preprocess(self, text: str, provenance: Optional[dict] = None) -> PreprocessResult:
        """
        预处理文本

        Args:
            text: 输入文本
            provenance: 来源信息（可选）

        Returns:
            PreprocessResult
        """
        result = self.split_multi_requirement_sentence(text)

        # 附加 provenance 到每个原子句子
        if provenance:
            for i, sentence in enumerate(result.sentences):
                sentence.provenance = {
                    **provenance,
                    "sentence_index": i,
                    "original_text": text,
                    "is_split": result.needs_split
                }

        return result


def preprocess_normative_text(
    text: str,
    provenance: Optional[dict] = None
) -> List[AtomicSentence]:
    """
    便捷函数：预处理规范文本

    Args:
        text: 输入文本
        provenance: 来源信息

    Returns:
        原子句子列表
    """
    preprocessor = SentencePreprocessor()
    result = preprocessor.preprocess(text, provenance)
    return result.sentences


def needs_split(text: str) -> bool:
    """
    便捷函数：检测是否需要拆分

    Args:
        text: 输入文本

    Returns:
        是否需要拆分
    """
    preprocessor = SentencePreprocessor()
    needs, _ = preprocessor.detect_needs_split(text)
    return needs
