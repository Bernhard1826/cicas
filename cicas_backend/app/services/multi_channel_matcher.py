"""
多通道PKI规则匹配引擎

实现5个独立通道来评估规则原文与zlint description的匹配度：
1. Semantic Score - 语义嵌入相似度
2. Logic Structure Score - 逻辑结构对齐
3. Field Alignment Score - 字段对齐
4. Rule Class Score - 规则类型分类一致性
5. Citation Score - 引用/OID/章节对齐
"""
import json
import re
from typing import Dict, List, Any, Tuple, Optional
from sqlalchemy.orm import Session
import numpy as np
from openai import OpenAI
import httpx

from app.core.logging_config import app_logger
from app.core.config import settings


class MultiChannelMatcher:
    """
    多通道PKI规则匹配器

    实现严格的多通道融合匹配，确保：
    - 原文最高优先级
    - zlint description 不能覆盖原文
    - 不得臆造规则或扩展原文不存在的内容
    """

    # PKI专用字段词表
    PKI_FIELDS = {
        "subjectAltName": ["subjectaltname", "san", "subject alternative name"],
        "dNSName": ["dnsname", "dns name", "dns"],
        "CN": ["cn", "common name", "commonname"],
        "validity": ["validity", "validity period", "notbefore", "notafter"],
        "keyUsage": ["keyusage", "key usage"],
        "extendedKeyUsage": ["extendedkeyusage", "extended key usage", "eku"],
        "nameConstraints": ["nameconstraints", "name constraints"],
        "basicConstraints": ["basicconstraints", "basic constraints"],
        "certificatePolicies": ["certificatepolicies", "certificate policies"],
        "serialNumber": ["serialnumber", "serial number"],
    }

    # 规则类型分类
    RULE_CLASSES = [
        "Required Field Rule",
        "Forbidden Field Rule",
        "Format Rule",
        "Length Rule",
        "Date Rule",
        "Equality Rule",
        "OID Presence",
        "NameConstraints Rule",
        "SAN Rule",
        "CN Rule",
        "Others"
    ]

    # 逻辑结构关键词
    LOGIC_KEYWORDS = {
        "must_contain": ["must contain", "shall contain", "required to contain"],
        "must_not_contain": ["must not contain", "shall not", "prohibited", "forbidden"],
        "format_regex": ["format must", "must match", "conform to"],
        "if_then": ["if", "when", "where"],
        "length": ["length", "at least", "minimum", "maximum"],
        "equals": ["must equal", "must be", "shall be"],
    }

    def __init__(self, db: Session):
        self.db = db

        # 初始化embedding客户端
        try:
            http_client = httpx.Client(trust_env=False, timeout=60.0)
            self.client = OpenAI(
                api_key=settings.embedding_api_key,
                base_url=settings.embedding_api_base,
                http_client=http_client
            )
            self.embedding_model = settings.embedding_model
            self.available = True
        except Exception as e:
            app_logger.error(f"Failed to initialize embedding client: {e}")
            self.available = False

    def match_rule_to_zlint(
        self,
        rule_original_text: str,
        zlint_descriptions: List[Dict[str, str]],
        rule_source_document: str,
        rule_source_section: Optional[str] = None,
        top_k: int = 10
    ) -> List[Dict[str, Any]]:
        """
        将规则原文与zlint descriptions进行多通道匹配

        Args:
            rule_original_text: 规则原文
            zlint_descriptions: zlint descriptions列表 [{description, lint_name, citation}]
            rule_source_document: 规则来源文档（如RFC5280）
            rule_source_section: 规则章节号
            top_k: 返回前k个匹配结果

        Returns:
            匹配结果列表，按final_score降序排列
        """
        if not self.available:
            app_logger.error("MultiChannelMatcher not available")
            return []

        app_logger.info(f"Matching rule from {rule_source_document} against {len(zlint_descriptions)} zlint descriptions")

        results = []

        for zlint_desc in zlint_descriptions:
            description = zlint_desc.get("description", "")
            lint_name = zlint_desc.get("lint_name", "")
            citation = zlint_desc.get("citation", "")

            if not description:
                continue

            # 计算5个通道的评分
            semantic_score = self._calculate_semantic_score(rule_original_text, description)
            logic_structure_score = self._calculate_logic_structure_score(rule_original_text, description)
            field_alignment_score = self._calculate_field_alignment_score(rule_original_text, description)
            rule_class_score = self._calculate_rule_class_score(rule_original_text, description)
            citation_score = self._calculate_citation_score(
                rule_source_document, rule_source_section, citation, description
            )

            # 综合评分（可配置权重）
            final_score = (
                0.25 * semantic_score +
                0.30 * logic_structure_score +
                0.20 * field_alignment_score +
                0.15 * rule_class_score +
                0.10 * citation_score
            )

            # 判断对齐等级
            alignment_level = self._determine_alignment_level(final_score, {
                "semantic": semantic_score,
                "logic": logic_structure_score,
                "field": field_alignment_score,
                "class": rule_class_score,
                "citation": citation_score
            })

            # 检测冲突
            has_conflict, conflict_notes = self._detect_conflicts(rule_original_text, description)

            # 生成推理说明
            reasoning = self._generate_reasoning(
                semantic_score, logic_structure_score, field_alignment_score,
                rule_class_score, citation_score, alignment_level
            )

            result = {
                "zlint_description": description,
                "lint_name": lint_name,
                "zlint_citation": citation,
                "analysis": {
                    "semantic_score": round(semantic_score, 4),
                    "logic_structure_score": round(logic_structure_score, 4),
                    "field_alignment_score": round(field_alignment_score, 4),
                    "rule_class_score": round(rule_class_score, 4),
                    "citation_score": round(citation_score, 4),
                    "final_score": round(final_score, 4)
                },
                "alignment_level": alignment_level,
                "has_conflict": has_conflict,
                "conflict_notes": conflict_notes,
                "reasoning": reasoning
            }

            results.append(result)

        # 按final_score降序排列
        results.sort(key=lambda x: x["analysis"]["final_score"], reverse=True)

        # 标记最佳匹配
        if results:
            results[0]["is_best_match"] = True

        # 返回top_k结果
        return results[:top_k]

    def _calculate_semantic_score(self, text1: str, text2: str) -> float:
        """
        通道1: 计算语义嵌入相似度
        """
        try:
            # 获取embeddings
            response1 = self.client.embeddings.create(
                input=text1,
                model=self.embedding_model
            )
            embedding1 = np.array(response1.data[0].embedding)

            response2 = self.client.embeddings.create(
                input=text2,
                model=self.embedding_model
            )
            embedding2 = np.array(response2.data[0].embedding)

            # 计算余弦相似度
            similarity = np.dot(embedding1, embedding2) / (
                np.linalg.norm(embedding1) * np.linalg.norm(embedding2)
            )

            # 归一化到0-1
            return max(0.0, min(1.0, (similarity + 1) / 2))

        except Exception as e:
            app_logger.warning(f"Failed to calculate semantic score: {e}")
            return 0.0

    def _calculate_logic_structure_score(self, text1: str, text2: str) -> float:
        """
        通道2: 计算逻辑结构对齐分数

        对比两段文本的逻辑结构：
        - Must contain
        - Must not contain
        - Format must match
        - If A then B
        - Length constraints
        - Equality constraints
        """
        text1_lower = text1.lower()
        text2_lower = text2.lower()

        # 提取逻辑结构
        structure1 = self._extract_logic_structure(text1_lower)
        structure2 = self._extract_logic_structure(text2_lower)

        # 计算结构匹配度
        if not structure1 and not structure2:
            return 0.5  # 都没有明确结构

        if not structure1 or not structure2:
            return 0.0  # 一个有结构一个没有

        # 计算重叠率
        common_structures = set(structure1.keys()) & set(structure2.keys())
        all_structures = set(structure1.keys()) | set(structure2.keys())

        if not all_structures:
            return 0.5

        overlap_ratio = len(common_structures) / len(all_structures)

        # 对每个共同的结构类型，比较其内容
        content_similarity = 0.0
        if common_structures:
            for struct_type in common_structures:
                val1 = structure1[struct_type]
                val2 = structure2[struct_type]
                # 简单的词集合重叠度
                words1 = set(val1.split())
                words2 = set(val2.split())
                if words1 or words2:
                    content_similarity += len(words1 & words2) / len(words1 | words2)
            content_similarity /= len(common_structures)

        # 综合评分
        score = 0.6 * overlap_ratio + 0.4 * content_similarity
        return max(0.0, min(1.0, score))

    def _extract_logic_structure(self, text: str) -> Dict[str, str]:
        """提取文本的逻辑结构"""
        structure = {}

        for logic_type, keywords in self.LOGIC_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    # 提取关键词后的内容作为该结构的值
                    idx = text.find(keyword)
                    snippet = text[idx:idx+100]  # 取后100个字符
                    structure[logic_type] = snippet
                    break

        return structure

    def _calculate_field_alignment_score(self, text1: str, text2: str) -> float:
        """
        通道3: 计算字段对齐分数

        优先级极高。根据PKI专用词表对比字段。
        """
        text1_lower = text1.lower()
        text2_lower = text2.lower()

        # 提取两段文本中的字段
        fields1 = self._extract_pki_fields(text1_lower)
        fields2 = self._extract_pki_fields(text2_lower)

        if not fields1 and not fields2:
            return 0.5  # 都没有明确字段 -> 中等分

        if not fields1 or not fields2:
            return 0.0  # 一个有字段一个没有 -> 低分

        # 计算字段重叠
        common_fields = fields1 & fields2
        all_fields = fields1 | fields2

        if not all_fields:
            return 0.5

        # 字段一致 -> 高分
        # 字段相关（如SAN与dNSName） -> 中等分
        # 字段无关 -> 低分
        overlap_ratio = len(common_fields) / len(all_fields)

        # 检查相关字段
        related_bonus = 0.0
        if "subjectAltName" in fields1 and "dNSName" in fields2:
            related_bonus = 0.3
        elif "dNSName" in fields1 and "subjectAltName" in fields2:
            related_bonus = 0.3

        score = overlap_ratio + related_bonus
        return max(0.0, min(1.0, score))

    def _extract_pki_fields(self, text: str) -> set:
        """从文本中提取PKI字段"""
        found_fields = set()

        for field_name, aliases in self.PKI_FIELDS.items():
            for alias in aliases:
                if alias in text:
                    found_fields.add(field_name)
                    break

        return found_fields

    def _calculate_rule_class_score(self, text1: str, text2: str) -> float:
        """
        通道4: 计算规则类型分类一致性分数

        将两段文本分类为规则类型，分类一致 -> 高分，不一致 -> 低分
        """
        class1 = self._classify_rule_type(text1.lower())
        class2 = self._classify_rule_type(text2.lower())

        if class1 == class2:
            return 1.0  # 分类一致

        # 某些类型是相关的
        related_classes = {
            ("SAN Rule", "NameConstraints Rule"),
            ("CN Rule", "SAN Rule"),
            ("Required Field Rule", "Format Rule"),
        }

        if (class1, class2) in related_classes or (class2, class1) in related_classes:
            return 0.5  # 相关类型

        return 0.0  # 分类不一致

    def _classify_rule_type(self, text: str) -> str:
        """将规则文本分类"""
        # 简单的基于关键词的分类
        if any(kw in text for kw in ["must contain", "required", "shall contain"]):
            return "Required Field Rule"

        if any(kw in text for kw in ["must not", "shall not", "prohibited", "forbidden"]):
            return "Forbidden Field Rule"

        if any(kw in text for kw in ["format", "pattern", "regex", "match"]):
            return "Format Rule"

        if any(kw in text for kw in ["length", "at least", "minimum", "maximum"]):
            return "Length Rule"

        if any(kw in text for kw in ["date", "validity", "notbefore", "notafter"]):
            return "Date Rule"

        if any(kw in text for kw in ["must equal", "must be", "shall be"]):
            return "Equality Rule"

        if any(kw in text for kw in ["oid", "2.5.29"]):
            return "OID Presence"

        if "nameconstraints" in text or "name constraints" in text:
            return "NameConstraints Rule"

        if "subjectaltname" in text or "san" in text:
            return "SAN Rule"

        if "common name" in text or "cn" in text:
            return "CN Rule"

        return "Others"

    def _calculate_citation_score(
        self,
        rule_doc: str,
        rule_section: Optional[str],
        zlint_citation: str,
        zlint_description: str
    ) -> float:
        """
        通道5: 计算引用/OID/章节对齐分数

        这是最强"非语义"证据。
        """
        score = 0.0

        # 1. 检查文档匹配（如RFC5280）
        if rule_doc.lower() in zlint_citation.lower():
            score += 0.5

        # 2. 检查章节号匹配
        if rule_section and rule_section in zlint_citation:
            score += 0.3

        # 3. 检查OID匹配
        oid_pattern = r'\b\d+\.\d+\.\d+(\.\d+)*\b'
        rule_oids = set(re.findall(oid_pattern, rule_doc + (rule_section or "")))
        zlint_oids = set(re.findall(oid_pattern, zlint_citation + zlint_description))

        if rule_oids and zlint_oids:
            common_oids = rule_oids & zlint_oids
            if common_oids:
                score += 0.2

        return max(0.0, min(1.0, score))

    def _determine_alignment_level(self, final_score: float, scores: Dict[str, float]) -> str:
        """
        根据综合评分和各通道评分判断对齐等级
        """
        if final_score >= 0.85:
            # 检查是否所有关键通道都高分
            if scores["field"] >= 0.7 and scores["logic"] >= 0.7:
                return "full"

        if final_score >= 0.65:
            return "partial"

        if final_score >= 0.40:
            return "weak"

        return "none"

    def _detect_conflicts(self, text1: str, text2: str) -> Tuple[bool, Optional[str]]:
        """
        检测两段文本是否存在冲突

        冲突的定义：
        - 一个说must，另一个说must not
        - 字段要求不一致
        - 数值要求冲突
        """
        text1_lower = text1.lower()
        text2_lower = text2.lower()

        # 检测must vs must not
        has_must_1 = "must" in text1_lower and "must not" not in text1_lower
        has_must_not_1 = "must not" in text1_lower
        has_must_2 = "must" in text2_lower and "must not" not in text2_lower
        has_must_not_2 = "must not" in text2_lower

        if (has_must_1 and has_must_not_2) or (has_must_not_1 and has_must_2):
            return True, "Conflicting requirements: one says 'must', the other says 'must not'"

        # 检测字段冲突
        fields1 = self._extract_pki_fields(text1_lower)
        fields2 = self._extract_pki_fields(text2_lower)

        if fields1 and fields2 and not (fields1 & fields2):
            # 字段完全不重叠
            return True, f"Different fields: {fields1} vs {fields2}"

        return False, None

    def _generate_reasoning(
        self,
        semantic: float,
        logic: float,
        field: float,
        rule_class: float,
        citation: float,
        alignment: str
    ) -> str:
        """生成匹配推理说明"""
        reasons = []

        if semantic >= 0.8:
            reasons.append("High semantic similarity")
        elif semantic < 0.3:
            reasons.append("Low semantic similarity")

        if logic >= 0.8:
            reasons.append("Strong logic structure alignment")
        elif logic < 0.3:
            reasons.append("Weak logic structure alignment")

        if field >= 0.8:
            reasons.append("Excellent field matching")
        elif field < 0.3:
            reasons.append("Poor field matching")

        if rule_class >= 0.9:
            reasons.append("Same rule classification")

        if citation >= 0.7:
            reasons.append("Strong citation evidence")

        if not reasons:
            reasons.append("Moderate alignment across all channels")

        return f"{alignment.upper()} alignment: " + "; ".join(reasons)
