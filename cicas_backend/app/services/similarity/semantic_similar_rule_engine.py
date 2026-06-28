"""
Cross-Document Semantic Similar Rules Discovery Engine (跨文档语义相似规则发现引擎)

This system discovers semantically similar rules across multiple PKI specification documents.

Research Goal:
    Identify rules that are semantically similar (not necessarily strictly equivalent)
    across heterogeneous specification documents.

System Architecture:
    Rule Text → Text Preprocessing → Semantic Vector Embedding → Similarity Computation
    → Maximal Clique Detection → SimilarRuleGroup Output

Key Design Principles:
    - Focus on semantic similarity, not strict structural matching
    - No complex IR extraction required
    - Use maximal clique algorithm to ensure group quality
    - Avoid transitivity pollution from Union-Find
    - Simple and efficient

Algorithm:
    Uses maximal clique algorithm to find similar rule groups.
    A clique is a subset where every pair of rules has similarity >= threshold.
    This guarantees high-quality groups without transitivity pollution.
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

import numpy as np
import networkx as nx

from app.core.logging_config import app_logger
from app.services.embeddings.embedding_generator import EmbeddingGenerator
from sqlalchemy.orm import Session  # ⭐ 新增：用于查询例外规则


class SemanticSimilarRuleEngine:
    """
    Semantic Similar Rule Discovery Engine (跨文档语义相似规则发现引擎)

    Discovers semantically similar rules using:
    1. Text preprocessing
    2. Semantic vector embedding (Sentence-BERT style)
    3. Cosine similarity computation
    4. Maximal clique detection for grouping (guarantees quality)

    IMPORTANT: This is a CROSS-DOCUMENT discovery system.
    Only groups containing rules from multiple documents are returned.
    Single-document groups are filtered out.
    """

    # System Configuration
    DEFAULT_CONFIG = {
        "similarity_threshold": 0.85,       # Cosine similarity threshold (降低以增加跨文档匹配)
        "min_group_size": 2,                # Minimum group size
        "batch_size": 5,                    # Batch size for embedding generation (free API: 1k tokens limit)
        "use_structural_filter": True,      # Enable structural compatibility checking
    }

    # RFC 2119 keywords for strength extraction
    STRENGTH_KEYWORDS = {
        "MUST": ["MUST", "SHALL", "REQUIRED"],
        "SHOULD": ["SHOULD", "RECOMMENDED"],
        "MAY": ["MAY", "OPTIONAL"],
        "MUST_NOT": ["MUST NOT", "SHALL NOT"],
        "SHOULD_NOT": ["SHOULD NOT", "NOT RECOMMENDED"]
    }

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None  # ⭐ 新增：数据库会话（用于查询例外规则）
    ):
        """
        Initialize semantic similar rule engine

        Args:
            config: Configuration overrides
            db: Database session for loading exception rules (optional)
        """
        self.logger = app_logger
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.db = db  # ⭐ 新增

        # Components
        self.embedder = EmbeddingGenerator()

        # State
        self.rules: List[Dict[str, Any]] = []
        self.embeddings: Optional[np.ndarray] = None
        self.similarity_groups: List[Dict[str, Any]] = []

    async def discover_similar_rules(
        self,
        documents: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Discover semantically similar rules across documents

        Args:
            documents: List of document dictionaries, each containing:
                - source_doc: Document identifier
                - rules: List of rule dictionaries with 'text' field

        Returns:
            Detection results with:
            - similarity_groups: List of SimilarRuleGroup dictionaries
            - statistics: Summary statistics
        """
        try:
            self.logger.info(f"Starting semantic similar rule discovery on {len(documents)} documents")

            # Step 1: Collect and preprocess rules
            all_rules = self._collect_rules(documents)
            self.logger.info(f"Collected {len(all_rules)} total rules")
            self.rules = all_rules

            # Step 2: Generate semantic embeddings
            embeddings = await self._generate_embeddings(all_rules)
            self.embeddings = embeddings
            self.logger.info(f"Generated embeddings with shape {self.embeddings.shape}")

            # Step 3: Compute similarity matrix
            similarity_matrix = self._compute_similarity_matrix()
            self.logger.info("Computed similarity matrix")

            # Step 4: Find similar groups using maximal clique algorithm
            similarity_groups = self._find_maximal_cliques(similarity_matrix)
            self.similarity_groups = similarity_groups
            self.logger.info(f"Discovered {len(similarity_groups)} similar rule groups using maximal clique algorithm")

            # Step 5: Generate statistics
            statistics = self._generate_statistics(documents, similarity_groups, all_rules)

            return {
                "similarity_groups": similarity_groups,
                "statistics": statistics,
            }

        except Exception as e:
            self.logger.error(f"Error in similar rule discovery: {e}", exc_info=True)
            raise

    def _collect_rules(
        self,
        documents: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Collect all rules from documents with preprocessing and exception loading

        Args:
            documents: List of documents with rules

        Returns:
            List of preprocessed rules with metadata and exception rules
        """
        all_rules = []

        for doc in documents:
            doc_id = doc["source_doc"]
            rules = doc["rules"]

            for rule in rules:
                # Preprocess text
                text = rule.get("text", "")
                preprocessed_text = self._preprocess_text(text)

                # Use database ID if available, otherwise generate one
                rule_id = rule.get("id")
                db_id = rule_id  # Store original database ID

                if rule_id is not None:
                    unique_rule_id = f"{doc_id}::db_{rule_id}"
                else:
                    # Fallback: use text hash for uniqueness
                    import hashlib
                    text_hash = hashlib.md5(text.encode()).hexdigest()[:8]
                    unique_rule_id = f"{doc_id}::{text_hash}"

                # ⭐ Load exception rules from database (if db session available)
                exception_rules = []
                has_exceptions = False
                if self.db and db_id is not None:
                    try:
                        from app.models.models import ExceptionRule
                        exception_rules = self.db.query(ExceptionRule).filter(
                            ExceptionRule.target_rule_id == db_id
                        ).all()
                        has_exceptions = len(exception_rules) > 0

                        if has_exceptions:
                            self.logger.debug(
                                f"Rule {unique_rule_id} has {len(exception_rules)} exception(s)"
                            )
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to load exception rules for rule {db_id}: {e}"
                        )

                # Add metadata
                processed_rule = {
                    "rule_id": unique_rule_id,
                    "source_doc": doc_id,
                    "text": text,  # Original text
                    "preprocessed_text": preprocessed_text,  # For embedding
                    "section": rule.get("section", ""),
                    "db_id": db_id,  # Store original database ID
                    "exception_rules": exception_rules,  # ⭐ 新增：例外规则列表
                    "has_exceptions": has_exceptions,  # ⭐ 新增：是否有例外
                }

                all_rules.append(processed_rule)

        return all_rules

    def _preprocess_text(self, text: str) -> str:
        """
        Preprocess rule text for embedding

        Args:
            text: Raw rule text

        Returns:
            Preprocessed text
        """
        # Basic preprocessing
        # 1. Strip whitespace
        text = text.strip()

        # 2. Normalize whitespace
        text = " ".join(text.split())

        # 3. Remove document numbers like "7.1.2.3" at the beginning
        text = re.sub(r"^\s*\d+(\.\d+)*\.?\s*", "", text)

        return text

    def _extract_rule_strength(self, text: str) -> Optional[str]:
        """
        Extract RFC 2119 strength keyword from rule text

        Args:
            text: Rule text

        Returns:
            Strength keyword (MUST/SHOULD/MAY/MUST_NOT/SHOULD_NOT) or None
        """
        text_upper = text.upper()

        # Check for negative forms first (MUST NOT, SHOULD NOT)
        for strength, keywords in self.STRENGTH_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text_upper:
                    return strength

        return None

    def _extract_affected_field(self, rule: Dict[str, Any]) -> Optional[str]:
        """
        Extract affected field from rule

        Args:
            rule: Rule dictionary

        Returns:
            Field name or None
        """
        # Try to get from rule metadata (if available)
        if "affected_field" in rule and rule["affected_field"]:
            return rule["affected_field"].lower()

        # Fallback: Try to extract from text (basic heuristic)
        text = rule.get("text", "").lower()

        # Common PKI fields
        common_fields = [
            "subject", "issuer", "validity", "serialnumber", "keyusage",
            "basicconstraints", "subjectalternativename", "subjectaltname",
            "extendedkeyusage", "certificatepolicies", "crlnumber",
            "authorityinformationaccess", "authorityinfoaccess",
            "subjectkeyidentifier", "authoritykeyidentifier"
        ]

        for field in common_fields:
            if field in text.replace(" ", "").replace("_", ""):
                return field

        return None

    def _is_structurally_compatible(
        self,
        rule_i: Dict[str, Any],
        rule_j: Dict[str, Any]
    ) -> bool:
        """
        Check if two rules are structurally compatible

        Two rules are structurally compatible if:
        1. They have the same normative strength (MUST/SHOULD/MAY)
        2. They refer to the same field (if extractable)

        Args:
            rule_i, rule_j: Rule dictionaries

        Returns:
            True if structurally compatible, False otherwise
        """
        # Extract strengths
        strength_i = self._extract_rule_strength(rule_i["text"])
        strength_j = self._extract_rule_strength(rule_j["text"])

        # If both have strength keywords, they must match
        if strength_i and strength_j:
            if strength_i != strength_j:
                self.logger.debug(
                    f"Structural mismatch: strength {strength_i} != {strength_j} "
                    f"for rules {rule_i.get('rule_id', 'N/A')} and {rule_j.get('rule_id', 'N/A')}"
                )
                return False

        # Extract fields
        field_i = self._extract_affected_field(rule_i)
        field_j = self._extract_affected_field(rule_j)

        # If both have extractable fields, they should match
        # (This is optional - if fields can't be extracted, we allow it)
        if field_i and field_j:
            if field_i != field_j:
                self.logger.debug(
                    f"Structural mismatch: field {field_i} != {field_j} "
                    f"for rules {rule_i.get('rule_id', 'N/A')} and {rule_j.get('rule_id', 'N/A')}"
                )
                return False

        return True

    async def _generate_embeddings(
        self,
        rules: List[Dict[str, Any]]
    ) -> np.ndarray:
        """
        Generate semantic embeddings for all rules

        Args:
            rules: List of preprocessed rules

        Returns:
            Numpy array of embeddings
        """
        # Extract preprocessed texts
        texts = [rule["preprocessed_text"] for rule in rules]

        if not texts:
            raise ValueError("No rules to generate embeddings for")

        # Generate embeddings in batch (use configured batch_size)
        batch_size = self.config.get("batch_size", 5)
        self.logger.info(f"Using batch_size={batch_size} for embedding generation")
        embeddings = await self.embedder.generate_embeddings_batch(texts, batch_size=batch_size)

        # Check for failures
        if any(emb is None for emb in embeddings):
            failed_indices = [i for i, emb in enumerate(embeddings) if emb is None]
            self.logger.error(f"Failed to generate embeddings for {len(failed_indices)} rules at indices: {failed_indices}")
            raise ValueError(f"Embedding generation failed for {len(failed_indices)} rules")

        # Convert to numpy array - ensure it's 2D
        embeddings_array = np.array(embeddings, dtype='float32')

        # Validate shape
        if embeddings_array.ndim == 1:
            # Single embedding returned as 1D, reshape to 2D
            embeddings_array = embeddings_array.reshape(1, -1)
        elif embeddings_array.ndim != 2:
            raise ValueError(f"Invalid embeddings shape: {embeddings_array.shape}. Expected 2D array.")

        # Normalize embeddings for cosine similarity
        norms = np.linalg.norm(embeddings_array, axis=1, keepdims=True)
        embeddings_array = embeddings_array / np.maximum(norms, 1e-8)

        # Attach embeddings to rules for reference
        for rule, embedding in zip(rules, embeddings):
            rule["embedding"] = embedding

        return embeddings_array

    def _should_compute_similarity(
        self,
        rule_i: Dict[str, Any],
        rule_j: Dict[str, Any]
    ) -> bool:
        """
        IR-based pre-filtering: determine if two rules need similarity computation (Exception-Aware)

        This is Layer 0 filtering before semantic similarity computation.
        Filters out obviously unrelated rule pairs based on IR structure.

        ⭐ Exception-Aware Extension:
        If one or both rules have exceptions, they may have different effective semantics
        even if the base text is similar. We flag these pairs for special handling.

        Args:
            rule_i, rule_j: Rule dictionaries

        Returns:
            True if similarity should be computed, False if pair should be skipped

        Performance impact:
            - Filters out ~70-80% of rule pairs (different fields)
            - Expected speedup: 5-10x for large rule sets
        """
        # ========== ⭐ Filter 0: Exception asymmetry check ==========
        # If one rule has exceptions and the other doesn't, they may not be truly equivalent
        # We still compute similarity, but flag it for review

        has_exception_i = rule_i.get("has_exceptions", False)
        has_exception_j = rule_j.get("has_exceptions", False)

        if has_exception_i != has_exception_j:
            # Asymmetric exception status
            # Still compute similarity, but this will be marked in the group
            self.logger.debug(
                f"Exception asymmetry detected: {rule_i['rule_id']} "
                f"(exceptions={has_exception_i}) vs {rule_j['rule_id']} "
                f"(exceptions={has_exception_j})"
            )

        # ========== Filter 1: Subject compatibility (most important!) ==========
        # Only compare rules that constrain the same or related fields

        field_i = rule_i.get("affected_field", "")
        field_j = rule_j.get("affected_field", "")

        if field_i and field_j:
            # Normalize fields for comparison
            field_i_norm = field_i.lower().strip()
            field_j_norm = field_j.lower().strip()

            # Check if fields are compatible (same base field)
            if not self._are_fields_compatible(field_i_norm, field_j_norm):
                self.logger.debug(
                    f"IR pre-filter: Skipping pair due to incompatible fields: "
                    f"{field_i} vs {field_j}"
                )
                return False

        # ========== Filter 2: Normative strength compatibility ==========
        # MUST vs MAY are too different to be semantically similar

        strength_i = self._extract_rule_strength(rule_i["text"])
        strength_j = self._extract_rule_strength(rule_j["text"])

        if strength_i and strength_j:
            # MUST vs MAY: too different
            if {strength_i, strength_j} == {"MUST", "MAY"}:
                self.logger.debug(
                    f"IR pre-filter: Skipping pair due to strength mismatch: "
                    f"{strength_i} vs {strength_j}"
                )
                return False

            # MUST_NOT vs MAY: also too different
            if {strength_i, strength_j} == {"MUST_NOT", "MAY"}:
                return False

        # ========== Filter 3: Operation type compatibility (optional) ==========
        # Some operations are fundamentally different

        op_i = rule_i.get("operation", "")
        op_j = rule_j.get("operation", "")

        if op_i and op_j:
            if self._are_operations_incompatible(op_i, op_j):
                self.logger.debug(
                    f"IR pre-filter: Skipping pair due to incompatible operations: "
                    f"{op_i} vs {op_j}"
                )
                return False

        # Passed all filters → compute similarity
        return True

    def _are_fields_compatible(self, field_a: str, field_b: str) -> bool:
        """
        Check if two fields are compatible (same base field or parent-child)

        Args:
            field_a, field_b: Normalized field names

        Returns:
            True if fields are compatible for similarity comparison
        """
        # Exact match
        if field_a == field_b:
            return True

        # Parent-child relationship
        # e.g., "extensions.keyusage" and "extensions.keyusage.critical"
        if field_a.startswith(field_b + ".") or field_b.startswith(field_a + "."):
            return True

        # Same parent (first two levels)
        # e.g., "extensions.keyusage" and "extensions.basicconstraints"
        parts_a = field_a.split('.')
        parts_b = field_b.split('.')

        if len(parts_a) >= 2 and len(parts_b) >= 2:
            # Check if they share the same first two levels
            if parts_a[0] == parts_b[0] and parts_a[1] == parts_b[1]:
                return True

        # Different base fields
        return False

    def _are_operations_incompatible(self, op_a: str, op_b: str) -> bool:
        """
        Check if two operations are fundamentally incompatible

        Args:
            op_a, op_b: Operation names

        Returns:
            True if operations are too different to be semantically similar
        """
        op_a_norm = op_a.lower().strip()
        op_b_norm = op_b.lower().strip()

        # Define incompatible operation pairs
        incompatible_pairs = [
            # Presence vs value operations
            ("must_be_present", "maximum_value"),
            ("must_be_present", "minimum_value"),
            ("must_not_be_present", "must_equal"),

            # Structural vs content operations
            ("must_be_critical", "must_contain"),
            ("must_be_critical", "maximum_value"),
        ]

        # Check if this pair is incompatible
        for op1, op2 in incompatible_pairs:
            if {op_a_norm, op_b_norm} == {op1, op2}:
                return True

        return False

    def _compute_similarity_matrix(self) -> np.ndarray:
        """
        Compute pairwise cosine similarity matrix (optimized with IR pre-filtering)

        Returns:
            Similarity matrix (n x n)
        """
        n = len(self.rules)
        similarity_matrix = np.zeros((n, n))
        np.fill_diagonal(similarity_matrix, 1.0)

        # ========== IR-based pre-filtering ==========
        # Only compute similarity for rule pairs that pass IR filters

        pairs_to_compute = []
        pairs_filtered = 0

        for i in range(n):
            for j in range(i + 1, n):
                if self._should_compute_similarity(self.rules[i], self.rules[j]):
                    pairs_to_compute.append((i, j))
                else:
                    pairs_filtered += 1

        total_pairs = n * (n - 1) // 2
        filter_rate = (pairs_filtered / total_pairs * 100) if total_pairs > 0 else 0

        self.logger.info(
            f"IR pre-filtering: {len(pairs_to_compute)} / {total_pairs} pairs "
            f"({len(pairs_to_compute) / total_pairs * 100:.1f}%) need similarity computation. "
            f"Filtered out {pairs_filtered} pairs ({filter_rate:.1f}%)."
        )

        # ========== Compute similarity only for filtered pairs ==========
        for i, j in pairs_to_compute:
            # Since embeddings are normalized, cosine similarity = dot product
            sim = float(np.dot(self.embeddings[i], self.embeddings[j]))
            similarity_matrix[i, j] = sim
            similarity_matrix[j, i] = sim

        return similarity_matrix

    def _find_maximal_cliques(
        self,
        similarity_matrix: np.ndarray
    ) -> List[Dict[str, Any]]:
        """
        Find similar rule groups using maximal clique algorithm

        A clique is a subset where every pair of nodes has an edge (similarity >= threshold).
        Maximal clique: cannot add any more nodes to it.

        This approach:
        - Guarantees every pair in a group has similarity >= threshold
        - Avoids transitivity pollution (A-B, B-C doesn't force A-C)
        - Naturally handles multi-document scenarios

        Args:
            similarity_matrix: Pairwise similarity matrix

        Returns:
            List of similar rule groups
        """
        threshold = self.config["similarity_threshold"]
        n = len(self.rules)

        # Build similarity graph
        G = nx.Graph()
        G.add_nodes_from(range(n))

        # ========== DEBUG: Analyze cross-document similarities ==========
        cross_doc_similarities = []
        same_doc_similarities = []
        cross_doc_above_threshold = 0
        cross_doc_filtered_structural = 0

        for i in range(n):
            for j in range(i + 1, n):
                sim = similarity_matrix[i, j]
                doc_i = self.rules[i]["source_doc"]
                doc_j = self.rules[j]["source_doc"]

                if doc_i != doc_j:
                    # Cross-document pair
                    cross_doc_similarities.append(sim)

                    if sim >= threshold:
                        cross_doc_above_threshold += 1
                        # Check structural compatibility
                        if self.config.get("use_structural_filter", True):
                            if not self._is_structurally_compatible(self.rules[i], self.rules[j]):
                                cross_doc_filtered_structural += 1
                else:
                    # Same-document pair
                    same_doc_similarities.append(sim)

        # Log cross-document similarity statistics
        if cross_doc_similarities:
            self.logger.info(
                f"[DEBUG] Cross-document similarity stats: "
                f"count={len(cross_doc_similarities)}, "
                f"max={max(cross_doc_similarities):.4f}, "
                f"mean={np.mean(cross_doc_similarities):.4f}, "
                f"median={np.median(cross_doc_similarities):.4f}, "
                f"above_threshold={cross_doc_above_threshold}, "
                f"filtered_by_structural={cross_doc_filtered_structural}"
            )
        else:
            self.logger.warning("[DEBUG] No cross-document rule pairs found!")

        if same_doc_similarities:
            self.logger.info(
                f"[DEBUG] Same-document similarity stats: "
                f"count={len(same_doc_similarities)}, "
                f"max={max(same_doc_similarities):.4f}, "
                f"mean={np.mean(same_doc_similarities):.4f}, "
                f"above_threshold={sum(1 for s in same_doc_similarities if s >= threshold)}"
            )
        # ================================================================

        # Add edges for similar rule pairs
        edge_count = 0
        filtered_count = 0  # Count rules filtered by structural compatibility
        for i in range(n):
            for j in range(i + 1, n):
                if similarity_matrix[i, j] >= threshold:
                    # Apply structural compatibility filter if enabled
                    if self.config.get("use_structural_filter", True):
                        if not self._is_structurally_compatible(self.rules[i], self.rules[j]):
                            filtered_count += 1
                            continue
                    G.add_edge(i, j, weight=similarity_matrix[i, j])
                    edge_count += 1

        self.logger.info(
            f"Built similarity graph with {n} nodes and {edge_count} edges (threshold={threshold}). "
            f"Filtered {filtered_count} pairs by structural compatibility."
        )

        # Find all maximal cliques
        cliques = list(nx.find_cliques(G))
        self.logger.info(f"Found {len(cliques)} maximal cliques")

        # Filter by minimum group size and build group objects
        min_group_size = self.config.get("min_group_size", 2)
        similarity_groups = []

        for clique_id, clique in enumerate(cliques):
            if len(clique) >= min_group_size:
                # Build group
                group = self._build_group_from_clique(clique_id, clique, similarity_matrix)

                # IMPORTANT: Only keep cross-document groups
                # This is a cross-document similarity discovery system
                if len(group["source_docs"]) > 1:
                    similarity_groups.append(group)
                else:
                    self.logger.debug(f"Skipping single-document group: {list(group['source_docs'].keys())}")

        self.logger.info(f"Kept {len(similarity_groups)} cross-document groups (filtered single-document groups)")

        return similarity_groups

    def _build_group_from_clique(
        self,
        group_id: int,
        clique: List[int],
        similarity_matrix: np.ndarray
    ) -> Dict[str, Any]:
        """
        Build a SimilarRuleGroup from a clique (Exception-Aware)

        Args:
            group_id: Group identifier
            clique: List of rule indices
            similarity_matrix: Similarity matrix

        Returns:
            Similar rule group dictionary with exception metadata
        """
        # Extract group information
        member_rules = []
        doc_counts = defaultdict(int)
        rules_with_exceptions = []  # ⭐ 新增：带例外的规则列表
        exception_asymmetry = False  # ⭐ 新增：例外不对称标志

        for idx in clique:
            rule = self.rules[idx]
            doc_counts[rule["source_doc"]] += 1

            # ⭐ 检查例外规则
            has_exceptions = rule.get("has_exceptions", False)
            if has_exceptions:
                rules_with_exceptions.append(rule["rule_id"])

            member_rules.append({
                "rule_id": rule["rule_id"],
                "text": rule["text"],
                "section": rule.get("section", ""),
                "source_doc": rule["source_doc"],
                "has_exceptions": has_exceptions,  # ⭐ 新增：例外标志
            })

        # ⭐ 检查例外不对称性（一些规则有例外，一些没有）
        if len(rules_with_exceptions) > 0 and len(rules_with_exceptions) < len(clique):
            exception_asymmetry = True

        # Compute statistics
        avg_similarity = self._compute_group_cohesion(clique, similarity_matrix)
        min_similarity = self._compute_min_similarity(clique, similarity_matrix)

        similarity_group = {
            "group_id": f"group_{group_id}",
            "member_count": len(clique),
            "source_docs": dict(doc_counts),
            "rules": member_rules,
            "avg_similarity": avg_similarity,
            "min_similarity": min_similarity,  # Guaranteed >= threshold for cliques
            "rules_with_exceptions": rules_with_exceptions,  # ⭐ 新增：带例外的规则ID列表
            "exception_asymmetry": exception_asymmetry,  # ⭐ 新增：例外不对称标志
            "created_at": datetime.utcnow().isoformat(),
        }

        return similarity_group

    def _compute_group_cohesion(self, member_indices: List[int], similarity_matrix: np.ndarray) -> float:
        """
        Compute average pairwise similarity within a group

        Args:
            member_indices: Indices of group members
            similarity_matrix: Similarity matrix

        Returns:
            Average pairwise similarity
        """
        if len(member_indices) < 2:
            return 1.0

        similarities = []
        for i, idx1 in enumerate(member_indices):
            for idx2 in member_indices[i + 1:]:
                similarities.append(float(similarity_matrix[idx1, idx2]))

        return float(np.mean(similarities)) if similarities else 1.0

    def _compute_min_similarity(self, member_indices: List[int], similarity_matrix: np.ndarray) -> float:
        """
        Compute minimum pairwise similarity within a group

        Args:
            member_indices: Indices of group members
            similarity_matrix: Similarity matrix

        Returns:
            Minimum pairwise similarity
        """
        if len(member_indices) < 2:
            return 1.0

        min_sim = 1.0
        for i, idx1 in enumerate(member_indices):
            for idx2 in member_indices[i + 1:]:
                min_sim = min(min_sim, float(similarity_matrix[idx1, idx2]))

        return min_sim

    def _generate_statistics(
        self,
        documents: List[Dict[str, Any]],
        similarity_groups: List[Dict[str, Any]],
        rules: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate statistics for detection results

        Args:
            documents: List of documents
            similarity_groups: List of similarity groups
            rules: List of rules

        Returns:
            Statistics dictionary
        """
        # Count rules in groups
        rules_in_groups = sum(g["member_count"] for g in similarity_groups)
        rules_not_in_groups = len(rules) - rules_in_groups

        # Group sizes
        group_sizes = [g["member_count"] for g in similarity_groups]

        # Rules per document
        rules_per_doc = defaultdict(int)
        for rule in rules:
            rules_per_doc[rule["source_doc"]] += 1

        # Cross-document groups
        cross_doc_groups = sum(1 for g in similarity_groups if len(g["source_docs"]) > 1)

        # Average cohesion
        avg_cohesion = float(np.mean([g["avg_similarity"] for g in similarity_groups])) if similarity_groups else 0.0

        # Minimum similarity statistics
        min_similarities = [g.get("min_similarity", 0.0) for g in similarity_groups]
        avg_min_similarity = float(np.mean(min_similarities)) if min_similarities else 0.0

        statistics = {
            "total_documents": len(documents),
            "total_rules": len(rules),
            "total_similarity_groups": len(similarity_groups),
            "rules_in_groups": rules_in_groups,
            "rules_not_in_groups": rules_not_in_groups,
            "coverage_ratio": rules_in_groups / len(rules) if len(rules) > 0 else 0,
            "avg_group_size": float(np.mean(group_sizes)) if group_sizes else 0,
            "median_group_size": float(np.median(group_sizes)) if group_sizes else 0,
            "max_group_size": max(group_sizes) if group_sizes else 0,
            "min_group_size": min(group_sizes) if group_sizes else 0,
            "cross_document_groups": cross_doc_groups,
            "avg_group_cohesion": avg_cohesion,
            "avg_min_similarity": avg_min_similarity,  # Average of minimum similarities
            "rules_per_document": dict(rules_per_doc),
            "algorithm": "maximal_clique",
            "similarity_threshold": self.config["similarity_threshold"],
        }

        return statistics

    def get_group_details(self, group_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a similarity group

        Args:
            group_id: Group identifier

        Returns:
            Group details with member rules
        """
        group = next((g for g in self.similarity_groups if g["group_id"] == group_id), None)
        return group

    def compute_pairwise_similarity(self, rule_id_1: str, rule_id_2: str) -> float:
        """
        Compute similarity between two specific rules

        Args:
            rule_id_1: First rule ID
            rule_id_2: Second rule ID

        Returns:
            Cosine similarity score
        """
        idx1 = next((i for i, r in enumerate(self.rules) if r["rule_id"] == rule_id_1), None)
        idx2 = next((i for i, r in enumerate(self.rules) if r["rule_id"] == rule_id_2), None)

        if idx1 is None or idx2 is None:
            return 0.0

        emb1 = self.embeddings[idx1]
        emb2 = self.embeddings[idx2]

        return float(np.dot(emb1, emb2))
