"""
Multi-Vector Embedding Generator (多向量嵌入生成器)
Generates multiple types of embeddings for rules:
- Semantic embedding: based on rule text
- Field embedding: based on field path
- Constraint embedding: based on constraint structure
"""
import hashlib
import json
from typing import Dict, List, Any, Optional
import numpy as np
from app.services.embeddings.embedding_generator import EmbeddingGenerator
from app.core.logging_config import app_logger


class MultiVectorEmbedding:
    """
    Generates multi-modal embeddings for PKI rules
    Combines semantic, field, and constraint embeddings
    """

    def __init__(self):
        """Initialize the multi-vector embedding generator"""
        self.logger = app_logger
        self.semantic_embedder = EmbeddingGenerator()

        # Predefined field embeddings (simple hash-based for now)
        # In a production system, these could be learned embeddings
        self.field_dim = 64

    async def generate_multi_vector(
        self,
        rule: Dict[str, Any]
    ) -> Dict[str, List[float]]:
        """
        Generate multi-vector embedding for a rule

        Args:
            rule: Canonicalized rule with field_path and constraint

        Returns:
            Dictionary with three embedding vectors:
            - semantic_vec: Embedding of rule text and normalized form
            - field_vec: Embedding of field path
            - constraint_vec: Embedding of constraint structure
        """
        try:
            # Generate semantic embedding
            semantic_vec = await self._generate_semantic_vec(rule)

            # Generate field embedding
            field_vec = self._generate_field_vec(rule.get("field_path", ""))

            # Generate constraint embedding
            constraint_vec = self._generate_constraint_vec(rule.get("constraint", {}))

            return {
                "semantic_vec": semantic_vec,
                "field_vec": field_vec,
                "constraint_vec": constraint_vec,
            }

        except Exception as e:
            self.logger.error(f"Error generating multi-vector embedding: {e}")
            return {
                "semantic_vec": None,
                "field_vec": None,
                "constraint_vec": None,
            }

    async def generate_multi_vectors_batch(
        self,
        rules: List[Dict[str, Any]]
    ) -> List[Dict[str, List[float]]]:
        """
        Generate multi-vector embeddings for multiple rules

        Args:
            rules: List of canonicalized rules

        Returns:
            List of multi-vector embeddings
        """
        embeddings = []

        # Generate semantic embeddings in batch
        texts = [
            f"{rule.get('text', '')} {rule.get('normalized_rule', '')}"
            for rule in rules
        ]
        semantic_vecs = await self.semantic_embedder.generate_embeddings_batch(texts)

        # Generate field and constraint embeddings individually
        for i, rule in enumerate(rules):
            field_vec = self._generate_field_vec(rule.get("field_path", ""))
            constraint_vec = self._generate_constraint_vec(rule.get("constraint", {}))

            embeddings.append({
                "semantic_vec": semantic_vecs[i],
                "field_vec": field_vec,
                "constraint_vec": constraint_vec,
            })

        self.logger.info(f"Generated multi-vector embeddings for {len(embeddings)} rules")

        return embeddings

    async def _generate_semantic_vec(self, rule: Dict[str, Any]) -> Optional[List[float]]:
        """
        Generate semantic embedding

        Args:
            rule: Rule dictionary

        Returns:
            Semantic embedding vector
        """
        # Combine rule text and normalized rule for better semantic representation
        text = rule.get("text", "")
        normalized = rule.get("normalized_rule", "")
        combined_text = f"{text} {normalized}"

        embedding = await self.semantic_embedder.generate_embedding(combined_text)

        return embedding

    def _generate_field_vec(self, field_path: str) -> List[float]:
        """
        Generate field embedding based on field path

        Uses a simple hash-based approach for now
        In production, could use learned embeddings

        Args:
            field_path: Field path string (e.g., "subject.altname.dns")

        Returns:
            Field embedding vector
        """
        # Hash the field path to a fixed-size vector
        hash_val = hashlib.sha256(field_path.encode()).digest()

        # Convert to float vector
        vec = []
        for i in range(self.field_dim):
            byte_idx = i % len(hash_val)
            vec.append(float(hash_val[byte_idx]) / 255.0)

        # Normalize
        vec = np.array(vec)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm

        return vec.tolist()

    def _generate_constraint_vec(self, constraint: Dict[str, Any]) -> List[float]:
        """
        Generate constraint embedding based on constraint structure

        Args:
            constraint: Constraint dictionary with type and value

        Returns:
            Constraint embedding vector (16-dimensional)
        """
        # Create a 16-dimensional vector encoding the constraint
        vec = [0.0] * 16

        constraint_type = constraint.get("type")
        constraint_value = constraint.get("value")

        # Encode constraint type (one-hot-like encoding in first 8 dimensions)
        type_map = {
            "max": 0,
            "min": 1,
            "range": 2,
            "exactly": 3,
            "forbid": 4,
            "require": 5,
            "should": 6,
            "may": 7,
        }

        if constraint_type in type_map:
            vec[type_map[constraint_type]] = 1.0

        # Encode constraint value in remaining dimensions
        if constraint_value is not None:
            if isinstance(constraint_value, bool):
                vec[8] = 1.0 if constraint_value else 0.0
            elif isinstance(constraint_value, (int, float)):
                # Normalize to 0-1 range (assuming max value of 10000)
                vec[9] = min(float(constraint_value) / 10000.0, 1.0)
            elif isinstance(constraint_value, list) and len(constraint_value) == 2:
                # Range: encode min and max
                vec[10] = min(float(constraint_value[0]) / 10000.0, 1.0)
                vec[11] = min(float(constraint_value[1]) / 10000.0, 1.0)

        # Normalize vector
        vec = np.array(vec)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm

        return vec.tolist()

    @staticmethod
    def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
        """
        Calculate cosine similarity between two vectors

        Args:
            vec1: First vector
            vec2: Second vector

        Returns:
            Cosine similarity score (0-1)
        """
        if vec1 is None or vec2 is None:
            return 0.0

        try:
            v1 = np.array(vec1)
            v2 = np.array(vec2)

            dot_product = np.dot(v1, v2)
            norm_v1 = np.linalg.norm(v1)
            norm_v2 = np.linalg.norm(v2)

            if norm_v1 == 0 or norm_v2 == 0:
                return 0.0

            similarity = dot_product / (norm_v1 * norm_v2)

            # Clamp to [0, 1] range
            return float(max(0.0, min(1.0, similarity)))

        except Exception as e:
            app_logger.error(f"Error calculating cosine similarity: {e}")
            return 0.0
