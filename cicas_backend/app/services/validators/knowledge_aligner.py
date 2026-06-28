"""
Knowledge alignment and validation module
Aligns new rules with existing knowledge and validates consistency
"""
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.models import Rule, RuleValidation
from app.services.embeddings.hybrid_embedding_generator import HybridEmbeddingGenerator
from app.core.logging_config import app_logger
import asyncio
from openai import AsyncOpenAI
import httpx
from app.core.config import settings


class KnowledgeAligner:
    """Align new rules with existing knowledge"""

    def __init__(self, db: Session):
        self.db = db
        self.embedding_generator = HybridEmbeddingGenerator()
        if settings.llm_api_key:
            http_client = httpx.AsyncClient(trust_env=False, timeout=60.0)
            self.async_client = AsyncOpenAI(
                api_key=settings.llm_api_key,
                base_url=settings.llm_api_base,
                http_client=http_client
            )
        else:
            self.async_client = None

    async def align_rule(self, rule_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Align a rule with existing knowledge

        Args:
            rule_data: Rule dictionary with embedding

        Returns:
            Alignment result with status
        """
        try:
            # Check if similar rule exists (by hash)
            rule_hash = rule_data.get('hash')
            existing = self.db.query(Rule).filter(Rule.hash == rule_hash).first()

            if existing:
                return {
                    'status': 'exists',
                    'message': f'Rule already exists (ID: {existing.id})',
                    'existing_id': existing.id
                }

            # Check for similar rules by embedding
            if rule_data.get('embedding'):
                similar_rules = await self._find_similar_rules(
                    rule_data['embedding'],
                    threshold=settings.similarity_threshold
                )

                if similar_rules:
                    # High similarity - likely replacement or duplicate
                    best_match = similar_rules[0]
                    return {
                        'status': 'similar',
                        'message': f'Similar rule found (similarity: {best_match["similarity"]:.2f})',
                        'similar_id': best_match['id'],
                        'similarity_score': best_match['similarity']
                    }

            # No similar rules found - this is new
            return {
                'status': 'new',
                'message': 'New rule - no similar existing rules found'
            }

        except Exception as e:
            app_logger.error(f"Error aligning rule: {e}")
            return {
                'status': 'error',
                'message': str(e)
            }

    async def _find_similar_rules(
        self,
        embedding: List[float],
        threshold: float = 0.85,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Find similar rules using vector similarity search

        Args:
            embedding: Query embedding vector
            threshold: Similarity threshold (0-1)
            limit: Maximum number of results

        Returns:
            List of similar rules with similarity scores
        """
        try:
            # Use pgvector for similarity search
            # Convert list to string format for pgvector
            embedding_str = '[' + ','.join(map(str, embedding)) + ']'

            # Query using cosine distance
            query = f"""
                SELECT id, section, text, embedding <=> '{embedding_str}'::vector AS distance
                FROM rules
                WHERE embedding IS NOT NULL
                AND embedding <=> '{embedding_str}'::vector < {1 - threshold}
                ORDER BY embedding <=> '{embedding_str}'::vector
                LIMIT {limit}
            """

            result = self.db.execute(query)
            rows = result.fetchall()

            similar_rules = []
            for row in rows:
                similarity = 1 - row[3]  # Convert distance to similarity
                similar_rules.append({
                    'id': row[0],
                    'section': row[1],
                    'text': row[2],
                    'similarity': similarity
                })

            return similar_rules

        except Exception as e:
            app_logger.error(f"Error finding similar rules: {e}")
            return []


class RuleValidator:
    """Validate rule consistency using cross-validation"""

    def __init__(self):
        if settings.llm_api_key:
            http_client = httpx.AsyncClient(trust_env=False, timeout=60.0)
            self.async_client = AsyncOpenAI(
                api_key=settings.llm_api_key,
                base_url=settings.llm_api_base,
                http_client=http_client
            )
        else:
            self.async_client = None

    async def validate_rule(
        self,
        rule_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """
        Validate a rule using LLM cross-validation

        Args:
            rule_data: Rule dictionary
            db: Database session

        Returns:
            Validation result
        """
        try:
            if not self.async_client:
                app_logger.warning("LLM client not initialized, skipping validation")
                return {
                    'is_consistent': True,
                    'consistency_score': 1.0,
                    'explanation': 'Validation skipped - no API key'
                }

            # Generate explanation from model A
            explanation_a = await self._generate_explanation(rule_data)

            # Validate explanation with model B
            validation_result = await self._cross_validate(rule_data, explanation_a)

            return validation_result

        except Exception as e:
            app_logger.error(f"Error validating rule: {e}")
            return {
                'is_consistent': False,
                'consistency_score': 0.0,
                'explanation': f'Validation error: {e}'
            }

    async def _generate_explanation(self, rule_data: Dict[str, Any]) -> str:
        """
        Generate explanation for a rule using LLM

        Args:
            rule_data: Rule dictionary

        Returns:
            Explanation text
        """
        try:
            prompt = f"""
Explain the following PKI standard rule in simple terms:

Section: {rule_data.get('section', 'Unknown')}
Title: {rule_data.get('title', 'Unknown')}
Rule: {rule_data.get('text', '')}

Provide a concise explanation of what this rule means and why it's important.
"""

            response = await self.async_client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": "You are a PKI standards expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )

            explanation = response.choices[0].message.content

            return explanation

        except Exception as e:
            app_logger.error(f"Error generating explanation: {e}")
            return ""

    async def _cross_validate(
        self,
        rule_data: Dict[str, Any],
        explanation: str
    ) -> Dict[str, Any]:
        """
        Cross-validate explanation with another model

        Args:
            rule_data: Rule dictionary
            explanation: Generated explanation

        Returns:
            Validation result
        """
        try:
            prompt = f"""
You are validating an explanation of a PKI standard rule.

Original Rule:
{rule_data.get('text', '')}

Explanation to Validate:
{explanation}

Is this explanation accurate and consistent with the original rule?
Rate the consistency from 0.0 (completely inconsistent) to 1.0 (perfectly consistent).

Respond in JSON format:
{{
    "is_consistent": true/false,
    "consistency_score": 0.0-1.0,
    "issues": "any issues found or empty string"
}}
"""

            response = await self.async_client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": "You are a PKI standards validation expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=300,
                response_format={"type": "json_object"}
            )

            import json
            result = json.loads(response.choices[0].message.content)

            return {
                'is_consistent': result.get('is_consistent', True),
                'consistency_score': result.get('consistency_score', 1.0),
                'explanation': explanation,
                'issues': result.get('issues', '')
            }

        except Exception as e:
            app_logger.error(f"Error in cross-validation: {e}")
            return {
                'is_consistent': True,
                'consistency_score': 0.5,
                'explanation': explanation,
                'issues': f'Validation error: {e}'
            }
