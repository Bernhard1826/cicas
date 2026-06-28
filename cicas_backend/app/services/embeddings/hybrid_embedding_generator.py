"""
Embedding Generator - API-based only
Uses SiliconFlow API for embeddings (bce-embedding-base_v1)
"""
import asyncio
from typing import List, Optional, Dict, Any
from app.core.config import settings
from app.core.logging_config import app_logger
from app.utils.llm_client import create_async_llm_client


class HybridEmbeddingGenerator:
    """
    Generate embeddings using SiliconFlow API (bce-embedding-base_v1)
    """

    def __init__(self):
        """Initialize embedding generator with API client"""
        if not settings.embedding_api_key:
            raise ValueError("EMBEDDING_API_KEY not configured in .env")

        # 使用通用函数创建客户端（自动禁用代理）
        self.client = create_async_llm_client(
            api_key=settings.embedding_api_key,
            base_url=settings.embedding_api_base,
            timeout=60.0
        )
        self.model_name = settings.embedding_model
        self.dimension = settings.embedding_dimension
        self.max_length = 512  # Reduced from 800 to avoid 413 errors (~256 tokens)

        app_logger.info(f"[OK] Embedding API initialized: {self.model_name} ({self.dimension}d)")

    async def generate_embedding(self, text: str) -> Optional[List[float]]:
        """
        Generate embedding vector for a single text

        Args:
            text: Text to embed

        Returns:
            List of floats representing the embedding vector
        """
        try:
            # 验证输入：不能为空
            if not text or not text.strip():
                app_logger.warning("[EmbeddingGenerator] Empty text provided, returning None")
                return None

            # Truncate if too long (API has 512 token limit)
            if len(text) > self.max_length:
                text = text[:self.max_length] + "..."
                app_logger.debug(f"Truncated text to {self.max_length} chars")

            # Direct HTTP POST request (no longer using OpenAI SDK)
            response = await self.client.post(
                "/embeddings",
                json={
                    "model": self.model_name,
                    "input": text.strip()  # 确保去除首尾空白
                }
            )
            response.raise_for_status()
            result = response.json()

            # Extract embedding from response
            if 'data' in result and len(result['data']) > 0:
                return result['data'][0]['embedding']
            else:
                app_logger.error(f"Unexpected embedding response format: {result}")
                return None

        except Exception as e:
            # 如果是413错误（请求实体太大），尝试更激进的截断
            if '413' in str(e) or 'Request Entity Too Large' in str(e):
                app_logger.warning(
                    f"[EmbeddingGenerator] 413 error, retrying with aggressive truncation. "
                    f"Original length: {len(text)}"
                )
                # 尝试更激进的截断：256字符（约128 tokens）
                try:
                    truncated_text = text[:256] + "..."
                    response = await self.client.post(
                        "/embeddings",
                        json={
                            "model": self.model_name,
                            "input": truncated_text
                        }
                    )
                    response.raise_for_status()
                    result = response.json()

                    if 'data' in result and len(result['data']) > 0:
                        app_logger.info(f"[EmbeddingGenerator] Retry successful with 256 chars")
                        return result['data'][0]['embedding']
                except Exception as retry_error:
                    app_logger.error(f"[EmbeddingGenerator] Retry also failed: {retry_error}")
                    return None

            app_logger.error(f"Error generating embedding: {e}")
            return None

    async def generate_embeddings_batch(
        self,
        texts: List[str],
        batch_size: int = 50
    ) -> List[Optional[List[float]]]:
        """
        Generate embeddings for multiple texts

        Args:
            texts: List of texts to embed
            batch_size: Batch size for processing

        Returns:
            List of embedding vectors
        """
        embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]

            # Truncate texts
            batch = [
                t[:self.max_length] + "..." if len(t) > self.max_length else t
                for t in batch
            ]

            try:
                # Process each text in batch sequentially to avoid rate limits
                batch_embeddings = []
                for text in batch:
                    embedding = await self.generate_embedding(text)
                    batch_embeddings.append(embedding)

                embeddings.extend(batch_embeddings)
                app_logger.info(f"Generated {len(batch_embeddings)} embeddings (batch {i//batch_size + 1})")

                # Rate limiting
                await asyncio.sleep(0.1)

            except Exception as e:
                app_logger.error(f"Batch error: {e}")
                embeddings.extend([None] * len(batch))

        return embeddings

    async def generate_embeddings_for_rules(
        self,
        rules: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Generate embeddings for rule dictionaries

        Args:
            rules: List of rule dictionaries with 'text' field

        Returns:
            Rules with added 'embedding' field
        """
        try:
            texts = [rule.get('text', '') for rule in rules]
            embeddings = await self.generate_embeddings_batch(texts)

            for rule, embedding in zip(rules, embeddings):
                rule['embedding'] = embedding

            success_count = sum(1 for emb in embeddings if emb is not None)
            app_logger.info(f"[OK] Generated embeddings for {success_count}/{len(rules)} rules")

            return rules

        except Exception as e:
            app_logger.error(f"Error generating embeddings for rules: {e}")
            return rules

    @staticmethod
    def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        try:
            import numpy as np

            v1 = np.array(vec1)
            v2 = np.array(vec2)

            dot_product = np.dot(v1, v2)
            norm_v1 = np.linalg.norm(v1)
            norm_v2 = np.linalg.norm(v2)

            if norm_v1 == 0 or norm_v2 == 0:
                return 0.0

            return float(dot_product / (norm_v1 * norm_v2))

        except Exception as e:
            app_logger.error(f"Cosine similarity error: {e}")
            return 0.0
