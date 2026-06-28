"""
Embedding generator using BAAI model API (supports SiliconFlow, DeepSeek, etc.)
Generates vector embeddings for text content
Pure httpx implementation without OpenAI SDK dependency
"""
import asyncio
from typing import List, Optional, Dict, Any
import httpx
from app.core.config import settings
from app.core.logging_config import app_logger


class EmbeddingGenerator:
    """Generate embeddings for text using BAAI/bge-m3 model via API"""

    def __init__(self):
        if not settings.embedding_api_key:
            app_logger.warning("Embedding API key not configured")
            self.available = False
        else:
            app_logger.info(f"Initializing embedding client with base URL: {settings.embedding_api_base}")
            app_logger.info(f"Using embedding model: {settings.embedding_model}")
            self.available = True
            app_logger.info("Embedding client initialized successfully")

        self.api_key = settings.embedding_api_key
        self.api_base = settings.embedding_api_base
        self.model = settings.embedding_model

        # BAAI/bge-m3 模型限制（bge-m3 支持最长 8192 token，远超 bge-large 的 512）
        # 使用字符数估算: 1 token ≈ 4 characters (英文)
        self.max_tokens = 8192  # BAAI/bge-m3 的输入限制
        self.max_chars = self.max_tokens * 4  # 约 32768 字符

    async def generate_embedding(self, text: str) -> Optional[List[float]]:
        """
        Generate embedding vector for a single text

        Args:
            text: Text to embed

        Returns:
            List of floats representing the embedding vector, or None if failed
        """
        try:
            if not self.available:
                app_logger.error("Embedding client not initialized (missing API key)")
                return None

            # Truncate text if too long
            text = self._truncate_text(text)

            # Call API using httpx
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.api_base}/embeddings",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "input": text,
                        "encoding_format": "float"
                    }
                )

                response.raise_for_status()
                result = response.json()

                # Extract embedding from response
                embedding = result['data'][0]['embedding']

                app_logger.debug(f"Generated embedding for text ({len(text)} chars)")

                return embedding

        except httpx.HTTPStatusError as e:
            app_logger.error(f"HTTP error generating embedding: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            app_logger.error(f"Error generating embedding: {e}")
            return None

    async def generate_embeddings_batch(
        self,
        texts: List[str],
        batch_size: int = 100
    ) -> List[Optional[List[float]]]:
        """
        Generate embeddings for multiple texts in batches

        Args:
            texts: List of texts to embed
            batch_size: Number of texts to process in each batch

        Returns:
            List of embedding vectors (or None for failures)
        """
        try:
            if not self.available:
                app_logger.error("Embedding client not initialized (missing API key)")
                return [None] * len(texts)

            app_logger.info(f"Generating embeddings for {len(texts)} texts in batches of {batch_size}")
            embeddings = []

            # Process in batches
            for i in range(0, len(texts), batch_size):
                batch = texts[i:i + batch_size]
                batch_num = i//batch_size + 1
                total_batches = (len(texts) + batch_size - 1) // batch_size

                # Truncate texts in batch
                batch = [self._truncate_text(text) for text in batch]

                try:
                    app_logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} texts)")

                    async with httpx.AsyncClient(timeout=60.0) as client:
                        response = await client.post(
                            f"{self.api_base}/embeddings",
                            headers={
                                "Authorization": f"Bearer {self.api_key}",
                                "Content-Type": "application/json"
                            },
                            json={
                                "model": self.model,
                                "input": batch,
                                "encoding_format": "float"
                            }
                        )

                        response.raise_for_status()
                        result = response.json()

                    # Extract embeddings in order
                    batch_embeddings = [data['embedding'] for data in result['data']]
                    embeddings.extend(batch_embeddings)

                    app_logger.info(f"Successfully generated {len(batch_embeddings)} embeddings (batch {batch_num}/{total_batches})")

                    # Rate limiting - delay between batches
                    await asyncio.sleep(1.0)  # 1 second delay

                except httpx.HTTPStatusError as e:
                    app_logger.error(f"HTTP error in batch {batch_num}/{total_batches}: {e.response.status_code} - {e.response.text}")
                    embeddings.extend([None] * len(batch))
                except Exception as e:
                    app_logger.error(f"Error in batch {batch_num}/{total_batches}: {e}", exc_info=True)
                    app_logger.error(f"Batch size: {len(batch)}, Starting index: {i}")
                    embeddings.extend([None] * len(batch))

            app_logger.info(f"Completed embedding generation: {len([e for e in embeddings if e is not None])}/{len(texts)} successful")
            return embeddings

        except Exception as e:
            app_logger.error(f"Error in batch embedding generation: {e}", exc_info=True)
            return [None] * len(texts)

    def _truncate_text(self, text: str) -> str:
        """
        Truncate text to fit within character limit

        BAAI/bge-m3 has an 8192 token limit
        Using approximation: 1 token ≈ 4 characters

        Args:
            text: Text to truncate

        Returns:
            Truncated text
        """
        try:
            if len(text) > self.max_chars:
                text = text[:self.max_chars]
                app_logger.warning(f"Text truncated to {self.max_chars} characters (~{self.max_tokens} tokens)")

            return text

        except Exception as e:
            app_logger.error(f"Error truncating text: {e}")
            return text[:self.max_chars]

    def count_tokens(self, text: str) -> int:
        """
        Estimate number of tokens in text

        Uses character-based approximation: 1 token ≈ 4 characters
        This is suitable for BAAI/bge models

        Args:
            text: Text to count tokens for

        Returns:
            Estimated number of tokens
        """
        try:
            # Simple estimation: 4 characters per token (for English text)
            estimated_tokens = len(text) // 4
            return estimated_tokens
        except Exception as e:
            app_logger.error(f"Error counting tokens: {e}")
            return 0

    async def generate_embeddings_for_rules(
        self,
        rules: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Generate embeddings for a list of rule dictionaries

        Args:
            rules: List of rule dictionaries with 'text' field

        Returns:
            Rules with added 'embedding' field
        """
        try:
            # Extract texts
            texts = [rule['text'] for rule in rules]

            # Generate embeddings
            embeddings = await self.generate_embeddings_batch(texts)

            # Add embeddings to rules
            for rule, embedding in zip(rules, embeddings):
                rule['embedding'] = embedding

            success_count = sum(1 for emb in embeddings if emb is not None)
            app_logger.info(f"Generated embeddings for {success_count}/{len(rules)} rules")

            return rules

        except Exception as e:
            app_logger.error(f"Error generating embeddings for rules: {e}")
            return rules

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
        try:
            import numpy as np

            v1 = np.array(vec1)
            v2 = np.array(vec2)

            dot_product = np.dot(v1, v2)
            norm_v1 = np.linalg.norm(v1)
            norm_v2 = np.linalg.norm(v2)

            if norm_v1 == 0 or norm_v2 == 0:
                return 0.0

            similarity = dot_product / (norm_v1 * norm_v2)

            return float(similarity)

        except Exception as e:
            app_logger.error(f"Error calculating cosine similarity: {e}")
            return 0.0
