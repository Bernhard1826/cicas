-- Migration: Upgrade embedding dimension from 768 to 1024 (BAAI/bge-large-en-v1.5)
-- Date: 2025-12-08
-- Description:
--   1. Update rules.embedding from vector(768) to vector(1024) for BAAI/bge-large-en-v1.5 model
--   2. Recreate vector indexes
--
-- IMPORTANT: This migration will clear all existing embeddings.
--            After running this migration, you MUST regenerate embeddings using the new BAAI model.

BEGIN;

-- Step 1: Drop existing vector index (required before changing dimension)
DROP INDEX IF EXISTS idx_rule_embedding;

-- Step 2: Clear existing embeddings (required before changing dimension)
-- WARNING: This will delete all existing 768-dimensional embeddings
UPDATE rules SET embedding = NULL WHERE embedding IS NOT NULL;

-- Step 3: Alter embedding column dimension (768 -> 1024)
ALTER TABLE rules ALTER COLUMN embedding TYPE vector(1024);

-- Step 4: Recreate vector index with new dimension
-- Note: Using ivfflat for approximate nearest neighbor search
CREATE INDEX idx_rule_embedding ON rules USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- Step 5: Verify migration
DO $$
DECLARE
    rule_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO rule_count FROM rules WHERE embedding IS NOT NULL;
    RAISE NOTICE 'Migration complete. % rules have embeddings (should be 0 after migration).', rule_count;
    RAISE NOTICE 'IMPORTANT: Regenerate embeddings using BAAI/bge-large-en-v1.5 model.';
END $$;

COMMIT;

-- Post-migration instructions:
-- 1. Verify .env configuration:
--    EMBEDDING_MODEL=BAAI/bge-large-en-v1.5
--    EMBEDDING_DIMENSION=1024
--    VECTOR_DIMENSION=1024
--
-- 2. Regenerate embeddings by running:
--    python -m app.scripts.regenerate_embeddings
--    OR
--    Call API endpoint: POST /api/admin/regenerate-embeddings
--
-- 3. Verify embedding generation:
--    SELECT COUNT(*) FROM rules WHERE embedding IS NOT NULL;
