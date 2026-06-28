-- Migration: Upgrade embedding dimension from 384 to 768 and add cross_validations table
-- Date: 2025-11-04
-- Description:
--   1. Update rules.embedding from vector(384) to vector(768) for bce-embedding-base_v1 model
--   2. Create missing cross_validations table
--   3. Recreate vector indexes

BEGIN;

-- Step 1: Drop existing vector index (required before changing dimension)
DROP INDEX IF EXISTS idx_rule_embedding;

-- Step 2: Clear existing embeddings (required before changing dimension)
-- WARNING: This will delete all existing 384-dimensional embeddings
UPDATE rules SET embedding = NULL WHERE embedding IS NOT NULL;

-- Step 3: Alter embedding column dimension
ALTER TABLE rules ALTER COLUMN embedding TYPE vector(768);

-- Step 3: Recreate vector index with new dimension
CREATE INDEX idx_rule_embedding ON rules USING ivfflat (embedding) WITH (lists = 100);

-- Step 4: Create cross_validations table
CREATE TABLE IF NOT EXISTS cross_validations (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER NOT NULL REFERENCES rules(id),

    -- Model A extraction results
    model_a_name VARCHAR(100) NOT NULL,
    model_a_extraction TEXT,
    model_a_affected_field VARCHAR(200),
    model_a_operation VARCHAR(100),
    model_a_expected_value TEXT,
    model_a_severity VARCHAR(50),

    -- Model B extraction results
    model_b_name VARCHAR(100) NOT NULL,
    model_b_extraction TEXT,
    model_b_affected_field VARCHAR(200),
    model_b_operation VARCHAR(100),
    model_b_expected_value TEXT,
    model_b_severity VARCHAR(50),

    -- A validates B
    a_validates_b_consistent BOOLEAN,
    a_validates_b_score FLOAT,
    a_validates_b_explanation TEXT,

    -- B validates A
    b_validates_a_consistent BOOLEAN,
    b_validates_a_score FLOAT,
    b_validates_a_explanation TEXT,

    -- Overall assessment
    field_consistency FLOAT,
    overall_consistency FLOAT,
    validation_passed BOOLEAN DEFAULT FALSE,
    is_ambiguous BOOLEAN DEFAULT FALSE,
    ambiguity_reasons TEXT,

    -- Secondary review
    needs_secondary_review BOOLEAN DEFAULT FALSE,
    secondary_review_model VARCHAR(100),
    secondary_review_result TEXT,
    secondary_review_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for cross_validations
CREATE INDEX IF NOT EXISTS idx_cross_validation_rule ON cross_validations(rule_id);
CREATE INDEX IF NOT EXISTS idx_cross_validation_status ON cross_validations(validation_passed, is_ambiguous);

-- Add comment
COMMENT ON TABLE cross_validations IS 'Cross-validation results between multiple LLM models for rule extraction';
COMMENT ON COLUMN rules.embedding IS 'Vector embedding (768 dimensions for bce-embedding-base_v1)';

COMMIT;

-- Post-migration note:
-- After running this migration, you MUST rebuild the ChromaDB vector database
-- using the new bce-embedding-base_v1 model, as the dimension has changed from 384 to 768.
