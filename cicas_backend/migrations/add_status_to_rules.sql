-- Migration: Add status column to rules table
-- Date: 2025-12-19
-- Description: Adds status field to track rule lifecycle (active, deprecated, deleted)

-- Add the status column with default value
ALTER TABLE rules ADD COLUMN status VARCHAR(50) DEFAULT 'active' NOT NULL;

-- Create index on status column for query performance
CREATE INDEX idx_rules_status ON rules(status);

-- Update existing rows to have 'active' status (in case default didn't apply)
UPDATE rules SET status = 'active' WHERE status IS NULL;

-- Verify the migration
SELECT COUNT(*) as total_rules, status, COUNT(*) as count_per_status
FROM rules
GROUP BY status;
