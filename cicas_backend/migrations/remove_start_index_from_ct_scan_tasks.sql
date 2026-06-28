-- Migration: Remove start_index field from ct_scan_tasks table
-- Date: 2026-01-17
-- Description: Remove start_index column as the feature is no longer used

ALTER TABLE ct_scan_tasks DROP COLUMN IF EXISTS start_index;
