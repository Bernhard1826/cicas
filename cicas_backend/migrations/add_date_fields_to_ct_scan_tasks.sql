-- Migration: Add date_from and date_to fields to ct_scan_tasks table
-- Date: 2026-01-16
-- Description: Add date filtering fields for certificate validity period

ALTER TABLE ct_scan_tasks ADD COLUMN IF NOT EXISTS date_from DATE;
ALTER TABLE ct_scan_tasks ADD COLUMN IF NOT EXISTS date_to DATE;

-- Add comment
COMMENT ON COLUMN ct_scan_tasks.date_from IS 'Certificate validity start date filter (not_before >= date_from)';
COMMENT ON COLUMN ct_scan_tasks.date_to IS 'Certificate validity end date filter (not_after <= date_to)';
