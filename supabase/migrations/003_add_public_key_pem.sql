-- Migration: Add public_key_pem column for text files
-- Allows storing public key PEM for text files that don't have embedded signatures

-- Add public_key_pem column to files table
ALTER TABLE files ADD COLUMN IF NOT EXISTS public_key_pem TEXT;

-- Index for public key lookups
CREATE INDEX IF NOT EXISTS idx_files_public_key_pem ON files(public_key_pem) WHERE public_key_pem IS NOT NULL;

-- Comment for documentation
COMMENT ON COLUMN files.public_key_pem IS 'PEM-formatted public key for text files (stored separately since text files do not have embedded signatures)';

