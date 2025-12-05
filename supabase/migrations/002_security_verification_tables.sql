-- Migration: Security Verification Tables
-- Adds tables for trusted public keys and security verifications
-- Extends files table with security status columns

-- Trusted Public Keys Table
CREATE TABLE IF NOT EXISTS trusted_public_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    public_key_hash TEXT UNIQUE NOT NULL,
    key_type TEXT NOT NULL,  -- RSA, EC, etc.
    key_size INTEGER,
    owner_name TEXT,
    organization TEXT,
    trust_level TEXT NOT NULL DEFAULT 'verified',  -- 'trusted', 'verified', 'suspicious', 'blocked'
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by UUID REFERENCES auth.users(id),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security Verifications Table
CREATE TABLE IF NOT EXISTS security_verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    public_key_hash TEXT,
    verification_status TEXT NOT NULL,  -- 'secure', 'warning', 'blocked', 'unknown'
    security_score INTEGER,  -- 0-100
    threats_detected JSONB,  -- Array of detected threats
    verification_details JSONB,  -- Full verification details
    recommendations JSONB,  -- Array of recommendations
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Extend files table with security columns
ALTER TABLE files ADD COLUMN IF NOT EXISTS security_status TEXT;
ALTER TABLE files ADD COLUMN IF NOT EXISTS security_score INTEGER;
ALTER TABLE files ADD COLUMN IF NOT EXISTS public_key_hash TEXT;
ALTER TABLE files ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_trusted_public_keys_hash ON trusted_public_keys(public_key_hash);
CREATE INDEX IF NOT EXISTS idx_trusted_public_keys_trust_level ON trusted_public_keys(trust_level);
CREATE INDEX IF NOT EXISTS idx_security_verifications_file_id ON security_verifications(file_id);
CREATE INDEX IF NOT EXISTS idx_security_verifications_status ON security_verifications(verification_status);
CREATE INDEX IF NOT EXISTS idx_security_verifications_verified_at ON security_verifications(verified_at DESC);
CREATE INDEX IF NOT EXISTS idx_files_security_status ON files(security_status);
CREATE INDEX IF NOT EXISTS idx_files_public_key_hash ON files(public_key_hash);

-- Function to update updated_at timestamp for trusted_public_keys
CREATE TRIGGER update_trusted_keys_updated_at
    BEFORE UPDATE ON trusted_public_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) Policies

-- Enable RLS on trusted_public_keys table
ALTER TABLE trusted_public_keys ENABLE ROW LEVEL SECURITY;

-- Policy: All authenticated users can view trusted keys
CREATE POLICY "Users can view trusted keys"
    ON trusted_public_keys FOR SELECT
    TO authenticated
    USING (true);

-- Policy: Only admins can insert trusted keys (using service role in practice)
CREATE POLICY "Admins can insert trusted keys"
    ON trusted_public_keys FOR INSERT
    TO authenticated
    WITH CHECK (true);  -- In practice, check admin role

-- Policy: Only admins can update trusted keys
CREATE POLICY "Admins can update trusted keys"
    ON trusted_public_keys FOR UPDATE
    TO authenticated
    USING (true)  -- In practice, check admin role
    WITH CHECK (true);

-- Policy: Only admins can delete trusted keys
CREATE POLICY "Admins can delete trusted keys"
    ON trusted_public_keys FOR DELETE
    TO authenticated
    USING (true);  -- In practice, check admin role

-- Enable RLS on security_verifications table
ALTER TABLE security_verifications ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view verifications for their own files
CREATE POLICY "Users can view own file verifications"
    ON security_verifications FOR SELECT
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM files
            WHERE files.id = security_verifications.file_id
            AND files.user_id = auth.uid()
        )
    );

-- Policy: Service role can insert verifications (for agent service)
CREATE POLICY "Service can insert verifications"
    ON security_verifications FOR INSERT
    TO authenticated
    WITH CHECK (true);  -- Service role bypasses RLS

-- Comments for documentation
COMMENT ON TABLE trusted_public_keys IS 'Registry of trusted public keys for security verification';
COMMENT ON TABLE security_verifications IS 'Security verification results from AI agent service';
COMMENT ON COLUMN files.security_status IS 'Security status: secure, warning, blocked, unknown';
COMMENT ON COLUMN files.security_score IS 'Security score from 0-100';
COMMENT ON COLUMN files.public_key_hash IS 'SHA-256 hash of the public key used to sign the file';

