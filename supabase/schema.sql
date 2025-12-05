-- Text File Signature Verification System Database Schema
-- Security: Row Level Security (RLS) enabled on all tables
-- Best Practices: UUIDs for IDs, timestamps for audit trails, proper indexing

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable Row Level Security
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Files table: Stores file metadata and signature information
CREATE TABLE IF NOT EXISTS files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    storage_path TEXT NOT NULL, -- Path in Supabase Storage
    original_hash TEXT NOT NULL, -- SHA-256 hash before signature (pre-signature hash)
    signature TEXT, -- Current signature value
    post_signature_hash TEXT, -- SHA-256 hash after signature (post-signature hash)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_filename UNIQUE (user_id, file_name)
);

-- File versions table: Tracks signature changes for audit and revert functionality
CREATE TABLE IF NOT EXISTS file_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    signature TEXT NOT NULL, -- Signature value at this version
    previous_signature TEXT, -- Previous signature (NULL for initial version)
    post_signature_hash TEXT NOT NULL, -- Post-signature hash at this version
    change_reason TEXT, -- Optional reason for the change
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    editor_id UUID NOT NULL REFERENCES auth.users(id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_file_versions_file_id ON file_versions(file_id);
CREATE INDEX IF NOT EXISTS idx_file_versions_created_at ON file_versions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_file_versions_file_created ON file_versions(file_id, created_at DESC);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER update_files_updated_at
    BEFORE UPDATE ON files
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) Policies

-- Enable RLS on files table
ALTER TABLE files ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own files
CREATE POLICY "Users can view own files"
    ON files FOR SELECT
    USING (auth.uid() = user_id);

-- Policy: Users can insert their own files
CREATE POLICY "Users can insert own files"
    ON files FOR INSERT
    WITH CHECK (auth.uid() = user_id);

-- Policy: Users can update their own files
CREATE POLICY "Users can update own files"
    ON files FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- Policy: Users can delete their own files
CREATE POLICY "Users can delete own files"
    ON files FOR DELETE
    USING (auth.uid() = user_id);

-- Enable RLS on file_versions table
ALTER TABLE file_versions ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view versions of their own files
CREATE POLICY "Users can view own file versions"
    ON file_versions FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM files
            WHERE files.id = file_versions.file_id
            AND files.user_id = auth.uid()
        )
    );

-- Policy: Users can insert versions for their own files
CREATE POLICY "Users can insert own file versions"
    ON file_versions FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM files
            WHERE files.id = file_versions.file_id
            AND files.user_id = auth.uid()
        )
        AND auth.uid() = user_id
        AND auth.uid() = editor_id
    );

-- Function to automatically create initial version when file is created
CREATE OR REPLACE FUNCTION create_initial_file_version()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO file_versions (
        file_id,
        user_id,
        signature,
        previous_signature,
        post_signature_hash,
        change_reason,
        editor_id
    ) VALUES (
        NEW.id,
        NEW.user_id,
        COALESCE(NEW.signature, ''),
        NULL,
        COALESCE(NEW.post_signature_hash, ''),
        'Initial version',
        NEW.user_id
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to create initial version
CREATE TRIGGER create_initial_version_on_file_insert
    AFTER INSERT ON files
    FOR EACH ROW
    EXECUTE FUNCTION create_initial_file_version();

-- Function to get file with latest version info
CREATE OR REPLACE FUNCTION get_file_with_latest_version(p_file_id UUID)
RETURNS TABLE (
    id UUID,
    user_id UUID,
    file_name TEXT,
    file_size BIGINT,
    storage_path TEXT,
    original_hash TEXT,
    signature TEXT,
    post_signature_hash TEXT,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    version_count BIGINT,
    last_modified_by UUID,
    last_modified_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        f.id,
        f.user_id,
        f.file_name,
        f.file_size,
        f.storage_path,
        f.original_hash,
        f.signature,
        f.post_signature_hash,
        f.created_at,
        f.updated_at,
        COUNT(fv.id)::BIGINT as version_count,
        MAX(fv.editor_id) as last_modified_by,
        MAX(fv.created_at) as last_modified_at
    FROM files f
    LEFT JOIN file_versions fv ON f.id = fv.file_id
    WHERE f.id = p_file_id
    AND f.user_id = auth.uid() -- RLS check
    GROUP BY f.id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permissions (restricted by RLS)
GRANT EXECUTE ON FUNCTION get_file_with_latest_version(UUID) TO authenticated;

