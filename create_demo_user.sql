-- Create demo user for development/testing
-- This script creates a demo user in auth.users if it doesn't exist
-- WARNING: Only use this in development! In production, users should be created via Supabase Auth

INSERT INTO auth.users (
    id,
    instance_id,
    email,
    encrypted_password,
    email_confirmed_at,
    created_at,
    updated_at,
    raw_app_meta_data,
    raw_user_meta_data,
    is_super_admin,
    role,
    aud,
    confirmation_token,
    recovery_token
)
VALUES (
    '00000000-0000-0000-0000-000000000000'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'demo@example.com',
    '$2a$10$XOPbrlUPQdwdJUpSrIF6X.LbE14qsMmKGhM8A9Xo3y27JmzYWnmUi', -- bcrypt hash for 'password'
    NOW(),
    NOW(),
    NOW(),
    '{"provider": "email", "providers": ["email"]}',
    '{"demo": true, "name": "Demo User"}',
    false,
    'authenticated',
    'authenticated',
    '',
    ''
)
ON CONFLICT (id) DO UPDATE
SET 
    email = EXCLUDED.email,
    updated_at = NOW();

-- Verify the user was created
SELECT id, email, created_at 
FROM auth.users 
WHERE id = '00000000-0000-0000-0000-000000000000';

