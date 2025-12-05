#!/usr/bin/env python3
"""
Supabase Configuration Script
Uses Supabase MCP and Python client to configure the project
"""

import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "build_scripts"))

def check_environment():
    """Check if .env file exists and has required variables"""
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        print("[X] .env file not found")
        print("    Create .env file with Supabase credentials")
        return False
    
    # Load .env file
    env_vars = {}
    with open(env_path, 'r', encoding='utf-8-sig') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()
    
    required = ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY']
    missing = [key for key in required if not env_vars.get(key) or env_vars[key] == f'YOUR_{key}_HERE' or env_vars[key].startswith('YOUR_')]
    
    if missing:
        print(f"[X] Missing or incomplete variables in .env: {', '.join(missing)}")
        if 'SUPABASE_SERVICE_ROLE_KEY' in missing:
            print("\n[!] To get your service role key:")
            print("    1. Go to https://supabase.com/dashboard")
            print("    2. Select your project: 'Text File Signature Verification'")
            print("    3. Go to Settings > API")
            print("    4. Copy the 'service_role' key")
            print("    5. Update .env file with the actual key")
        return False
    
    print("[OK] .env file exists and has all required variables")
    return True, env_vars

def create_storage_bucket():
    """Create the text-files storage bucket using Supabase client"""
    try:
        from build_scripts.supabase_client import SupabaseFileManager
        
        print("\n[!] Creating storage bucket 'text-files'...")
        manager = SupabaseFileManager(use_service_role=True)
        
        # Check if bucket already exists
        try:
            buckets = manager.client.storage.list_buckets()
            existing_buckets = [b.name for b in buckets]
            
            if 'text-files' in existing_buckets:
                print("[OK] Storage bucket 'text-files' already exists!")
                return True
            
            # Create bucket (using storage API)
            # Note: The Python client may not have direct bucket creation
            # We'll try to use it, otherwise provide instructions
            try:
                # Try to create bucket via client
                # This might not be available in the client, so we'll check first
                print("[!] Attempting to create bucket via API...")
                
                # The Supabase Python client doesn't have a direct create_bucket method
                # We need to use the REST API directly
                import requests
                
                url = os.getenv('SUPABASE_URL')
                service_role_key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
                
                # Create bucket via REST API
                bucket_url = f"{url}/storage/v1/bucket"
                headers = {
                    'Authorization': f'Bearer {service_role_key}',
                    'apikey': service_role_key,
                    'Content-Type': 'application/json'
                }
                payload = {
                    'name': 'text-files',
                    'public': True,
                    'file_size_limit': None,
                    'allowed_mime_types': None
                }
                
                response = requests.post(bucket_url, json=payload, headers=headers)
                
                if response.status_code == 200 or response.status_code == 201:
                    print("[OK] Storage bucket 'text-files' created successfully!")
                    return True
                elif response.status_code == 409:
                    print("[OK] Storage bucket 'text-files' already exists!")
                    return True
                else:
                    print(f"[!] Could not create bucket via API (status {response.status_code})")
                    print("    You'll need to create it manually:")
                    print("    1. Go to https://supabase.com/dashboard")
                    print("    2. Select your project")
                    print("    3. Go to Storage")
                    print("    4. Click 'Create a new bucket'")
                    print("    5. Name: 'text-files'")
                    print("    6. Make it Public")
                    return False
                    
            except Exception as e:
                print(f"[!] Error creating bucket: {e}")
                print("    You'll need to create it manually in the Supabase Dashboard")
                return False
                
        except Exception as e:
            print(f"[!] Error checking buckets: {e}")
            print("    You'll need to create it manually in the Supabase Dashboard")
            return False
            
    except ImportError:
        print("[X] supabase-py not installed")
        print("    Install: pip install supabase requests")
        return False
    except Exception as e:
        print(f"[X] Error: {e}")
        return False

def verify_setup():
    """Verify the Supabase setup"""
    try:
        from build_scripts.supabase_client import SupabaseFileManager
        
        print("\n[!] Verifying Supabase setup...")
        manager = SupabaseFileManager(use_service_role=True)
        print("[OK] Supabase connection successful!")
        
        # Test database tables
        print("\n[!] Testing database tables...")
        try:
            result = manager.client.table("files").select("id").limit(1).execute()
            print("[OK] Database connection successful!")
            print("[OK] 'files' table exists")
        except Exception as e:
            print(f"[!] Database issue: {e}")
            return False
        
        # Test storage bucket
        print("\n[!] Testing storage bucket...")
        try:
            result = manager.client.storage.from_('text-files').list()
            print("[OK] Storage bucket 'text-files' exists and is accessible!")
        except Exception as e:
            if "not found" in str(e).lower() or "does not exist" in str(e).lower():
                print("[!] Storage bucket 'text-files' not found")
                print("    Create it in Supabase Dashboard: Storage > Create bucket")
                return False
            else:
                print(f"[!] Storage connection issue: {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"[X] Verification failed: {e}")
        return False

def main():
    """Main setup function"""
    print("=" * 60)
    print("Supabase Configuration Script")
    print("=" * 60)
    
    # Check environment
    env_check = check_environment()
    if isinstance(env_check, tuple):
        has_env, env_vars = env_check
        if not has_env:
            return
    elif not env_check:
        return
    
    # Create storage bucket
    bucket_created = create_storage_bucket()
    
    # Verify setup
    if verify_setup():
        print("\n" + "=" * 60)
        print("[OK] Setup Complete!")
        print("=" * 60)
        print("\nYou can now:")
        print("  1. Start the server: python demo_server/server.py")
        print("  2. Access the web UI: http://localhost:5000")
        print("\nThe server will connect to Supabase automatically!")
    else:
        print("\n" + "=" * 60)
        print("[!] Setup Incomplete")
        print("=" * 60)
        print("\nPlease:")
        print("  1. Ensure storage bucket 'text-files' exists in Supabase Dashboard")
        print("  2. Run this script again to verify")

if __name__ == "__main__":
    main()

