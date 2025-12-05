#!/usr/bin/env python3
"""Test Supabase connection and setup"""
import os
from pathlib import Path

def test_env_file():
    """Check if .env file exists and has required variables"""
    env_path = Path(".env")
    if not env_path.exists():
        print("[X] .env file not found")
        print("\n[!] Create a .env file in the project root with:")
        print("   SUPABASE_URL=https://your-project-id.supabase.co")
        print("   SUPABASE_ANON_KEY=your-anon-key")
        print("   SUPABASE_SERVICE_ROLE_KEY=your-service-role-key")
        print("   DEMO_MODE=false")
        return False
    
    # Load .env file (handle BOM)
    env_vars = {}
    with open(env_path, 'r', encoding='utf-8-sig') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()
    
    required = ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY']
    missing = [key for key in required if not env_vars.get(key) or env_vars[key] == f'your-{key.lower().replace("_", "-")}']
    
    if missing:
        print(f"[X] Missing or incomplete variables in .env: {', '.join(missing)}")
        return False
    
    print("[OK] .env file exists and has all required variables")
    return True

def test_supabase_connection():
    """Test actual Supabase connection"""
    try:
        # Import after checking env
        from build_scripts.supabase_client import SupabaseFileManager
        
        print("\n[!] Testing Supabase connection...")
        manager = SupabaseFileManager(use_service_role=True)
        print("[OK] Supabase connection successful!")
        
        # Test database tables
        print("\n[!] Testing database tables...")
        try:
            # Try to query files table (will fail if table doesn't exist, but connection works)
            result = manager.client.table("files").select("id").limit(1).execute()
            print("[OK] Database connection successful!")
            print("[OK] 'files' table exists")
        except Exception as e:
            if "does not exist" in str(e).lower() or "relation" in str(e).lower():
                print("[!] Database connected but 'files' table not found")
                print("    Run the schema from supabase/schema.sql in Supabase SQL Editor")
            else:
                print(f"[!] Database connection issue: {e}")
        
        # Test storage bucket
        print("\n[!] Testing storage bucket...")
        try:
            # Try to list bucket (will fail if bucket doesn't exist)
            result = manager.client.storage.from_(manager.bucket_name).list()
            print(f"[OK] Storage bucket '{manager.bucket_name}' exists!")
        except Exception as e:
            if "not found" in str(e).lower() or "does not exist" in str(e).lower():
                print(f"[!] Storage bucket '{manager.bucket_name}' not found")
                print("    Create it in Supabase Dashboard: Storage > Create bucket")
            else:
                print(f"[!] Storage connection issue: {e}")
        
        return True
        
    except ImportError as e:
        print(f"[X] Missing dependencies: {e}")
        print("    Install: pip install -r requirements.txt")
        return False
    except ValueError as e:
        print(f"[X] Configuration error: {e}")
        print("    Check your .env file and Supabase credentials")
        return False
    except Exception as e:
        print(f"[X] Connection failed: {e}")
        print("    Verify your SUPABASE_URL and keys are correct")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("Supabase Connection Test")
    print("=" * 60)
    
    if not test_env_file():
        print("\nSee SETUP_SUPABASE.md for setup instructions")
        return
    
    if test_supabase_connection():
        print("\n" + "=" * 60)
        print("[OK] Setup Complete!")
        print("=" * 60)
        print("\nYou can now:")
        print("  1. Start the server: python demo_server/server.py")
        print("  2. Access the web UI: http://localhost:5000")
    else:
        print("\n" + "=" * 60)
        print("[!] Setup Incomplete")
        print("=" * 60)
        print("\nSee SETUP_SUPABASE.md for troubleshooting")

if __name__ == "__main__":
    main()

