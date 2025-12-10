#!/usr/bin/env python3
"""
Main entry point for Security Verification Service
Can be run independently for testing
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "security_service"))

from service import SecurityVerificationService
from security_service.config import validate_config


def main():
    """Main entry point for standalone verification service"""
    parser = argparse.ArgumentParser(description="Security Verification Service")
    parser.add_argument("--file-id", type=str, help="File ID to verify")
    parser.add_argument("--file-path", type=str, help="Path to file to verify")
    parser.add_argument("--user-id", type=str, default="00000000-0000-0000-0000-000000000000", help="User ID")
    parser.add_argument("--validate-config", action="store_true", help="Validate configuration and exit")
    
    args = parser.parse_args()
    
    # Validate configuration
    if args.validate_config:
        if validate_config():
            print("Configuration is valid")
            sys.exit(0)
        else:
            print("Configuration is invalid - check environment variables")
            sys.exit(1)
    
    # Validate required configuration
    if not validate_config():
        print("Error: Configuration is invalid")
        print("Required environment variables:")
        print("  - OPENAI_API_KEY")
        print("  - SUPABASE_URL")
        print("  - SUPABASE_SERVICE_ROLE_KEY")
        sys.exit(1)
    
    # Initialize service
    try:
        service = SecurityVerificationService()
    except Exception as e:
        print(f"Error initializing service: {e}")
        sys.exit(1)
    
    # Verify file if provided
    if args.file_id:
        print(f"Verifying file: {args.file_id}")
        try:
            assessment = service.verify_file(args.file_id, args.user_id, args.file_path)
            print("\nSecurity Assessment:")
            print(f"  Status: {assessment.get('security_status', 'unknown')}")
            print(f"  Score: {assessment.get('security_score', 0)}/100")
            print(f"  Trusted: {assessment.get('trusted', False)}")
            if assessment.get('public_key_hash'):
                print(f"  Public Key Hash: {assessment['public_key_hash'][:16]}...")
            if assessment.get('threats_detected'):
                print(f"  Threats Detected: {len(assessment['threats_detected'])}")
            if assessment.get('recommendations'):
                print(f"  Recommendations: {len(assessment['recommendations'])}")
        except Exception as e:
            print(f"Error verifying file: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    elif args.file_path:
        print(f"Verifying file at path: {args.file_path}")
        print("Note: File path verification requires file_id. Use --file-id option.")
        sys.exit(1)
    else:
        print("Security Verification Service")
        print("Use --file-id to verify a file")
        print("Use --validate-config to validate configuration")
        print("Use --help for more options")


if __name__ == '__main__':
    main()

