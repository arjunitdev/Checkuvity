#!/usr/bin/env python3
"""
Test script for Security Agent Service
Tests the agent through multiple methods:
1. Direct service call
2. API endpoint calls
3. File upload with automatic verification
"""

import sys
import os
import requests
import json
from pathlib import Path
from typing import Dict, Any, Optional

import pytest

# These tests exercise the live security verification stack and require the demo
# server plus Supabase credentials. Skip by default so unit test runs remain
# green; developers can run this module directly (python test_security_agent.py)
# when the environment is ready.
pytestmark = pytest.mark.skip(reason="requires running demo server + Supabase environment")

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "security_agent_service"))

# Test configuration
BASE_URL = "http://localhost:5000"
DEFAULT_USER_ID = "00000000-0000-0000-0000-000000000000"


def test_direct_service(file_id: str, user_id: str = DEFAULT_USER_ID) -> Optional[Dict[str, Any]]:
    """Test the security agent service directly"""
    print("\n" + "="*60)
    print("TEST 1: Direct Service Call")
    print("="*60)
    
    try:
        from security_agent_service.service import SecurityVerificationService
        
        print(f"Initializing SecurityVerificationService...")
        service = SecurityVerificationService()
        
        print(f"Verifying file: {file_id}")
        print(f"User ID: {user_id}")
        
        assessment = service.verify_file(file_id, user_id)
        
        print("\n[OK] Security Assessment:")
        print(f"  Status: {assessment.get('security_status', 'unknown')}")
        print(f"  Score: {assessment.get('security_score', 0)}/100")
        print(f"  Trusted: {assessment.get('trusted', False)}")
        
        if assessment.get('public_key_hash'):
            print(f"  Public Key Hash: {assessment['public_key_hash'][:32]}...")
        
        if assessment.get('threats_detected'):
            print(f"  Threats Detected: {len(assessment['threats_detected'])}")
            for threat in assessment['threats_detected']:
                print(f"    - {threat}")
        
        if assessment.get('recommendations'):
            print(f"  Recommendations: {len(assessment['recommendations'])}")
            for rec in assessment['recommendations']:
                print(f"    - {rec}")
        
        if assessment.get('details'):
            print(f"\n  Details: {json.dumps(assessment['details'], indent=2)}")
        
        return assessment
        
    except ImportError as e:
        print(f"[ERROR] Security service not available: {e}")
        print("  Make sure OPENAI_API_KEY is set in .env")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return None


def test_api_verify_security(file_id: str) -> Optional[Dict[str, Any]]:
    """Test the /api/verify-security endpoint"""
    print("\n" + "="*60)
    print("TEST 2: API Endpoint - Verify Security")
    print("="*60)
    
    url = f"{BASE_URL}/api/verify-security/{file_id}"
    print(f"GET {url}")
    
    try:
        response = requests.get(url, timeout=120)  # Agent may take time
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("\n[OK] Security Assessment:")
            print(f"  Status: {data.get('security_status', 'unknown')}")
            print(f"  Score: {data.get('security_score', 0)}/100")
            print(f"  Trusted: {data.get('trusted', False)}")
            
            if data.get('details'):
                print(f"\n  Details: {json.dumps(data['details'], indent=2)}")
            
            return data
        else:
            print(f"[ERROR] Status Code: {response.status_code}")
            print(f"  Response: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Could not connect to {BASE_URL}")
        print("  Make sure the server is running: python demo_server/server.py")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None


def test_api_security_status(file_id: str) -> Optional[Dict[str, Any]]:
    """Test the /api/security-status endpoint"""
    print("\n" + "="*60)
    print("TEST 3: API Endpoint - Security Status")
    print("="*60)
    
    url = f"{BASE_URL}/api/security-status/{file_id}"
    print(f"GET {url}")
    
    try:
        response = requests.get(url, timeout=30)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("\n[OK] Security Status:")
            print(f"  Status: {data.get('security_status', 'unknown')}")
            print(f"  Score: {data.get('security_score', 0)}/100")
            print(f"  Verification Time: {data.get('verification_time', 'N/A')}")
            
            return data
        elif response.status_code == 404:
            print("  No verification result found (file may not be verified yet)")
            return None
        else:
            print(f"[ERROR] Status Code: {response.status_code}")
            print(f"  Response: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Could not connect to {BASE_URL}")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None


def test_api_trusted_keys() -> Optional[Dict[str, Any]]:
    """Test the /api/trusted-keys endpoint"""
    print("\n" + "="*60)
    print("TEST 4: API Endpoint - List Trusted Keys")
    print("="*60)
    
    url = f"{BASE_URL}/api/trusted-keys"
    print(f"GET {url}")
    
    try:
        response = requests.get(url, timeout=30)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            keys = data.get('keys', [])
            print(f"\n[OK] Found {len(keys)} trusted key(s)")
            
            for key in keys:
                print(f"  - Hash: {key.get('public_key_hash', 'N/A')[:32]}...")
                print(f"    Type: {key.get('key_type', 'N/A')}")
                print(f"    Trust Level: {key.get('trust_level', 'N/A')}")
            
            return data
        else:
            print(f"[ERROR] Status Code: {response.status_code}")
            print(f"  Response: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Could not connect to {BASE_URL}")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None


def test_file_upload_with_verification(file_path: Path) -> Optional[Dict[str, Any]]:
    """Test file upload with automatic security verification"""
    print("\n" + "="*60)
    print("TEST 5: File Upload with Automatic Verification")
    print("="*60)
    
    url = f"{BASE_URL}/api/files"
    print(f"POST {url}")
    print(f"Uploading file: {file_path}")
    
    if not file_path.exists():
        print(f"✗ Error: File not found: {file_path}")
        return None
    
    try:
        with open(file_path, 'rb') as f:
            files = {'files': (file_path.name, f, 'text/plain')}
            data = {'user_id': DEFAULT_USER_ID}
            
            response = requests.post(url, files=files, data=data, timeout=120)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            files_result = result.get('files', [])
            
            if files_result:
                file_result = files_result[0]
                if file_result.get('success'):
                    file_id = file_result['file'].get('id')
                    print(f"\n[OK] File uploaded successfully")
                    print(f"  File ID: {file_id}")
                    
                    # Check if security verification was triggered
                    if 'security' in file_result:
                        security = file_result['security']
                        print(f"\n[OK] Security Verification (automatic):")
                        print(f"  Status: {security.get('status', 'unknown')}")
                        print(f"  Score: {security.get('score', 0)}/100")
                    else:
                        print("\n  Note: Security verification not triggered automatically")
                        print("  (This may be normal if the service is not configured)")
                    
                    return file_result
                else:
                    print(f"[ERROR] Upload failed: {file_result.get('error', 'Unknown error')}")
                    return None
            else:
                print("[ERROR] No files in response")
                return None
        else:
            print(f"[ERROR] Status Code: {response.status_code}")
            print(f"  Response: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Could not connect to {BASE_URL}")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None


def list_files() -> Optional[list]:
    """List all files to get a file_id for testing"""
    print("\n" + "="*60)
    print("Listing Files")
    print("="*60)
    
    url = f"{BASE_URL}/api/files"
    params = {'user_id': DEFAULT_USER_ID}
    print(f"GET {url}?user_id={DEFAULT_USER_ID}")
    
    try:
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            files = data.get('files', [])
            print(f"\n[OK] Found {len(files)} file(s)")
            
            for i, file in enumerate(files, 1):
                print(f"\n  {i}. File: {file.get('file_name', 'N/A')}")
                print(f"     ID: {file.get('id', 'N/A')}")
                print(f"     Security Status: {file.get('security_status', 'unknown')}")
                print(f"     Security Score: {file.get('security_score', 0)}/100")
            
            return files
        else:
            print(f"[ERROR] Status Code: {response.status_code}")
            print(f"  Response: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Could not connect to {BASE_URL}")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None


def main():
    """Main test function"""
    print("\n" + "="*60)
    print("Security Agent Service - Test Suite")
    print("="*60)
    
    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code != 200:
            print(f"[ERROR] Server health check failed: {response.status_code}")
            return
        print("[OK] Server is running")
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Server is not running at {BASE_URL}")
        print("  Start the server: python demo_server/server.py")
        return
    
    # List files to get a file_id
    files = list_files()
    
    if not files:
        print("\n[WARN] No files found. Creating a test file...")
        # Create a simple test file
        test_file = PROJECT_ROOT / "test_file.txt"
        test_content = "Original Hash: abc123def456\nSignature: sig789\nPost-Signature Hash: xyz987"
        test_file.write_text(test_content)
        
        print(f"Uploading test file: {test_file}")
        upload_result = test_file_upload_with_verification(test_file)
        
        if upload_result and upload_result.get('file'):
            file_id = upload_result['file'].get('id')
        else:
            print("\n[ERROR] Could not create test file. Exiting.")
            return
    else:
        # Use the first file
        file_id = files[0].get('id')
        print(f"\nUsing file ID: {file_id}")
    
    # Run tests
    print("\n" + "="*60)
    print("Running Tests")
    print("="*60)
    
    # Test 1: Direct service call
    test_direct_service(file_id)
    
    # Test 2: API verify security
    test_api_verify_security(file_id)
    
    # Test 3: API security status
    test_api_security_status(file_id)
    
    # Test 4: List trusted keys
    test_api_trusted_keys()
    
    print("\n" + "="*60)
    print("Test Suite Complete")
    print("="*60)
    print("\nNote: If security verification fails, check:")
    print("  1. OPENAI_API_KEY is set in .env")
    print("  2. Supabase credentials are correct")
    print("  3. Security agent service is properly installed")


if __name__ == '__main__':
    main()

