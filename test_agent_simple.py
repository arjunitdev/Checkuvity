#!/usr/bin/env python3
"""
Simple test script to verify the security agent is working
"""

import requests
import json
from pathlib import Path

BASE_URL = "http://localhost:5000"
USER_ID = "00000000-0000-0000-0000-000000000000"

def test_agent():
    print("=" * 60)
    print("Security Agent Test")
    print("=" * 60)
    
    # 1. Check if server is running
    print("\n1. Checking server status...")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        if r.status_code == 200:
            print("   [OK] Server is running")
            print(f"   Response: {r.json()}")
        else:
            print(f"   [ERROR] Server returned status {r.status_code}")
            return
    except Exception as e:
        print(f"   [ERROR] Cannot connect to server: {e}")
        print("   Make sure the server is running: python demo_server/server.py")
        return
    
    # 2. List existing files
    print("\n2. Listing files...")
    try:
        r = requests.get(f"{BASE_URL}/api/files", params={"user_id": USER_ID}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            files = data.get('files', [])
            print(f"   [OK] Found {len(files)} file(s)")
            
            if not files:
                print("   [INFO] No files found. Upload a file first to test the agent.")
                return
            
            # Use the first file
            file_id = files[0].get('id')
            file_name = files[0].get('file_name', 'N/A')
            print(f"   Using file: {file_name} (ID: {file_id})")
        else:
            print(f"   [ERROR] Failed to list files: {r.status_code}")
            return
    except Exception as e:
        print(f"   [ERROR] Failed to list files: {e}")
        return
    
    # 3. Verify file security (this triggers the agent)
    print(f"\n3. Verifying file security (triggering agent)...")
    print(f"   This may take 30-60 seconds...")
    try:
        r = requests.get(f"{BASE_URL}/api/verify-security/{file_id}", timeout=120)
        if r.status_code == 200:
            assessment = r.json()
            print("   [OK] Security verification completed!")
            print(f"\n   Security Assessment:")
            print(f"   - Status: {assessment.get('security_status', 'unknown')}")
            print(f"   - Score: {assessment.get('security_score', 0)}/100")
            print(f"   - Trusted: {assessment.get('trusted', False)}")
            
            if assessment.get('public_key_hash'):
                print(f"   - Public Key Hash: {assessment['public_key_hash'][:32]}...")
            
            if assessment.get('recommendations'):
                print(f"\n   Recommendations ({len(assessment['recommendations'])}):")
                for i, rec in enumerate(assessment['recommendations'], 1):
                    print(f"   {i}. {rec}")
            
            if assessment.get('threats_detected'):
                print(f"\n   Threats Detected ({len(assessment['threats_detected'])}):")
                for i, threat in enumerate(assessment['threats_detected'], 1):
                    print(f"   {i}. {threat}")
        else:
            print(f"   [ERROR] Verification failed: {r.status_code}")
            print(f"   Response: {r.text}")
    except Exception as e:
        print(f"   [ERROR] Verification failed: {e}")
    
    # 4. Get security status
    print(f"\n4. Getting security status...")
    try:
        r = requests.get(f"{BASE_URL}/api/security-status/{file_id}", timeout=10)
        if r.status_code == 200:
            status = r.json()
            print("   [OK] Security status retrieved")
            print(f"   - Status: {status.get('security_status', 'unknown')}")
            print(f"   - Score: {status.get('security_score', 0)}/100")
            print(f"   - Verified At: {status.get('verification_time', 'N/A')}")
        elif r.status_code == 404:
            print("   [INFO] No verification result found yet")
        else:
            print(f"   [ERROR] Failed to get status: {r.status_code}")
    except Exception as e:
        print(f"   [ERROR] Failed to get status: {e}")
    
    # 5. List trusted public keys
    print(f"\n5. Listing trusted public keys...")
    try:
        r = requests.get(f"{BASE_URL}/api/trusted-keys", timeout=10)
        if r.status_code == 200:
            data = r.json()
            keys = data.get('keys', [])
            print(f"   [OK] Found {len(keys)} trusted key(s)")
            
            if keys:
                for i, key in enumerate(keys, 1):
                    print(f"\n   Key {i}:")
                    print(f"   - Hash: {key.get('public_key_hash', 'N/A')[:32]}...")
                    print(f"   - Type: {key.get('key_type', 'N/A')}")
                    print(f"   - Size: {key.get('key_size', 'N/A')}")
                    print(f"   - Trust Level: {key.get('trust_level', 'N/A')}")
                    print(f"   - Owner: {key.get('owner_name', 'N/A')}")
            else:
                print("   [INFO] No trusted keys registered yet")
        else:
            print(f"   [ERROR] Failed to list keys: {r.status_code}")
    except Exception as e:
        print(f"   [ERROR] Failed to list keys: {e}")
    
    print("\n" + "=" * 60)
    print("Test Complete!")
    print("=" * 60)
    print("\nTo see public keys from verified files:")
    print("1. Upload a file with a signature")
    print("2. The agent will extract the public key")
    print("3. Check /api/verify-security/<file_id> for public_key_hash")
    print("4. Add trusted keys via POST /api/trusted-keys")

if __name__ == '__main__':
    test_agent()

