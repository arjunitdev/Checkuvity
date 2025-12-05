#!/usr/bin/env python3
"""Test API endpoints"""
import requests
import json

BASE_URL = "http://localhost:5000"

def test_health():
    """Test health endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Health check: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Health check failed: {e}")
        return False

def test_list_files():
    """Test list files endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/api/files?user_id=00000000-0000-0000-0000-000000000000")
        print(f"\nList files: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"List files failed: {e}")
        return False

def test_upload_file():
    """Test upload endpoint"""
    try:
        # Create a test file
        test_content = """
1. Pre-Signature Hash (SHA-256):
68d2b4b76a937916e26531c607f6bc21f80a76539ca42ad99e539b3590c6d658

2. Security Signature:
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

4. Post-Signature Hash (SHA-256):
9f8e7d6c5b4a39383746543219284756fedcba9876543210fedcba9876543210
"""
        files = {'files': ('test.txt', test_content, 'text/plain')}
        data = {'user_id': '00000000-0000-0000-0000-000000000000'}
        
        response = requests.post(f"{BASE_URL}/api/files", files=files, data=data)
        print(f"\nUpload file: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Upload failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing API endpoints...")
    print("=" * 60)
    
    if not test_health():
        print("\nServer is not running. Start it with: python demo_server/server.py")
        exit(1)
    
    test_list_files()
    test_upload_file()
    
    print("\n" + "=" * 60)
    print("Tests complete!")

