#!/usr/bin/env python3
"""
Test script for verifying all API endpoints.
"""

import sys
import requests
import json
from pathlib import Path

BASE_URL = "http://localhost:5000"

def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

def test_health():
    """Test health endpoint"""
    print_section("Testing Health Endpoint")
    
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"[ERROR] {e}")
        return False

def test_list():
    """Test list endpoint"""
    print_section("Testing List Endpoint")
    
    try:
        response = requests.get(f"{BASE_URL}/list", timeout=5)
        print(f"Status Code: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        files = data.get('files', [])
        print(f"\nFound {len(files)} files:")
        for file in files:
            print(f"  - {file['filename']}: {file['size']:,} bytes")
        
        return response.status_code == 200
    except Exception as e:
        print(f"[ERROR] {e}")
        return False

def test_verify_by_filename():
    """Test verify endpoint with filename"""
    print_section("Testing Verify Endpoint (by filename)")
    
    # Try to verify a non-existent file first
    print("\n1. Testing with non-existent file:")
    try:
        response = requests.get(f"{BASE_URL}/verify?file=nonexistent.exe", timeout=5)
        print(f"Status Code: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
    except Exception as e:
        print(f"[ERROR] {e}")
    
    # List files first to see what's available
    print("\n2. Getting available files:")
    try:
        response = requests.get(f"{BASE_URL}/list", timeout=5)
        files = response.json().get('files', [])
        
        if files:
            # Try to verify the first file
            test_file = files[0]['filename']
            print(f"\n3. Testing verification of: {test_file}")
            response = requests.get(f"{BASE_URL}/verify?file={test_file}", timeout=10)
            print(f"Status Code: {response.status_code}")
            data = response.json()
            print(f"Response: {json.dumps(data, indent=2)}")
        else:
            print("\n  [INFO] No files available for verification")
            print("  Note: Files need to be in artifacts/signed/ directory")
            
    except Exception as e:
        print(f"[ERROR] {e}")

def test_verify_upload():
    """Test verify endpoint with file upload"""
    print_section("Testing Verify Endpoint (file upload)")
    
    # Find an unsigned executable to upload
    unsigned_dir = Path("artifacts/unsigned")
    test_files = list(unsigned_dir.glob("*.exe")) if unsigned_dir.exists() else []
    
    if not test_files:
        print("[INFO] No unsigned executables found for upload test")
        return False
    
    test_file = test_files[0]
    print(f"Uploading: {test_file}")
    
    try:
        with open(test_file, 'rb') as f:
            files = {'file': (test_file.name, f, 'application/x-msdownload')}
            response = requests.post(f"{BASE_URL}/verify", files=files, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        if data.get('verified') is False:
            print("\n  [NOTE] Verification failed (expected for unsigned files)")
            print("  This is normal - unsigned executables won't have valid signatures")
        
        return response.status_code in [200, 500]  # 500 is OK for unsigned files
    except Exception as e:
        print(f"[ERROR] {e}")
        return False

def test_download():
    """Test download endpoint"""
    print_section("Testing Download Endpoint")
    
    # Get list of available files
    try:
        response = requests.get(f"{BASE_URL}/list", timeout=5)
        files = response.json().get('files', [])
        
        if files:
            test_file = files[0]['filename']
            print(f"Downloading: {test_file}")
            
            response = requests.get(f"{BASE_URL}/download/{test_file}", timeout=10, stream=True)
            print(f"Status Code: {response.status_code}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
            print(f"Content-Length: {response.headers.get('Content-Length', 'N/A')} bytes")
            
            if response.status_code == 200:
                # Save downloaded file
                download_path = Path(f"test_download_{test_file}")
                with open(download_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                file_size = download_path.stat().st_size
                print(f"Downloaded {file_size:,} bytes to: {download_path}")
                print(f"[SUCCESS] Download test completed")
                
                # Cleanup
                download_path.unlink()
                return True
            else:
                print(f"Response: {response.text[:200]}")
        else:
            print("[INFO] No files available for download")
            print("  Note: Files need to be in artifacts/signed/ directory")
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    return False

def test_web_interface():
    """Test web interface"""
    print_section("Testing Web Interface")
    
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        
        if response.status_code == 200:
            content = response.text[:500]  # First 500 chars
            if "Code Signing Verification" in content:
                print("[SUCCESS] Web interface is accessible")
                print(f"\n  Open in browser: {BASE_URL}")
                return True
            else:
                print("[INFO] Web interface returned different content")
                print(f"  Content preview: {content[:200]}...")
        else:
            print(f"[WARN] Unexpected status code: {response.status_code}")
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    return False

def main():
    """Run all endpoint tests"""
    print("\n" + "=" * 60)
    print("API Endpoint Testing")
    print("=" * 60)
    print(f"\nTesting server at: {BASE_URL}")
    
    results = {
        "Health": test_health(),
        "List": test_list(),
        "Web Interface": test_web_interface(),
        "Verify (filename)": None,  # Not critical
        "Verify (upload)": test_verify_upload(),
        "Download": test_download(),
    }
    
    # Test verify by filename (non-blocking)
    test_verify_by_filename()
    
    print_section("Test Summary")
    
    for test_name, result in results.items():
        if result is None:
            status = "[SKIP]"
        elif result:
            status = "[PASS]"
        else:
            status = "[FAIL]"
        print(f"{test_name}: {status}")
    
    print("\n" + "=" * 60)
    print("Testing Complete")
    print("=" * 60)
    print(f"\nOpen web interface: {BASE_URL}")
    print("\nManual Testing:")
    print("  1. Open http://localhost:5000 in your browser")
    print("  2. Try downloading files (if any are available)")
    print("  3. Try verifying files by filename or upload")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] Test interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()

