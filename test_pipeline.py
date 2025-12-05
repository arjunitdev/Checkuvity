#!/usr/bin/env python3
"""
Test script to verify the code signing pipeline.
"""

import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent

def test_certificates():
    """Test certificate generation"""
    print("=" * 60)
    print("Testing Certificates")
    print("=" * 60)
    
    cert_dir = PROJECT_ROOT / "certs"
    required_files = ["ca.cert.pem", "ca.key.pem", "signer.cert.pem", "signer.key.pem"]
    
    all_exist = True
    for cert_file in required_files:
        cert_path = cert_dir / cert_file
        if cert_path.exists():
            size = cert_path.stat().st_size
            print(f"[OK] {cert_file}: {size} bytes")
        else:
            print(f"[FAIL] {cert_file}: NOT FOUND")
            all_exist = False
    
    return all_exist

def test_build():
    """Test build artifacts"""
    print("\n" + "=" * 60)
    print("Testing Build Artifacts")
    print("=" * 60)
    
    unsigned_dir = PROJECT_ROOT / "artifacts" / "unsigned"
    required_files = ["app1.exe", "app2.exe", "app3.exe", "app4.exe", "unsigned_manifest.json"]
    
    all_exist = True
    for exe_file in required_files:
        exe_path = unsigned_dir / exe_file
        if exe_path.exists():
            size = exe_path.stat().st_size
            print(f"[OK] {exe_file}: {size:,} bytes")
        else:
            print(f"[FAIL] {exe_file}: NOT FOUND")
            all_exist = False
    
    # Check manifest
    manifest_path = unsigned_dir / "unsigned_manifest.json"
    if manifest_path.exists():
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        print(f"\n  Manifest: {len(manifest.get('artifacts', []))} artifacts listed")
        for artifact in manifest.get('artifacts', []):
            print(f"    - {artifact['filename']}: SHA256 {artifact['sha256'][:16]}...")
    
    return all_exist

def test_signed():
    """Test signed artifacts"""
    print("\n" + "=" * 60)
    print("Testing Signed Artifacts")
    print("=" * 60)
    
    signed_dir = PROJECT_ROOT / "artifacts" / "signed"
    
    signed_files = list(signed_dir.glob("*_signed.exe")) if signed_dir.exists() else []
    
    if signed_files:
        print(f"Found {len(signed_files)} signed executables:")
        for signed_file in signed_files:
            size = signed_file.stat().st_size
            print(f"  [OK] {signed_file.name}: {size:,} bytes")
        
        # Check metadata
        metadata_path = signed_dir / "signing_metadata.json"
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            print(f"\n  Signing metadata: {len(metadata.get('signatures', []))} entries")
    else:
        print("  [WARN] No signed executables found (signing requires osslsigncode or signtool)")
    
    return len(signed_files) > 0

def test_server():
    """Test server endpoints"""
    print("\n" + "=" * 60)
    print("Testing Server")
    print("=" * 60)
    
    try:
        import requests
        
        base_url = "http://localhost:5000"
        
        # Test health endpoint
        try:
            response = requests.get(f"{base_url}/health", timeout=2)
            if response.status_code == 200:
                print(f"[OK] Health endpoint: OK - {response.json()}")
            else:
                print(f"[FAIL] Health endpoint: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("[WARN] Server not running (start with: python demo_server/server.py)")
            return False
        except requests.exceptions.Timeout:
            print("[WARN] Server timeout")
            return False
        
        # Test list endpoint
        try:
            response = requests.get(f"{base_url}/list", timeout=2)
            if response.status_code == 200:
                files = response.json().get('files', [])
                print(f"[OK] List endpoint: {len(files)} files available")
            else:
                print(f"[FAIL] List endpoint: {response.status_code}")
        except Exception as e:
            print(f"⚠ List endpoint error: {e}")
        
        return True
    except ImportError:
        print("[WARN] requests library not available for server testing")
        return False

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("Code Signing Pipeline Test")
    print("=" * 60)
    
    results = {
        "Certificates": test_certificates(),
        "Build": test_build(),
        "Signed": test_signed(),
        "Server": test_server()
    }
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for test_name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"{test_name}: {status}")
    
    all_passed = all(results.values())
    
    if all_passed:
        print("\n[SUCCESS] All tests passed!")
    else:
        print("\n[WARN] Some tests failed or are incomplete")
        if not results["Signed"]:
            print("\n  Note: Signing requires osslsigncode or signtool.exe")
            print("  Download osslsigncode from: https://github.com/mtrojnar/osslsigncode")
            print("  Or install Windows SDK for signtool.exe")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())

