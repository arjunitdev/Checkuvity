#!/usr/bin/env python3
"""Quick test script for all endpoints"""

import requests

BASE_URL = "http://localhost:5000"

print("=" * 60)
print("Quick Endpoint Tests")
print("=" * 60)

# Test 1: Health
print("\n1. Health Check:")
try:
    r = requests.get(f"{BASE_URL}/health", timeout=5)
    print(f"   Status: {r.status_code}")
    print(f"   Response: {r.json()}")
except Exception as e:
    print(f"   ERROR: {e}")

# Test 2: List
print("\n2. List Files:")
try:
    r = requests.get(f"{BASE_URL}/list", timeout=5)
    print(f"   Status: {r.status_code}")
    data = r.json()
    print(f"   Response: {len(data.get('files', []))} files")
except Exception as e:
    print(f"   ERROR: {e}")

# Test 3: Verify without filename (should get error)
print("\n3. Verify WITHOUT filename (expected 400):")
try:
    r = requests.get(f"{BASE_URL}/verify", timeout=5)
    print(f"   Status: {r.status_code}")
    data = r.json()
    print(f"   Error: {data.get('errors', ['Unknown'])[0]}")
except Exception as e:
    print(f"   ERROR: {e}")

# Test 4: Verify with nonexistent filename
print("\n4. Verify WITH nonexistent filename (expected 404):")
try:
    r = requests.get(f"{BASE_URL}/verify?file=nonexistent.exe", timeout=5)
    print(f"   Status: {r.status_code}")
    data = r.json()
    print(f"   Error: {data.get('errors', ['Unknown'])[0]}")
except Exception as e:
    print(f"   ERROR: {e}")

print("\n" + "=" * 60)
print("Summary:")
print("  - Call /verify with ?file=<filename> parameter")
print("  - Or POST a file to /verify endpoint")
print("  - See HOW_TO_TEST.md for complete guide")
print("=" * 60)

