#!/usr/bin/env python3
"""Test script to check server routes"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from demo_server.server import app
    print("=" * 60)
    print("Available Routes:")
    print("=" * 60)
    for rule in app.url_map.iter_rules():
        methods = ', '.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
        print(f"{methods:20} {rule.rule}")
    print("=" * 60)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

