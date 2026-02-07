#!/usr/bin/env python3
"""
Configuration for Security Verification Service
"""

import os
from pathlib import Path
from typing import Dict, Any

# Load environment variables
try:
    from dotenv import load_dotenv
    PROJECT_ROOT = Path(__file__).parent.parent
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # dotenv not required if env vars are set directly



# Supabase Configuration
SUPABASE_CONFIG = {
    "url": os.getenv("SUPABASE_URL", ""),
    "service_role_key": os.getenv("SUPABASE_SERVICE_ROLE_KEY", ""),
    "anon_key": os.getenv("SUPABASE_ANON_KEY", ""),
}

# Security Policy Configuration
SECURITY_POLICY = {
    "trust_levels": ["trusted", "verified", "suspicious", "blocked"],
    "min_security_score": 70,  # Minimum score for "secure" status
    "auto_block_threshold": 30,  # Score below which to auto-block
    "warning_threshold": 50,  # Score below which to warn
    "score_weights": {
        "signature_verified": 30,
        "chain_valid": 25,
        "timestamp_valid": 10,
        "trusted_key": 20,
        "no_threats": 15,
        "hash_match": 20,
        "hash_mismatch_penalty": 50,
    },
    "status_mapping": {
        "secure": {"min_score": 70, "max_score": 100},
        "warning": {"min_score": 50, "max_score": 69},
        "blocked": {"min_score": 0, "max_score": 29},
        "unknown": {"min_score": 30, "max_score": 49},
    },
}

# Service Version
SERVICE_VERSION = "1.0.0"


