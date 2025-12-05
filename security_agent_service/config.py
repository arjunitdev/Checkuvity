#!/usr/bin/env python3
"""
Configuration for Security Agent Service
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


# AutoGen Configuration
AUTOGEN_CONFIG = {
    "model": os.getenv("OPENAI_MODEL", "gpt-4"),
    "api_key": os.getenv("OPENAI_API_KEY", ""),
    "temperature": 0.1,  # Low temperature for consistent decisions
    "max_tokens": 2000,
    "timeout": 60,  # Timeout in seconds
}

# Agent Configuration
AGENT_CONFIG = {
    "orchestrator": {
        "max_consecutive_auto_reply": 10,
        "human_input_mode": "NEVER",
        "temperature": 0.1,
    },
    "signature_verifier": {
        "max_consecutive_auto_reply": 5,
        "human_input_mode": "NEVER",
        "temperature": 0.0,  # Very low for technical verification
    },
    "public_key_agent": {
        "max_consecutive_auto_reply": 5,
        "human_input_mode": "NEVER",
        "temperature": 0.1,
    },
    "threat_intel": {
        "max_consecutive_auto_reply": 3,
        "human_input_mode": "NEVER",
        "temperature": 0.1,
    },
    "policy_agent": {
        "max_consecutive_auto_reply": 5,
        "human_input_mode": "NEVER",
        "temperature": 0.1,
    },
    "reporter": {
        "max_consecutive_auto_reply": 3,
        "human_input_mode": "NEVER",
        "temperature": 0.2,  # Slightly higher for report generation
    },
}

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

# Agent Version
AGENT_VERSION = "1.0.0"

# Workflow Configuration
WORKFLOW_CONFIG = {
    "max_rounds": 20,  # Maximum conversation rounds
    "timeout": 120,  # Timeout in seconds
    "enable_parallel": False,  # Enable parallel agent execution
}

def get_llm_config(agent_name: str = "default") -> Dict[str, Any]:
    """
    Get LLM configuration for an agent
    
    Args:
        agent_name: Name of the agent
        
    Returns:
        LLM configuration dictionary
    """
    agent_config = AGENT_CONFIG.get(agent_name, {})
    
    return {
        "config_list": [{
            "model": AUTOGEN_CONFIG["model"],
            "api_key": AUTOGEN_CONFIG["api_key"],
            "temperature": agent_config.get("temperature", AUTOGEN_CONFIG["temperature"]),
        }],
        "timeout": AUTOGEN_CONFIG.get("timeout", 60),
        "max_tokens": AUTOGEN_CONFIG.get("max_tokens", 2000),
    }

def validate_config() -> bool:
    """
    Validate that required configuration is present
    
    Returns:
        True if valid, False otherwise
    """
    if not AUTOGEN_CONFIG.get("api_key"):
        print("Warning: OPENAI_API_KEY not set")
        return False
    
    if not SUPABASE_CONFIG.get("url") or not SUPABASE_CONFIG.get("service_role_key"):
        print("Warning: Supabase configuration missing")
        return False
    
    return True

