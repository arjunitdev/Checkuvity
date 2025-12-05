#!/usr/bin/env python3
"""
Public Key Agent - Public key extraction and trust analysis
"""

import sys
from pathlib import Path
from typing import Dict, Any
from autogen import ConversableAgent

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_agent_service.config import get_llm_config, AGENT_CONFIG
from tools.public_key_store import PublicKeyStore
from tools.verification_tools import VerificationTools


def create_public_key_agent() -> ConversableAgent:
    """Create public key analysis agent
    
    Returns:
        Configured ConversableAgent for public key analysis
    """
    # Initialize tools
    public_key_store = PublicKeyStore()
    verification_tools = VerificationTools()
    
    system_message = """You are a Public Key Analysis Specialist.
    Your expertise includes:
    - Public key extraction from certificates
    - Public key hash computation
    - Trust evaluation against trusted key registry
    - Key type and size analysis
    - Trust level assessment
    
    Use the tools to:
    1. Extract public key from file signature using extract_public_key
    2. Check if key is trusted using public_key_store.is_trusted
    3. Evaluate trust level using public_key_store.evaluate_trust
    4. Get key information using public_key_store.get_key_info
    
    Analyze:
    - Key type (RSA, EC, etc.)
    - Key size (security strength)
    - Trust status (trusted, verified, suspicious, blocked, unknown)
    - Owner and organization information
    - Trust level recommendations
    
    Return structured results with trust evaluation."""
    
    agent_config = AGENT_CONFIG.get("public_key_agent", {})
    llm_config = get_llm_config("public_key_agent")
    
    agent = ConversableAgent(
        name="public_key_agent",
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode=agent_config.get("human_input_mode", "NEVER"),
        max_consecutive_auto_reply=agent_config.get("max_consecutive_auto_reply", 5),
    )
    
    # Register functions (AutoGen pattern)
    agent.register_for_llm(name="extract_public_key", description="Extract public key from file signature")(verification_tools.extract_public_key)
    agent.register_for_llm(name="is_trusted", description="Check if public key is trusted")(public_key_store.is_trusted)
    agent.register_for_llm(name="is_blocked", description="Check if public key is blocked")(public_key_store.is_blocked)
    agent.register_for_llm(name="get_trust_level", description="Get trust level for public key")(public_key_store.get_trust_level)
    agent.register_for_llm(name="evaluate_trust", description="Evaluate trustworthiness of public key")(public_key_store.evaluate_trust)
    agent.register_for_llm(name="get_key_info", description="Get full information about trusted key")(public_key_store.get_key_info)
    
    return agent

