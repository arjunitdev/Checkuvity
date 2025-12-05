#!/usr/bin/env python3
"""
Signature Verifier Agent - Technical signature verification
"""

import sys
from pathlib import Path
from typing import Dict, Any
from autogen import ConversableAgent

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_agent_service.config import get_llm_config, AGENT_CONFIG
from tools.verification_tools import VerificationTools


def create_signature_verifier_agent() -> ConversableAgent:
    """Create signature verification agent
    
    Returns:
        Configured ConversableAgent for signature verification
    """
    # Initialize verification tools
    verification_tools = VerificationTools()
    
    system_message = """You are a Signature Verification Specialist.
    Your expertise includes:
    - PKCS#7 signature extraction and validation
    - Certificate chain verification
    - Timestamp validation
    - Authenticode hash computation
    - PE file signature analysis
    
    Use the verification_tools to:
    1. Extract signatures from files using extract_pkcs7_from_pe
    2. Verify certificate chains using verify_certificate_chain
    3. Validate timestamps
    4. Compute hashes (pre-signature, post-signature) using get_file_hashes
    5. Perform full signature verification using verify_signature
    
    Provide detailed technical analysis of:
    - Signature validity
    - Certificate chain status
    - Timestamp validity
    - Hash matches
    - Any errors or warnings
    
    Return structured results with all verification details."""
    
    agent_config = AGENT_CONFIG.get("signature_verifier", {})
    llm_config = get_llm_config("signature_verifier")
    
    # Define functions that the agent can call
    function_map = {
        "verify_signature": verification_tools.verify_signature,
        "extract_public_key": verification_tools.extract_public_key,
        "verify_certificate_chain": verification_tools.verify_certificate_chain,
        "get_file_hashes": verification_tools.get_file_hashes,
    }
    
    agent = ConversableAgent(
        name="signature_verifier",
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode=agent_config.get("human_input_mode", "NEVER"),
        max_consecutive_auto_reply=agent_config.get("max_consecutive_auto_reply", 5),
    )
    
    # Register functions (AutoGen pattern)
    agent.register_for_llm(name="verify_signature", description="Verify file signature")(verification_tools.verify_signature)
    agent.register_for_llm(name="extract_public_key", description="Extract public key from file")(verification_tools.extract_public_key)
    agent.register_for_llm(name="verify_certificate_chain", description="Verify certificate chain")(verification_tools.verify_certificate_chain)
    agent.register_for_llm(name="get_file_hashes", description="Get file hashes")(verification_tools.get_file_hashes)
    
    return agent

