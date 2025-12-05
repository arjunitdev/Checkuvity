#!/usr/bin/env python3
"""
Orchestrator Agent - Coordinates all verification agents
"""

import sys
from pathlib import Path
from typing import Dict, Any
from autogen import ConversableAgent

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_agent_service.config import get_llm_config, AGENT_CONFIG


def create_orchestrator_agent() -> ConversableAgent:
    """Create the main orchestrator agent
    
    Returns:
        Configured ConversableAgent for orchestration
    """
    system_message = """You are a Security Verification Orchestrator.
    Your role is to coordinate comprehensive file security verification by:
    
    1. Receiving file verification requests with file_id and file_path
    2. Delegating tasks to specialized agents:
       - signature_verifier: Technical signature verification (PKCS#7, certificate chain, timestamps)
       - public_key_agent: Public key extraction and trust analysis
       - threat_intel: Threat intelligence checks against known bad keys/certs
       - policy_agent: Security policy enforcement and scoring
    3. Aggregating results from all agents
    4. Making final security decisions (secure, warning, blocked, unknown)
    5. Coordinating with reporter_agent for result formatting
    
    Workflow:
    1. Ask signature_verifier to verify the file signature
    2. Ask public_key_agent to extract and analyze the public key
    3. Ask threat_intel to check for known threats
    4. Ask policy_agent to calculate security score and make decision
    5. Ask reporter_agent to format the final assessment
    
    Always provide clear reasoning for your decisions.
    Return structured results in JSON format when requested."""
    
    agent_config = AGENT_CONFIG.get("orchestrator", {})
    llm_config = get_llm_config("orchestrator")
    
    return ConversableAgent(
        name="orchestrator",
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode=agent_config.get("human_input_mode", "NEVER"),
        max_consecutive_auto_reply=agent_config.get("max_consecutive_auto_reply", 10),
    )

