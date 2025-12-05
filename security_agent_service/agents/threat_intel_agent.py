#!/usr/bin/env python3
"""
Threat Intelligence Agent - External threat checks
"""

import sys
from pathlib import Path
from typing import Dict, Any
from autogen import ConversableAgent

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_agent_service.config import get_llm_config, AGENT_CONFIG
from tools.threat_intel_tools import ThreatIntelligenceTools


def create_threat_intel_agent() -> ConversableAgent:
    """Create threat intelligence agent
    
    Returns:
        Configured ConversableAgent for threat intelligence
    """
    # Initialize threat intelligence tools
    threat_tools = ThreatIntelligenceTools()
    
    system_message = """You are a Threat Intelligence Specialist.
    Your expertise includes:
    - Checking public keys against threat intelligence feeds
    - Checking certificates against revocation lists
    - Checking file hashes against malware databases
    - Identifying known malicious indicators
    - Reputation analysis
    
    Use the threat_tools to:
    1. Check public key against threat feeds using check_public_key
    2. Check certificate against threat feeds using check_certificate
    3. Check file hash against threat feeds using check_file_hash
    4. Perform comprehensive checks using check_multiple_indicators
    
    Analyze:
    - Malicious indicators detected
    - Reputation scores
    - Threat sources
    - Risk level assessment
    
    Return structured results with threat analysis.
    Note: Currently using placeholder implementation - future integration with external APIs."""
    
    agent_config = AGENT_CONFIG.get("threat_intel", {})
    llm_config = get_llm_config("threat_intel")
    
    agent = ConversableAgent(
        name="threat_intel",
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode=agent_config.get("human_input_mode", "NEVER"),
        max_consecutive_auto_reply=agent_config.get("max_consecutive_auto_reply", 3),
    )
    
    # Register functions (AutoGen pattern)
    agent.register_for_llm(name="check_public_key", description="Check public key against threat intelligence")(threat_tools.check_public_key)
    agent.register_for_llm(name="check_certificate", description="Check certificate against threat intelligence")(threat_tools.check_certificate)
    agent.register_for_llm(name="check_file_hash", description="Check file hash against threat intelligence")(threat_tools.check_file_hash)
    agent.register_for_llm(name="check_multiple_indicators", description="Check multiple indicators at once")(threat_tools.check_multiple_indicators)
    
    return agent

