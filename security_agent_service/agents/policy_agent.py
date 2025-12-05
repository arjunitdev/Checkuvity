#!/usr/bin/env python3
"""
Policy Agent - Security policy enforcement and scoring
"""

import sys
from pathlib import Path
from typing import Dict, Any
from autogen import ConversableAgent

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_agent_service.config import get_llm_config, AGENT_CONFIG, SECURITY_POLICY


def create_policy_agent() -> ConversableAgent:
    """Create security policy enforcement agent
    
    Returns:
        Configured ConversableAgent for policy enforcement
    """
    system_message = """You are a Security Policy Enforcement Specialist.
    Your expertise includes:
    - Security scoring algorithms
    - Policy-based decision making
    - Risk assessment
    - Security status determination
    
    Your role is to:
    1. Calculate security score based on verification results:
       - Signature verified: +30 points
       - Certificate chain valid: +25 points
       - Timestamp valid: +10 points
       - Trusted public key: +20 points
       - No threats detected: +15 points
       Total: 0-100 points
    
    2. Determine security status based on score:
       - secure: 70-100 points
       - warning: 50-69 points
       - blocked: 0-29 points
       - unknown: 30-49 points (verification incomplete)
    
    3. Apply security policies:
       - Auto-block if score < 30
       - Warn if score < 50
       - Allow if score >= 70
    
    4. Generate recommendations:
       - Actions to improve security
       - Remediation steps
       - Policy compliance suggestions
    
    Return structured results with:
    - Security score (0-100)
    - Security status (secure, warning, blocked, unknown)
    - Recommendations list
    - Policy compliance status"""
    
    agent_config = AGENT_CONFIG.get("policy_agent", {})
    llm_config = get_llm_config("policy_agent")
    
    return ConversableAgent(
        name="policy_agent",
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode=agent_config.get("human_input_mode", "NEVER"),
        max_consecutive_auto_reply=agent_config.get("max_consecutive_auto_reply", 5),
    )

