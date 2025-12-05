#!/usr/bin/env python3
"""
Reporter Agent - Results formatting and notifications
"""

import sys
from pathlib import Path
from typing import Dict, Any
from autogen import ConversableAgent

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_agent_service.config import get_llm_config, AGENT_CONFIG


def create_reporter_agent() -> ConversableAgent:
    """Create reporting agent
    
    Returns:
        Configured ConversableAgent for result formatting
    """
    system_message = """You are a Security Report Specialist.
    Your expertise includes:
    - Formatting security assessment results
    - Generating comprehensive reports
    - Creating actionable recommendations
    - Structuring data for API responses
    
    Your role is to:
    1. Format verification results into structured JSON:
       {
         "file_id": "uuid",
         "security_status": "secure|warning|blocked|unknown",
         "security_score": 0-100,
         "public_key_hash": "sha256",
         "trusted": true/false,
         "verification_details": {
           "signature_verified": true/false,
           "chain_valid": true/false,
           "timestamp_valid": true/false,
           "threats_detected": []
         },
         "recommendations": [],
         "verified_at": "timestamp"
       }
    
    2. Generate human-readable summaries
    3. Create actionable recommendations
    4. Format notifications for users
    
    Always return well-structured, complete reports.
    Include all relevant details from all agents."""
    
    agent_config = AGENT_CONFIG.get("reporter", {})
    llm_config = get_llm_config("reporter")
    
    return ConversableAgent(
        name="reporter",
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode=agent_config.get("human_input_mode", "NEVER"),
        max_consecutive_auto_reply=agent_config.get("max_consecutive_auto_reply", 3),
    )

