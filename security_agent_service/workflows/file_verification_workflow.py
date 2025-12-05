#!/usr/bin/env python3
"""
File Verification Workflow - Orchestrates multi-agent verification
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from autogen import GroupChat, GroupChatManager

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import from security_agent_service.config to avoid conflicts with demo_server.config
from security_agent_service.config import WORKFLOW_CONFIG, AGENT_VERSION
from agents.orchestrator_agent import create_orchestrator_agent
from agents.signature_verifier_agent import create_signature_verifier_agent
from agents.public_key_agent import create_public_key_agent
from agents.threat_intel_agent import create_threat_intel_agent
from agents.policy_agent import create_policy_agent
from agents.reporter_agent import create_reporter_agent
from models.security_assessment import SecurityAssessment, VerificationDetails, ThreatInfo


class FileVerificationWorkflow:
    """Orchestrates multi-agent file verification workflow"""
    
    def __init__(self):
        """Initialize workflow with all agents"""
        # Create all agents
        self.orchestrator = create_orchestrator_agent()
        self.signature_verifier = create_signature_verifier_agent()
        self.public_key_agent = create_public_key_agent()
        self.threat_intel = create_threat_intel_agent()
        self.policy_agent = create_policy_agent()
        self.reporter = create_reporter_agent()
        
        # Create agent list for group chat
        self.agents = [
            self.orchestrator,
            self.signature_verifier,
            self.public_key_agent,
            self.threat_intel,
            self.policy_agent,
            self.reporter,
        ]
        
        # Create group chat
        self.group_chat = GroupChat(
            agents=self.agents,
            messages=[],
            max_round=WORKFLOW_CONFIG.get("max_rounds", 20),
            speaker_selection_method="round_robin",
        )
        
        # Create group chat manager
        self.manager = GroupChatManager(
            groupchat=self.group_chat,
            llm_config=self.orchestrator.llm_config,
        )
    
    def verify_file(self, file_id: str, file_path: str, user_id: str) -> Dict[str, Any]:
        """
        Verify a file using multi-agent workflow
        
        Args:
            file_id: UUID of the file
            file_path: Path to the file to verify
            user_id: UUID of the user
            
        Returns:
            Security assessment dictionary
        """
        # Create initial message
        initial_message = f"""Verify file security:
        - File ID: {file_id}
        - File Path: {file_path}
        - User ID: {user_id}
        
        Please coordinate with all agents to:
        1. Verify the file signature
        2. Extract and analyze the public key
        3. Check for known threats
        4. Calculate security score
        5. Generate final assessment
        
        Return the assessment in JSON format."""
        
        try:
            # Initiate conversation
            response = self.orchestrator.initiate_chat(
                self.manager,
                message=initial_message,
                max_turns=WORKFLOW_CONFIG.get("max_rounds", 20),
            )
            
            # Extract structured results from conversation
            assessment = self._extract_assessment(response, file_id, file_path)
            
            return assessment.to_dict()
        
        except Exception as e:
            print(f"Error in verification workflow: {e}")
            # Return error assessment
            return {
                "file_id": file_id,
                "security_status": "unknown",
                "security_score": 0,
                "errors": [str(e)],
                "verified_at": datetime.now().isoformat(),
            }
    
    def _extract_assessment(
        self,
        response: Any,
        file_id: str,
        file_path: str
    ) -> SecurityAssessment:
        """
        Extract structured assessment from agent conversation
        
        Args:
            response: Response from agent conversation
            file_id: UUID of the file
            file_path: Path to the file
            
        Returns:
            SecurityAssessment object
        """
        # Try to extract JSON from conversation
        # This is a simplified extraction - in practice, you'd parse the full conversation
        assessment = SecurityAssessment(
            file_id=file_id,
            security_status="unknown",
            security_score=0,
            verified_at=datetime.now(),
        )
        
        # In a real implementation, you would:
        # 1. Parse the conversation messages
        # 2. Extract structured data from each agent's responses
        # 3. Combine results into final assessment
        
        # For now, return a basic assessment
        # The actual implementation would parse agent messages and extract structured data
        
        return assessment
    
    def _parse_agent_messages(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Parse agent messages to extract structured data
        
        Args:
            messages: List of conversation messages
            
        Returns:
            Dictionary with extracted data
        """
        results = {
            "signature_verified": False,
            "chain_valid": False,
            "timestamp_valid": False,
            "public_key_hash": None,
            "trusted": False,
            "threats_detected": [],
            "security_score": 0,
            "security_status": "unknown",
        }
        
        # Parse messages to extract results
        # This would involve parsing JSON from agent responses
        # and extracting key information
        
        return results

