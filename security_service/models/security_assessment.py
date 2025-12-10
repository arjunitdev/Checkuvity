#!/usr/bin/env python3
"""
Security Assessment Model - Data structures for security verification results
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional as Opt


@dataclass
class VerificationDetails:
    """Details from signature verification"""
    signature_verified: bool
    chain_valid: bool
    timestamp_valid: bool
    cert_subject: Optional[str] = None
    cert_thumbprint: Optional[str] = None
    pre_signature_hash: Optional[str] = None
    post_signature_hash: Optional[str] = None
    signed_hash: Optional[str] = None
    hash_matches: Optional[bool] = None
    hash_mismatch_reasons: List[str] = None
    public_key_pem: Optional[str] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.hash_mismatch_reasons is None:
            self.hash_mismatch_reasons = []


@dataclass
class ThreatInfo:
    """Information about detected threats"""
    type: str
    severity: str
    description: str
    source: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class SecurityAssessment:
    """Complete security assessment result"""
    file_id: str
    security_status: str  # secure, warning, blocked, unknown
    security_score: int  # 0-100
    public_key_hash: Optional[str] = None
    trusted: bool = False
    verification_details: Optional[VerificationDetails] = None
    threats_detected: List[ThreatInfo] = None
    recommendations: List[str] = None
    verified_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.threats_detected is None:
            self.threats_detected = []
        if self.recommendations is None:
            self.recommendations = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        
        # Convert VerificationDetails to dict
        if self.verification_details:
            result["verification_details"] = asdict(self.verification_details)
        
        # Convert ThreatInfo to dict
        if self.threats_detected:
            result["threats_detected"] = [asdict(t) for t in self.threats_detected]
        
        # Convert datetime to ISO format
        if self.verified_at:
            result["verified_at"] = self.verified_at.isoformat()
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityAssessment':
        """Create from dictionary"""
        # Convert verification_details
        if "verification_details" in data and data["verification_details"]:
            vd = data["verification_details"]
            data["verification_details"] = VerificationDetails(**vd)
        
        # Convert threats_detected
        if "threats_detected" in data and data["threats_detected"]:
            threats = [ThreatInfo(**t) for t in data["threats_detected"]]
            data["threats_detected"] = threats
        
        # Convert verified_at
        if "verified_at" in data and data["verified_at"]:
            if isinstance(data["verified_at"], str):
                data["verified_at"] = datetime.fromisoformat(data["verified_at"])
        
        return cls(**data)

