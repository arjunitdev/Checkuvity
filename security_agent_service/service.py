#!/usr/bin/env python3
"""
Security Verification Service - High-level service for file security verification
"""

import sys
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import tempfile
import os

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from tools.verification_tools import VerificationTools
from tools.supabase_tools import SupabaseSecurityTools
from tools.public_key_store import PublicKeyStore
from tools.threat_intel_tools import ThreatIntelligenceTools
from tools.email_notifier import EmailNotifier
from workflows.file_verification_workflow import FileVerificationWorkflow
from models.security_assessment import SecurityAssessment, VerificationDetails, ThreatInfo
from security_agent_service.config import SECURITY_POLICY, AGENT_VERSION


class SecurityVerificationService:
    """High-level service for file security verification"""
    
    def __init__(self):
        """Initialize verification service"""
        self.verification_tools = VerificationTools()
        self.supabase = SupabaseSecurityTools(use_service_role=True)
        self.public_key_store = PublicKeyStore(supabase_tools=self.supabase)
        self.threat_intel = ThreatIntelligenceTools()
        self.email_notifier = EmailNotifier()
        # Note: Workflow initialization is optional - can use direct calls instead
        # self.workflow = FileVerificationWorkflow()
    
    def verify_file(self, file_id: str, user_id: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify file security
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user
            file_path: Optional path to file (if None, downloads from Supabase)
            
        Returns:
            Security assessment dictionary
        """
        try:
            # Get file record
            file_record = self.supabase.get_file(file_id, user_id)
            if not file_record:
                return {
                    "file_id": file_id,
                    "security_status": "unknown",
                    "security_score": 0,
                    "errors": ["File not found"],
                    "verified_at": datetime.now().isoformat(),
                }
            
            # Download file if path not provided
            if not file_path:
                file_content = self.supabase.download_file(file_id, user_id)
                if not file_content:
                    return {
                        "file_id": file_id,
                        "security_status": "unknown",
                        "security_score": 0,
                        "errors": ["Failed to download file"],
                        "verified_at": datetime.now().isoformat(),
                    }
                
                # Save to temporary file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.exe') as tmp_file:
                    tmp_file.write(file_content)
                    file_path = tmp_file.name
            
            # Perform verification
            assessment = self._perform_verification(file_id, file_path, file_record, user_id)
            
            # Store results in database
            self._store_results(file_id, assessment)
            
            # Clean up temporary file if created
            if file_path and os.path.exists(file_path) and file_path.startswith(tempfile.gettempdir()):
                try:
                    os.unlink(file_path)
                except:
                    pass
            
            return assessment.to_dict()
        
        except Exception as e:
            print(f"Error in verify_file: {e}")
            import traceback
            traceback.print_exc()
            return {
                "file_id": file_id,
                "security_status": "unknown",
                "security_score": 0,
                "errors": [str(e)],
                "verified_at": datetime.now().isoformat(),
            }
    
    def _perform_verification(
        self,
        file_id: str,
        file_path: str,
        file_record: Dict[str, Any],
        user_id: str,
    ) -> SecurityAssessment:
        """
        Perform comprehensive security verification
        
        Args:
            file_id: UUID of the file
            file_path: Path to the file
            file_record: File record from database
            
        Returns:
            SecurityAssessment object
        """
        # Step 1: Verify signature
        signature_result = self.verification_tools.verify_signature(file_path)
        
        # Step 2: Extract public key
        public_key_info = self.verification_tools.extract_public_key(file_path)
        public_key_hash = None
        public_key_pem = None
        if public_key_info:
            public_key_hash = public_key_info.get("hash")
            public_key_pem = public_key_info.get("pem")

        if not public_key_pem:
            sig_pub = signature_result.get("public_key")
            if isinstance(sig_pub, dict):
                public_key_pem = sig_pub.get("pem")
        
        # Step 3: Evaluate trust
        trusted = False
        if public_key_hash:
            trusted = self.public_key_store.is_trusted(public_key_hash)
            blocked = self.public_key_store.is_blocked(public_key_hash)
            if blocked:
                # If blocked, return immediately
                return SecurityAssessment(
                    file_id=file_id,
                    security_status="blocked",
                    security_score=0,
                    public_key_hash=public_key_hash,
                    trusted=False,
                    verification_details=VerificationDetails(
                        signature_verified=signature_result.get("verified", False),
                        chain_valid=signature_result.get("chain_valid", False),
                        timestamp_valid=bool(signature_result.get("timestamp")),
                        cert_subject=signature_result.get("cert_subject"),
                        cert_thumbprint=signature_result.get("cert_thumbprint"),
                        pre_signature_hash=signature_result.get("pre_signature_hash"),
                        post_signature_hash=signature_result.get("post_signature_hash"),
                        signed_hash=signature_result.get("signed_hash"),
                        hash_matches=False,
                        hash_mismatch_reasons=["Blocked public key"],
                        public_key_pem=public_key_pem,
                        errors=signature_result.get("errors", []),
                    ),
                    threats_detected=[ThreatInfo(
                        type="blocked_public_key",
                        severity="critical",
                        description="Public key is in blocked list",
                    )],
                    recommendations=["File is blocked due to untrusted public key"],
                    verified_at=datetime.now(),
                )
        
        # Step 3b: Compare hashes against stored baseline
        def _normalize_hash(value: Optional[str]) -> Optional[str]:
            if value is None:
                return None
            if isinstance(value, str):
                stripped = value.strip()
                return stripped.lower() if stripped else None
            return None

        expected_pre_hash = _normalize_hash(file_record.get("original_hash"))
        expected_post_hash = _normalize_hash(file_record.get("post_signature_hash"))
        signed_hash = _normalize_hash(signature_result.get("signed_hash"))
        computed_pre_hash = _normalize_hash(signature_result.get("pre_signature_hash"))
        computed_post_hash = _normalize_hash(signature_result.get("post_signature_hash"))

        hash_matches = True
        hash_mismatch_reasons = []

        if expected_pre_hash and signed_hash and signed_hash != expected_pre_hash:
            hash_matches = False
            hash_mismatch_reasons.append(
                "Hash embedded in signature does not match the original hash stored during upload."
            )

        if expected_pre_hash and computed_pre_hash and computed_pre_hash != expected_pre_hash:
            hash_matches = False
            hash_mismatch_reasons.append(
                "Recalculated hash of the current file bytes differs from the original upload hash."
            )

        if expected_post_hash and computed_post_hash and computed_post_hash != expected_post_hash:
            hash_matches = False
            hash_mismatch_reasons.append(
                "Authenticode post-signature hash no longer matches the stored baseline."
            )

        hash_details = {
            "expected_pre_hash": expected_pre_hash,
            "expected_post_hash": expected_post_hash,
            "signed_hash": signed_hash,
            "computed_pre_hash": computed_pre_hash,
            "computed_post_hash": computed_post_hash,
        }

        # Step 4: Check threats
        threats = []
        if public_key_hash:
            threat_result = self.threat_intel.check_public_key(public_key_hash)
            if threat_result.get("is_malicious"):
                threats.append(ThreatInfo(
                    type="malicious_public_key",
                    severity="high",
                    description="Public key flagged as malicious",
                    details=threat_result,
                ))
        
        if signature_result.get("cert_thumbprint"):
            cert_threat = self.threat_intel.check_certificate(signature_result["cert_thumbprint"])
            if cert_threat.get("is_malicious") or cert_threat.get("is_revoked"):
                threats.append(ThreatInfo(
                    type="malicious_certificate" if cert_threat.get("is_malicious") else "revoked_certificate",
                    severity="high",
                    description="Certificate flagged as malicious or revoked",
                    details=cert_threat,
                ))

        if not hash_matches:
            threats.append(ThreatInfo(
                type="content_mismatch",
                severity="critical",
                description="File content differs from the originally signed version.",
                details=hash_details,
            ))

            self._notify_hash_mismatch(
                file_record=file_record,
                user_id=user_id,
                mismatch_reasons=hash_mismatch_reasons,
                hash_details=hash_details,
            )
        
        # Step 5: Calculate security score
        score = self._calculate_security_score(
            signature_result,
            trusted,
            threats,
            hash_matches,
        )
        
        # Step 6: Determine status
        status = self._determine_status(score, hash_matches)
        
        # Step 7: Generate recommendations
        recommendations = self._generate_recommendations(
            signature_result,
            trusted,
            threats,
            score,
            hash_matches,
            hash_mismatch_reasons,
        )
        
        # Create assessment
        assessment = SecurityAssessment(
            file_id=file_id,
            security_status=status,
            security_score=score,
            public_key_hash=public_key_hash,
            trusted=trusted,
            verification_details=VerificationDetails(
                signature_verified=signature_result.get("verified", False),
                chain_valid=signature_result.get("chain_valid", False),
                timestamp_valid=bool(signature_result.get("timestamp")),
                cert_subject=signature_result.get("cert_subject"),
                cert_thumbprint=signature_result.get("cert_thumbprint"),
                pre_signature_hash=signature_result.get("pre_signature_hash"),
                post_signature_hash=signature_result.get("post_signature_hash"),
                signed_hash=signature_result.get("signed_hash"),
                hash_matches=hash_matches,
                hash_mismatch_reasons=hash_mismatch_reasons,
                public_key_pem=public_key_pem,
                errors=signature_result.get("errors", []),
            ),
            threats_detected=threats,
            recommendations=recommendations,
            verified_at=datetime.now(),
        )
        
        return assessment
    
    def _notify_hash_mismatch(
        self,
        *,
        file_record: Dict[str, Any],
        user_id: str,
        mismatch_reasons: list,
        hash_details: Dict[str, Optional[str]],
    ) -> None:
        """Send email notification when a hash mismatch is detected."""
        try:
            if not self.email_notifier or not self.email_notifier.enabled:
                return

            recipients = []
            user_email = self.supabase.get_user_email(user_id) if self.supabase else None
            if user_email:
                recipients.append(user_email)

            file_name = file_record.get("file_name", file_record.get("id", "unknown file"))
            reasons = mismatch_reasons or ["File hash mismatch detected."]

            body_lines = [
                f"File: {file_name}",
                f"File ID: {file_record.get('id')}",
                f"User ID: {user_id}",
                "",
                "Detected hash mismatches:",
            ]
            body_lines.extend(f"- {reason}" for reason in reasons)
            body_lines.append("")
            body_lines.append("Hash details:")
            for key, value in hash_details.items():
                body_lines.append(f"  {key}: {value or 'n/a'}")

            body = "\n".join(body_lines)
            subject = f"Security Alert: Hash mismatch detected for {file_name}"

            self.email_notifier.send_hash_mismatch_alert(
                recipients=recipients,
                subject=subject,
                body=body,
            )
        except Exception as e:
            print(f"Error sending hash mismatch notification: {e}")

    def _calculate_security_score(
        self,
        signature_result: Dict[str, Any],
        trusted: bool,
        threats: list,
        hash_matches: bool,
    ) -> int:
        """
        Calculate security score (0-100)
        
        Args:
            signature_result: Signature verification results
            trusted: Whether public key is trusted
            threats: List of detected threats
            
        Returns:
            Security score (0-100)
        """
        score = 0
        weights = SECURITY_POLICY.get("score_weights", {})
        
        # Signature verified: +30
        if signature_result.get("verified", False):
            score += weights.get("signature_verified", 30)
        
        # Chain valid: +25
        if signature_result.get("chain_valid", False):
            score += weights.get("chain_valid", 25)
        
        # Timestamp valid: +10
        if signature_result.get("timestamp"):
            score += weights.get("timestamp_valid", 10)
        
        # Trusted key: +20
        if trusted:
            score += weights.get("trusted_key", 20)
        
        # No threats: +15
        if not threats:
            score += weights.get("no_threats", 15)

        # Hash consistency bonus / penalty
        if hash_matches:
            score += weights.get("hash_match", 0)
        else:
            score -= weights.get("hash_mismatch_penalty", 0)
        
        # Deduct for threats
        for threat in threats:
            if threat.severity == "critical":
                score -= 50
            elif threat.severity == "high":
                score -= 30
            elif threat.severity == "medium":
                score -= 15
            else:
                score -= 5
        
        # Ensure score is between 0 and 100
        score = max(0, min(100, score))
        
        return score
    
    def _determine_status(self, score: int, hash_matches: bool) -> str:
        """
        Determine security status based on score
        
        Args:
            score: Security score (0-100)
            
        Returns:
            Security status (secure, warning, blocked, unknown)
        """
        status_mapping = SECURITY_POLICY.get("status_mapping", {})
        
        if not hash_matches:
            return "blocked"

        if score >= status_mapping.get("secure", {}).get("min_score", 70):
            return "secure"
        elif score >= status_mapping.get("warning", {}).get("min_score", 50):
            return "warning"
        elif score >= status_mapping.get("blocked", {}).get("min_score", 0):
            return "blocked"
        else:
            return "unknown"
    
    def _generate_recommendations(
        self,
        signature_result: Dict[str, Any],
        trusted: bool,
        threats: list,
        score: int,
        hash_matches: bool,
        hash_mismatch_reasons: list,
    ) -> list:
        """
        Generate security recommendations
        
        Args:
            signature_result: Signature verification results
            trusted: Whether public key is trusted
            threats: List of detected threats
            score: Security score
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if not signature_result.get("verified", False):
            recommendations.append("File signature is not valid - verify the signing process")
        
        if not signature_result.get("chain_valid", False):
            recommendations.append("Certificate chain is invalid - ensure proper certificate chain")
        
        if not signature_result.get("timestamp"):
            recommendations.append("File is not timestamped - add timestamp to signature")
        
        if not trusted:
            recommendations.append("Public key is not in trusted registry - consider adding to trusted keys")
        
        if threats:
            recommendations.append(f"{len(threats)} threat(s) detected - review threat details")
        
        if score < 50:
            recommendations.append("Security score is low - review all security aspects")
        
        if not hash_matches:
            recommendations.append("File hash mismatch detected - investigate possible tampering")
            for reason in hash_mismatch_reasons:
                recommendations.append(reason)

        if not recommendations:
            recommendations.append("File security verification passed - no recommendations")
        
        return recommendations
    
    def _store_results(self, file_id: str, assessment: SecurityAssessment) -> None:
        """
        Store verification results in database
        
        Args:
            file_id: UUID of the file
            assessment: SecurityAssessment object
        """
        try:
            # Store verification result
            self.supabase.store_verification_result(
                file_id=file_id,
                public_key_hash=assessment.public_key_hash,
                verification_status=assessment.security_status,
                security_score=assessment.security_score,
                threats_detected=[t.__dict__ for t in assessment.threats_detected],
                verification_details=assessment.verification_details.__dict__ if assessment.verification_details else {},
                recommendations=assessment.recommendations,
                agent_version=AGENT_VERSION,
            )
            
            # Update file record
            self.supabase.update_file_security_status(
                file_id=file_id,
                security_status=assessment.security_status,
                security_score=assessment.security_score,
                public_key_hash=assessment.public_key_hash,
                verified_at=assessment.verified_at,
            )
        except Exception as e:
            print(f"Error storing results: {e}")
            import traceback
            traceback.print_exc()

