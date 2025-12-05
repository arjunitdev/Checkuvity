#!/usr/bin/env python3
"""
Verification Tools - Wraps existing verify.py functions for agent use
"""

import sys
from pathlib import Path
from typing import Dict, Optional, Any

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "build_scripts"))

try:
    from verify import (
        verify_executable,
        get_public_key_from_cert,
        extract_pkcs7_from_pe,
        verify_pkcs7_signature,
        get_pre_signature_hash,
        get_signature_hash,
        compute_authenticode_hash,
        load_config,
    )
except ImportError as e:
    print(f"Warning: Could not import verification functions: {e}")
    verify_executable = None
    get_public_key_from_cert = None
    extract_pkcs7_from_pe = None
    verify_pkcs7_signature = None
    get_pre_signature_hash = None
    get_signature_hash = None
    compute_authenticode_hash = None
    load_config = None


class VerificationTools:
    """Tools for signature verification - wraps existing verify.py functions"""
    
    def __init__(self):
        """Initialize verification tools with configuration"""
        if load_config:
            try:
                self.config = load_config()
            except Exception as e:
                print(f"Warning: Could not load config: {e}")
                self.config = {}
        else:
            self.config = {}
    
    def verify_signature(self, file_path: str) -> Dict[str, Any]:
        """
        Verify file signature using existing verify.py logic
        
        Args:
            file_path: Path to the file to verify
            
        Returns:
            Dictionary with verification results
        """
        if not verify_executable:
            return {
                "verified": False,
                "errors": ["Verification functions not available"],
                "chain_valid": False,
                "cert_subject": None,
                "timestamp": None,
                "pre_signature_hash": None,
                "post_signature_hash": None,
            }
        
        try:
            path = Path(file_path)
            if not path.exists():
                return {
                    "verified": False,
                    "errors": [f"File not found: {file_path}"],
                    "chain_valid": False,
                    "cert_subject": None,
                    "timestamp": None,
                    "pre_signature_hash": None,
                    "post_signature_hash": None,
                }
            
            result = verify_executable(path, self.config)
            return {
                "verified": result.get("verified", False),
                "chain_valid": result.get("chain_valid", False),
                "cert_subject": result.get("cert_subject"),
                "cert_thumbprint": result.get("cert_thumbprint"),
                "timestamp": result.get("timestamp"),
                "pre_signature_hash": result.get("pre_signature_hash"),
                "signature_hash": result.get("signature_hash"),
                "post_signature_hash": result.get("post_signature_hash"),
                "public_key": result.get("public_key"),
                "signed_hash": result.get("signed_hash"),
                "errors": result.get("errors", []),
            }
        except Exception as e:
            return {
                "verified": False,
                "errors": [f"Verification error: {str(e)}"],
                "chain_valid": False,
                "cert_subject": None,
                "timestamp": None,
                "pre_signature_hash": None,
                "post_signature_hash": None,
            }
    
    def extract_public_key(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Extract public key from file signature
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with public key information or None
        """
        if not extract_pkcs7_from_pe or not get_public_key_from_cert:
            return None
        
        try:
            path = Path(file_path)
            if not path.exists():
                return None
            
            # Extract PKCS#7 signature
            pkcs7_data = extract_pkcs7_from_pe(path)
            if not pkcs7_data:
                return None
            
            # Extract public key from PKCS#7
            try:
                from asn1crypto import cms
                signed_data = cms.ContentInfo.load(pkcs7_data)
                if signed_data['content_type'].dotted == '1.2.840.113549.1.7.2':
                    signed_data = signed_data['content']
                    if 'certificates' in signed_data and len(signed_data['certificates']) > 0:
                        cert_data = signed_data['certificates'][0].dump()
                        public_key_info = get_public_key_from_cert(cert_data)
                        return public_key_info
            except Exception as e:
                print(f"Error extracting public key: {e}")
                return None
            
            return None
        except Exception as e:
            print(f"Error in extract_public_key: {e}")
            return None
    
    def verify_certificate_chain(self, file_path: str) -> Dict[str, Any]:
        """
        Verify certificate chain for a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with chain verification results
        """
        if not extract_pkcs7_from_pe or not verify_pkcs7_signature:
            return {
                "verified": False,
                "chain_valid": False,
                "errors": ["Verification functions not available"],
            }
        
        try:
            path = Path(file_path)
            if not path.exists():
                return {
                    "verified": False,
                    "chain_valid": False,
                    "errors": [f"File not found: {file_path}"],
                }
            
            # Extract PKCS#7 signature
            pkcs7_data = extract_pkcs7_from_pe(path)
            if not pkcs7_data:
                return {
                    "verified": False,
                    "chain_valid": False,
                    "errors": ["Failed to extract PKCS#7 signature"],
                }
            
            # Verify PKCS#7 signature
            ca_cert_path = PROJECT_ROOT / self.config.get("certs", {}).get("ca_cert", "certs/ca.cert.pem")
            pkcs7_result = verify_pkcs7_signature(pkcs7_data, ca_cert_path)
            
            return {
                "verified": pkcs7_result.get("verified", False),
                "chain_valid": pkcs7_result.get("chain_valid", False),
                "cert_subject": pkcs7_result.get("cert_subject"),
                "cert_thumbprint": pkcs7_result.get("cert_thumbprint"),
                "timestamp": pkcs7_result.get("timestamp"),
                "errors": pkcs7_result.get("errors", []),
            }
        except Exception as e:
            return {
                "verified": False,
                "chain_valid": False,
                "errors": [f"Chain verification error: {str(e)}"],
            }
    
    def get_file_hashes(self, file_path: str) -> Dict[str, Optional[str]]:
        """
        Get all hashes for a file (pre-signature, post-signature)
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with hash values
        """
        if not get_pre_signature_hash or not compute_authenticode_hash:
            return {
                "pre_signature_hash": None,
                "post_signature_hash": None,
            }
        
        try:
            path = Path(file_path)
            if not path.exists():
                return {
                    "pre_signature_hash": None,
                    "post_signature_hash": None,
                }
            
            pre_hash = get_pre_signature_hash(path)
            post_hash = compute_authenticode_hash(path)
            
            return {
                "pre_signature_hash": pre_hash,
                "post_signature_hash": post_hash,
            }
        except Exception as e:
            print(f"Error getting file hashes: {e}")
            return {
                "pre_signature_hash": None,
                "post_signature_hash": None,
            }

