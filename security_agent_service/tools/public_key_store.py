#!/usr/bin/env python3
"""
Public Key Store - Trusted key registry management
"""

from typing import Dict, Optional, List, Any
from .supabase_tools import SupabaseSecurityTools


class PublicKeyStore:
    """Manages trusted public key registry"""
    
    def __init__(self, supabase_tools: Optional[SupabaseSecurityTools] = None):
        """Initialize public key store
        
        Args:
            supabase_tools: SupabaseSecurityTools instance (creates new if None)
        """
        if supabase_tools:
            self.supabase = supabase_tools
        else:
            self.supabase = SupabaseSecurityTools(use_service_role=True)
    
    def is_trusted(self, public_key_hash: str) -> bool:
        """
        Check if a public key is trusted
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            
        Returns:
            True if trusted, False otherwise
        """
        trusted_key = self.supabase.get_trusted_key(public_key_hash)
        if not trusted_key:
            return False
        
        trust_level = trusted_key.get("trust_level", "").lower()
        return trust_level in ["trusted", "verified"]
    
    def is_blocked(self, public_key_hash: str) -> bool:
        """
        Check if a public key is blocked
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            
        Returns:
            True if blocked, False otherwise
        """
        trusted_key = self.supabase.get_trusted_key(public_key_hash)
        if not trusted_key:
            return False
        
        trust_level = trusted_key.get("trust_level", "").lower()
        return trust_level == "blocked"
    
    def get_trust_level(self, public_key_hash: str) -> Optional[str]:
        """
        Get trust level for a public key
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            
        Returns:
            Trust level (trusted, verified, suspicious, blocked) or None
        """
        trusted_key = self.supabase.get_trusted_key(public_key_hash)
        if not trusted_key:
            return None
        
        return trusted_key.get("trust_level")
    
    def get_key_info(self, public_key_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get full information about a trusted key
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            
        Returns:
            Key information dictionary or None
        """
        return self.supabase.get_trusted_key(public_key_hash)
    
    def evaluate_trust(self, public_key_hash: str) -> Dict[str, Any]:
        """
        Evaluate trustworthiness of a public key
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            
        Returns:
            Dictionary with trust evaluation results
        """
        trusted_key = self.supabase.get_trusted_key(public_key_hash)
        
        if not trusted_key:
            return {
                "trusted": False,
                "trust_level": "unknown",
                "blocked": False,
                "exists": False,
                "owner": None,
                "organization": None,
            }
        
        trust_level = trusted_key.get("trust_level", "").lower()
        
        return {
            "trusted": trust_level in ["trusted", "verified"],
            "trust_level": trust_level,
            "blocked": trust_level == "blocked",
            "exists": True,
            "owner": trusted_key.get("owner_name"),
            "organization": trusted_key.get("organization"),
            "key_type": trusted_key.get("key_type"),
            "key_size": trusted_key.get("key_size"),
            "added_at": trusted_key.get("added_at"),
            "notes": trusted_key.get("notes"),
        }
    
    def add_trusted_key(
        self,
        public_key_hash: str,
        key_type: str,
        key_size: Optional[int] = None,
        owner_name: Optional[str] = None,
        organization: Optional[str] = None,
        trust_level: str = "verified",
        notes: Optional[str] = None,
        added_by: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Add a trusted key to the registry
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            key_type: Type of key (RSA, EC, etc.)
            key_size: Size of key in bits
            owner_name: Name of key owner
            organization: Organization name
            trust_level: Trust level (trusted, verified, suspicious, blocked)
            notes: Optional notes
            added_by: User ID who added the key
            
        Returns:
            Created trusted key record or None
        """
        return self.supabase.add_trusted_key(
            public_key_hash=public_key_hash,
            key_type=key_type,
            key_size=key_size,
            owner_name=owner_name,
            organization=organization,
            trust_level=trust_level,
            notes=notes,
            added_by=added_by
        )
    
    def list_trusted_keys(self, trust_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all trusted keys, optionally filtered by trust level
        
        Args:
            trust_level: Optional filter by trust level
            
        Returns:
            List of trusted key records
        """
        return self.supabase.list_trusted_keys(trust_level=trust_level)
    
    def update_trust_level(
        self,
        public_key_hash: str,
        trust_level: str,
        notes: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Update trust level for a key
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            trust_level: New trust level
            notes: Optional notes
            
        Returns:
            Updated trusted key record or None
        """
        return self.supabase.update_trusted_key(
            public_key_hash=public_key_hash,
            trust_level=trust_level,
            notes=notes
        )
    
    def remove_trusted_key(self, public_key_hash: str) -> bool:
        """
        Remove a trusted key from the registry
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            
        Returns:
            True if removed, False otherwise
        """
        return self.supabase.delete_trusted_key(public_key_hash)

