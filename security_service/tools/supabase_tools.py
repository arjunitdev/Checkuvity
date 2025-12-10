#!/usr/bin/env python3
"""
Supabase Tools for Security Verification
Provides database operations for trusted keys and security verifications
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "build_scripts"))

try:
    from supabase_client import SupabaseFileManager
except ImportError:
    print("Warning: Could not import SupabaseFileManager")
    SupabaseFileManager = None


class SupabaseSecurityTools:
    """Tools for security-related Supabase operations"""
    
    def __init__(self, use_service_role: bool = True):
        """Initialize Supabase client for security operations
        
        Args:
            use_service_role: Use service role key (required for security operations)
        """
        if SupabaseFileManager is None:
            raise ImportError("SupabaseFileManager not available")
        
        self.manager = SupabaseFileManager(use_service_role=use_service_role)
        self.client = self.manager.client
    
    def get_trusted_key(self, public_key_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get trusted key by public key hash
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            
        Returns:
            Trusted key record or None
        """
        try:
            result = self.client.table("trusted_public_keys").select("*").eq("public_key_hash", public_key_hash.lower()).single().execute()
            return result.data if result.data else None
        except Exception as e:
            if "No rows" in str(e) or "PGRST116" in str(e):
                return None
            print(f"Error getting trusted key: {e}")
            return None
    
    def list_trusted_keys(self, trust_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all trusted keys, optionally filtered by trust level
        
        Args:
            trust_level: Optional filter by trust level
            
        Returns:
            List of trusted key records
        """
        try:
            query = self.client.table("trusted_public_keys").select("*")
            if trust_level:
                query = query.eq("trust_level", trust_level)
            result = query.order("added_at", desc=True).execute()
            return result.data if result.data else []
        except Exception as e:
            print(f"Error listing trusted keys: {e}")
            return []
    
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
        Add a trusted public key to the registry
        
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
        try:
            key_data = {
                "public_key_hash": public_key_hash.lower(),
                "key_type": key_type,
                "key_size": key_size,
                "owner_name": owner_name,
                "organization": organization,
                "trust_level": trust_level,
                "notes": notes,
                "added_by": added_by,
            }
            
            result = self.client.table("trusted_public_keys").insert(key_data).execute()
            return result.data[0] if result.data and len(result.data) > 0 else None
        except Exception as e:
            print(f"Error adding trusted key: {e}")
            return None
    
    def update_trusted_key(
        self,
        public_key_hash: str,
        trust_level: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Update a trusted key
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            trust_level: New trust level
            notes: Updated notes
            
        Returns:
            Updated trusted key record or None
        """
        try:
            update_data = {}
            if trust_level:
                update_data["trust_level"] = trust_level
            if notes is not None:
                update_data["notes"] = notes
            
            if not update_data:
                return None
            
            result = self.client.table("trusted_public_keys").update(update_data).eq("public_key_hash", public_key_hash.lower()).execute()
            return result.data[0] if result.data and len(result.data) > 0 else None
        except Exception as e:
            print(f"Error updating trusted key: {e}")
            return None
    
    def delete_trusted_key(self, public_key_hash: str) -> bool:
        """
        Delete a trusted key from the registry
        
        Args:
            public_key_hash: SHA-256 hash of the public key
            
        Returns:
            True if deleted, False otherwise
        """
        try:
            self.client.table("trusted_public_keys").delete().eq("public_key_hash", public_key_hash.lower()).execute()
            return True
        except Exception as e:
            print(f"Error deleting trusted key: {e}")
            return False
    
    def store_verification_result(
        self,
        file_id: str,
        public_key_hash: Optional[str],
        verification_status: str,
        security_score: Optional[int],
        threats_detected: Optional[List[Dict[str, Any]]] = None,
        verification_details: Optional[Dict[str, Any]] = None,
        recommendations: Optional[List[str]] = None,
        service_version: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Store security verification result
        
        Args:
            file_id: UUID of the file
            public_key_hash: SHA-256 hash of the public key
            verification_status: Status (secure, warning, blocked, unknown)
            security_score: Security score 0-100
            threats_detected: List of detected threats
            verification_details: Full verification details
            recommendations: List of recommendations
            service_version: Version of the service
            
        Returns:
            Created verification record or None
        """
        try:
            verification_data = {
                "file_id": file_id,
                "public_key_hash": public_key_hash.lower() if public_key_hash else None,
                "verification_status": verification_status,
                "security_score": security_score,
                "threats_detected": threats_detected or [],
                "verification_details": verification_details or {},
                "recommendations": recommendations or [],
                "service_version": service_version or "1.0.0",
            }
            
            result = self.client.table("security_verifications").insert(verification_data).execute()
            return result.data[0] if result.data and len(result.data) > 0 else None
        except Exception as e:
            print(f"Error storing verification result: {e}")
            return None
    
    def get_verification_result(self, file_id: str) -> Optional[Dict[str, Any]]:
        """
        Get latest verification result for a file
        
        Args:
            file_id: UUID of the file
            
        Returns:
            Latest verification record or None
        """
        try:
            result = self.client.table("security_verifications").select("*").eq("file_id", file_id).order("verified_at", desc=True).limit(1).execute()
            return result.data[0] if result.data and len(result.data) > 0 else None
        except Exception as e:
            print(f"Error getting verification result: {e}")
            return None
    
    def update_file_security_status(
        self,
        file_id: str,
        security_status: Optional[str] = None,
        security_score: Optional[int] = None,
        public_key_hash: Optional[str] = None,
        verified_at: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Update file record with security status
        
        Args:
            file_id: UUID of the file
            security_status: Security status
            security_score: Security score
            public_key_hash: Public key hash
            verified_at: Verification timestamp
            
        Returns:
            Updated file record or None
        """
        try:
            update_data = {}
            if security_status:
                update_data["security_status"] = security_status
            if security_score is not None:
                update_data["security_score"] = security_score
            if public_key_hash:
                update_data["public_key_hash"] = public_key_hash.lower()
            if verified_at:
                update_data["verified_at"] = verified_at.isoformat()
            
            if not update_data:
                return None
            
            result = self.client.table("files").update(update_data).eq("id", file_id).execute()
            return result.data[0] if result.data and len(result.data) > 0 else None
        except Exception as e:
            print(f"Error updating file security status: {e}")
            return None
    
    def get_file(self, file_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get file record by ID
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user (for RLS)
            
        Returns:
            File record or None
        """
        try:
            result = self.client.table("files").select("*").eq("id", file_id).eq("user_id", user_id).single().execute()
            return result.data if result.data else None
        except Exception as e:
            if "No rows" in str(e) or "PGRST116" in str(e):
                return None
            print(f"Error getting file: {e}")
            return None
    
    def download_file(self, file_id: str, user_id: str) -> Optional[str]:
        """
        Download file content from Supabase Storage
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user
            
        Returns:
            File content as string or None
        """
        try:
            return self.manager.download_file(file_id, user_id)
        except Exception as e:
            print(f"Error downloading file: {e}")
            return None

    def get_user_email(self, user_id: str) -> Optional[str]:
        """Fetch user email using Supabase admin API."""
        try:
            admin = getattr(self.client.auth, "admin", None)
            if not admin:
                return None
            response = admin.get_user_by_id(user_id)
            user = getattr(response, "user", None)
            return getattr(user, "email", None)
        except Exception as e:
            print(f"Error fetching user email: {e}")
            return None

