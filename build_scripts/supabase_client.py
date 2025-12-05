#!/usr/bin/env python3
"""
Supabase Client Integration for Text File Signature Verification System.
Provides CRUD operations for files and signatures with security best practices.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    from supabase import create_client, Client
    from supabase.lib.client_options import ClientOptions
except ImportError:
    print("Warning: supabase-py not installed. Install with: pip install supabase")
    Client = None

# Project root
PROJECT_ROOT = Path(__file__).parent.parent

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # dotenv not required if env vars are set directly

def _clean(value: Optional[str]) -> str:
    """Normalize config values by stripping whitespace and converting None to empty string."""
    return value.strip() if isinstance(value, str) else ""


def load_supabase_config() -> Dict:
    """Load Supabase configuration from file and environment variables."""
    env_url = _clean(os.getenv("SUPABASE_URL"))
    env_anon = _clean(os.getenv("SUPABASE_ANON_KEY"))
    env_service = _clean(os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
    env_bucket = _clean(os.getenv("SUPABASE_STORAGE_BUCKET"))

    config_path = PROJECT_ROOT / "supabase" / "config.json"
    file_config: Dict[str, Any] = {}

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            try:
                file_config = json.load(f)
            except json.JSONDecodeError:
                file_config = {}

    supabase_config = file_config.get("supabase", {}) if isinstance(file_config, dict) else {}
    storage_config = file_config.get("storage", {}) if isinstance(file_config, dict) else {}

    return {
        "url": env_url or _clean(supabase_config.get("url")),
        "anon_key": env_anon or _clean(supabase_config.get("anon_key")),
        "service_role_key": env_service or _clean(supabase_config.get("service_role_key")),
        "bucket": env_bucket or _clean(storage_config.get("bucket")) or "text-files",
    }

PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----"
PUBLIC_KEY_END = "-----END PUBLIC KEY-----"


class SupabaseFileManager:
    """Manager for file operations in Supabase with security best practices"""
    
    def __init__(self, use_service_role: bool = False):
        """Initialize Supabase client
        
        Args:
            use_service_role: If True, use service_role_key (server-side only!)
                              If False, use anon_key (client-side, respects RLS)
        """
        config = load_supabase_config()
        self.config = config.copy()
        print("[SupabaseFileManager] Loaded config keys:",
              {k: ("[set]" if v else "[missing]") for k, v in config.items()})
        
        if not config["url"]:
            raise ValueError("Supabase configuration missing. Set SUPABASE_URL")
        
        # Use service role key only on server-side, never in client code
        if use_service_role:
            if not config["service_role_key"]:
                raise ValueError("Supabase service role key missing. Set SUPABASE_SERVICE_ROLE_KEY")
            api_key = config["service_role_key"]
        else:
            if not config["anon_key"]:
                raise ValueError("Supabase anon key missing. Set SUPABASE_ANON_KEY")
            api_key = config["anon_key"]
        
        if Client is None:
            raise ImportError("supabase-py library not installed. Install with: pip install supabase")
        
        # Create client with security options optimized for serverless
        # Disable session persistence and auto-refresh for serverless environments
        # These features don't work in Vercel/serverless and can cause FUNCTION_INVOCATION_FAILED
        client_options = None
        if ClientOptions is not None:
            try:
                candidate = ClientOptions(
                    auto_refresh_token=False,  # Disable for serverless (no persistent storage)
                    persist_session=False  # Disable for serverless (no persistent storage)
                )
                # Some older supabase-py builds shipped without the `storage` attribute.
                # If that's the case (observed in Vercel runtime), fall back to defaults.
                if not hasattr(candidate, "storage"):
                    print("[SupabaseFileManager] ClientOptions missing storage; falling back to defaults")
                else:
                    client_options = candidate
            except Exception as options_error:
                print(f"[SupabaseFileManager] Failed to construct ClientOptions: {options_error}")
        
        # Create client with error handling for serverless
        try:
            if client_options is not None:
                self.client: Client = create_client(config["url"], api_key, options=client_options)
            else:
                self.client: Client = create_client(config["url"], api_key)
        except Exception as e:
            raise ConnectionError(f"Failed to create Supabase client: {e}")
        
        print("[SupabaseFileManager] Client initialized for host:", config["url"])
        
        self.bucket_name = config["bucket"]
        self.use_service_role = use_service_role
        
        # Skip connection validation query in serverless environments
        # This query can cause FUNCTION_INVOCATION_FAILED due to timeouts during cold starts
        # Connection will be validated on first actual database operation
        # The client is created but not tested until first use
    
    def validate_hash(self, hash_value: str) -> bool:
        """Validate SHA-256 hash format"""
        if not hash_value:
            return False
        return bool(len(hash_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value))
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for storage security"""
        # Remove path components
        filename = Path(filename).name
        # Remove dangerous characters
        filename = "".join(c for c in filename if c.isalnum() or c in "._-")
        # If filename is empty after sanitization, use a default name
        if not filename:
            filename = "unnamed_file"
        # Limit length
        return filename[:255] if len(filename) > 255 else filename
    
    def get_file_by_name(self, user_id: str, file_name: str) -> Optional[Dict[str, Any]]:
        """Get a file by user_id and file_name
        
        Args:
            user_id: UUID of the user
            file_name: Name of the file
            
        Returns:
            File record or None if not found
        """
        try:
            sanitized_filename = self.sanitize_filename(file_name)
            result = self.client.table("files").select("*").eq("user_id", user_id).eq("file_name", sanitized_filename).single().execute()
            return result.data if result.data else None
        except Exception as e:
            if "No rows" in str(e) or "PGRST116" in str(e):
                return None
            raise RuntimeError(f"Failed to fetch file by name: {e}")
    
    def upload_file(
        self,
        file_path: Path,
        user_id: str,
        file_content: str,
        original_hash: str,
        signature: Optional[str] = None,
        post_signature_hash: Optional[str] = None,
        public_key_pem: Optional[str] = None,
        public_key_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Upload a text file to Supabase Storage and create or update database record
        
        Args:
            file_path: Path to the file
            user_id: UUID of the user (from auth)
            file_content: Content of the text file
            original_hash: SHA-256 hash before signature
            signature: Optional signature value
            post_signature_hash: Optional hash after signature
            public_key_pem: Optional PEM-formatted public key (for text files)
            public_key_hash: Optional SHA-256 hash of the PEM (auto-computed if omitted)
            
        Returns:
            Dictionary with file record data
        """
        # Validate inputs
        if not self.validate_hash(original_hash):
            raise ValueError(f"Invalid original_hash format: {original_hash}")
        
        if signature:
            if not isinstance(signature, str):
                raise ValueError("signature must be provided as a hexadecimal string")
            signature = signature.strip().lower()
            try:
                bytes.fromhex(signature)
            except ValueError:
                raise ValueError(f"Invalid signature format: {signature}")
        
        if post_signature_hash and not self.validate_hash(post_signature_hash):
            raise ValueError(f"Invalid post_signature_hash format: {post_signature_hash}")

        normalized_public_key_pem = None
        if public_key_pem:
            normalized_public_key_pem = public_key_pem.strip().replace('\r\n', '\n').replace('\r', '\n')
            if not normalized_public_key_pem.startswith(PUBLIC_KEY_BEGIN) or not normalized_public_key_pem.endswith(PUBLIC_KEY_END):
                raise ValueError("public_key_pem must be a PEM-formatted public key")

            pem_body = normalized_public_key_pem[len(PUBLIC_KEY_BEGIN): -len(PUBLIC_KEY_END)].strip()
            if not pem_body:
                raise ValueError("public_key_pem appears to be empty")

            if public_key_hash:
                if not self.validate_hash(public_key_hash):
                    raise ValueError(f"Invalid public_key_hash format: {public_key_hash}")
            else:
                public_key_hash = hashlib.sha256(normalized_public_key_pem.encode('utf-8')).hexdigest()
        elif public_key_hash:
            raise ValueError("public_key_hash was provided without a corresponding public_key_pem")
        
        # Sanitize filename
        sanitized_filename = self.sanitize_filename(file_path.name)
        
        # Check if file already exists and make filename unique if needed
        final_filename = sanitized_filename
        counter = 1
        while self.get_file_by_name(user_id, final_filename) is not None:
            # Append counter to make filename unique
            # Always use original sanitized_filename as base to avoid issues with existing suffixes
            name_parts = sanitized_filename.rsplit('.', 1)
            if len(name_parts) == 2:
                base_name, ext = name_parts
                final_filename = f"{base_name}_{counter}.{ext}"
            else:
                final_filename = f"{sanitized_filename}_{counter}"
            counter += 1
        
        # Storage path: user_id/final_filename
        storage_path = f"{user_id}/{final_filename}"
        
        # Upload to storage (server-side only)
        if self.use_service_role:
            try:
                print(f"[DEBUG] Uploading to storage: {storage_path}")
                # Remove existing file if it exists
                try:
                    self.client.storage.from_(self.bucket_name).remove([storage_path])
                    print(f"[DEBUG] Removed existing file at {storage_path}")
                except Exception as remove_error:
                    print(f"[DEBUG] No existing file to remove at {storage_path}: {remove_error}")
                    pass  # File doesn't exist, that's fine
                
                # Upload new file
                print(f"[DEBUG] Uploading file to storage: bucket={self.bucket_name}, path={storage_path}")
                upload_result = self.client.storage.from_(self.bucket_name).upload(
                    storage_path,
                    file_content.encode('utf-8'),
                    file_options={"content-type": "text/plain"}
                )
                print(f"[DEBUG] Storage upload successful: {upload_result}")
            except Exception as e:
                error_msg = f"Failed to upload file to storage: {e}"
                print(f"[ERROR] {error_msg}")
                import traceback
                traceback.print_exc()
                raise RuntimeError(error_msg)
        
        # Prepare file data
        file_data = {
            "user_id": user_id,
            "file_name": final_filename,
            "file_size": len(file_content.encode('utf-8')),
            "storage_path": storage_path,
            "original_hash": original_hash.lower(),  # Normalize to lowercase
            "signature": signature.lower() if signature else None,
            "post_signature_hash": post_signature_hash.lower() if post_signature_hash else None,
            "public_key_hash": public_key_hash.lower() if public_key_hash else None,
            "public_key_pem": normalized_public_key_pem,
        }
        
        print(f"[DEBUG] File data prepared: user_id={user_id}, file_name={final_filename}, original_hash={original_hash[:16] if original_hash else None}...")
        
        # Always insert new file record (never update)
        try:
            print(f"[DEBUG] Inserting file record into database...")
            result = self.client.table("files").insert(file_data).execute()
            print(f"[DEBUG] Insert result: {result}")
            if result.data and len(result.data) > 0:
                print(f"[DEBUG] File record created successfully: {result.data[0]}")
                return result.data[0]
            print(f"[ERROR] No data returned from insert: {result}")
            raise RuntimeError("Failed to create file record: No data returned")
        except Exception as e:
            error_msg = f"Failed to create file record: {e}"
            print(f"[ERROR] {error_msg}")
            import traceback
            traceback.print_exc()
            # If storage upload succeeded but DB insert failed, clean up
            if self.use_service_role:
                try:
                    print(f"[DEBUG] Cleaning up storage file after DB insert failure: {storage_path}")
                    self.client.storage.from_(self.bucket_name).remove([storage_path])
                except:
                    pass
            raise RuntimeError(error_msg)
    
    def get_user_files(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all files for a user
        
        Args:
            user_id: UUID of the user
            
        Returns:
            List of file records (RLS ensures user can only see their own files)
        """
        try:
            # First query - validate connection with timeout protection
            result = self.client.table("files").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()
            return result.data if result.data else []
        except Exception as e:
            # Log the actual error for debugging
            error_msg = str(e)
            error_type = type(e).__name__
            print(f"[Supabase] Error fetching user files: {error_type}: {error_msg}")
            
            # Check if it's a connection/timeout error
            if "timeout" in error_msg.lower() or "connection" in error_msg.lower():
                raise ConnectionError(f"Supabase connection failed: {e}")
            elif "JWT" in error_msg or "permission" in error_msg.lower() or "auth" in error_msg.lower():
                raise ValueError(f"Supabase authentication failed: {e}")
            else:
                raise RuntimeError(f"Failed to fetch user files: {e}")
    
    def get_file(self, file_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific file by ID
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user (for RLS verification)
            
        Returns:
            File record or None if not found
        """
        try:
            result = self.client.table("files").select("*").eq("id", file_id).eq("user_id", user_id).single().execute()
            return result.data if result.data else None
        except Exception as e:
            if "No rows" in str(e) or "PGRST116" in str(e):
                return None
            raise RuntimeError(f"Failed to fetch file: {e}")
    
    def update_signature(self, file_id: str, user_id: str, new_signature: str,
                        change_reason: Optional[str] = None) -> Dict[str, Any]:
        """Update signature for a file with version tracking
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user
            new_signature: New signature value
            change_reason: Optional reason for the change
            
        Returns:
            Updated file record
        """
        # Validate signature
        if not self.validate_hash(new_signature):
            raise ValueError(f"Invalid signature format: {new_signature}")
        
        # Get current file
        current_file = self.get_file(file_id, user_id)
        if not current_file:
            raise ValueError(f"File not found: {file_id}")
        
        # Calculate new post-signature hash
        original_hash = current_file["original_hash"]
        new_post_hash = self._calculate_post_hash(original_hash, new_signature)
        
        # Update file record
        update_data = {
            "signature": new_signature.lower(),
            "post_signature_hash": new_post_hash
        }
        
        try:
            # Update file
            result = self.client.table("files").update(update_data).eq("id", file_id).eq("user_id", user_id).execute()
            
            if not result.data or len(result.data) == 0:
                raise RuntimeError("Failed to update file")
            
            updated_file = result.data[0]
            
            # Create version record
            version_data = {
                "file_id": file_id,
                "user_id": user_id,
                "signature": new_signature.lower(),
                "previous_signature": current_file.get("signature"),
                "post_signature_hash": new_post_hash,
                "change_reason": change_reason or "Signature updated",
                "editor_id": user_id
            }
            
            try:
                self.client.table("file_versions").insert(version_data).execute()
            except Exception as e:
                # Log error but don't fail the update
                print(f"Warning: Failed to create version record: {e}")
            
            return updated_file
            
        except Exception as e:
            raise RuntimeError(f"Failed to update signature: {e}")
    
    def revert_signature(self, file_id: str, user_id: str, version_id: str) -> Dict[str, Any]:
        """Revert signature to a previous version
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user
            version_id: UUID of the version to revert to
            
        Returns:
            Updated file record
        """
        # Get the version to revert to
        try:
            version_result = self.client.table("file_versions").select("*").eq("id", version_id).eq("file_id", file_id).single().execute()
            if not version_result.data:
                raise ValueError(f"Version not found: {version_id}")
            
            version = version_result.data
            
            # Verify user owns the file
            file_record = self.get_file(file_id, user_id)
            if not file_record:
                raise ValueError(f"File not found or access denied: {file_id}")
            
            # Revert to version signature
            return self.update_signature(
                file_id=file_id,
                user_id=user_id,
                new_signature=version["signature"],
                change_reason=f"Reverted to version {version_id}"
            )
            
        except Exception as e:
            raise RuntimeError(f"Failed to revert signature: {e}")
    
    def get_file_versions(self, file_id: str, user_id: str) -> List[Dict[str, Any]]:
        """Get version history for a file
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user
            
        Returns:
            List of version records (ordered by created_at DESC)
        """
        # Verify user owns the file
        if not self.get_file(file_id, user_id):
            raise ValueError(f"File not found or access denied: {file_id}")
        
        try:
            result = self.client.table("file_versions").select("*").eq("file_id", file_id).order("created_at", desc=True).execute()
            return result.data if result.data else []
        except Exception as e:
            raise RuntimeError(f"Failed to fetch file versions: {e}")
    
    def delete_file(self, file_id: str, user_id: str) -> bool:
        """Delete a file and its storage object
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user
            
        Returns:
            True if successful
        """
        # Get file to get storage path
        file_record = self.get_file(file_id, user_id)
        if not file_record:
            raise ValueError(f"File not found or access denied: {file_id}")
        
        storage_path = file_record["storage_path"]
        
        try:
            # Delete from database (versions will be deleted by CASCADE)
            self.client.table("files").delete().eq("id", file_id).eq("user_id", user_id).execute()
            
            # Delete from storage (server-side only)
            if self.use_service_role:
                try:
                    self.client.storage.from_(self.bucket_name).remove([storage_path])
                except Exception as e:
                    print(f"Warning: Failed to delete file from storage: {e}")
            
            return True
            
        except Exception as e:
            raise RuntimeError(f"Failed to delete file: {e}")
    
    def _calculate_post_hash(self, original_hash: str, signature: str) -> str:
        """Calculate post-signature hash from original hash and signature"""
        combined = f"{original_hash}{signature}".encode('utf-8')
        return hashlib.sha256(combined).hexdigest()
    
    def download_file(self, file_id: str, user_id: str) -> Optional[str]:
        """Download file content from storage
        
        Args:
            file_id: UUID of the file
            user_id: UUID of the user
            
        Returns:
            File content as string or None if not found
        """
        file_record = self.get_file(file_id, user_id)
        if not file_record:
            return None
        
        storage_path = file_record["storage_path"]
        
        try:
            result = self.client.storage.from_(self.bucket_name).download(storage_path)
            return result.decode('utf-8')
        except Exception as e:
            raise RuntimeError(f"Failed to download file: {e}")

