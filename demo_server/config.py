#!/usr/bin/env python3
"""
Configuration constants for the Text File Signature Verification Server.
"""

# Hash constants
SHA256_HASH_LENGTH = 64  # SHA-256 produces 64 hex characters
MAX_FILENAME_LENGTH = 255

# File size limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB in bytes

# Default values
DEFAULT_DEMO_USER_ID = "00000000-0000-0000-0000-000000000000"
DEFAULT_PORT = 5000
DEFAULT_HOST = "0.0.0.0"

# Error messages (user-friendly, no internal details)
ERROR_MESSAGES = {
    "no_files": "No files provided",
    "file_not_found": "File not found",
    "supabase_not_configured": "Storage service not configured",
    "auth_required": "Authentication required. Provide user_id or valid JWT token",
    "invalid_signature": "Invalid signature format. Must be 64 hexadecimal characters.",
    "signature_required": "signature is required",
    "version_id_required": "version_id is required",
    "parse_failed": "Failed to parse file",
    "upload_failed": "Failed to upload file",
    "storage_error": "Storage operation failed",
}

# Logging configuration
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"












