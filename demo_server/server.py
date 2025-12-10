#!/usr/bin/env python3
"""
Text File Signature Verification Server with Supabase Integration.
Handles text file uploads, signature updates, and revert operations.
"""

import io
import logging
import os
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding, rsa
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import NotFound, Unauthorized


try:
    from demo_server.config import (
        DEFAULT_DEMO_USER_ID,
        DEFAULT_HOST,
        DEFAULT_PORT,
        ERROR_MESSAGES,
        LOG_DATE_FORMAT,
        LOG_FORMAT,
        MAX_FILE_SIZE,
    )
except ImportError:
    fallback_project_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(fallback_project_root))
    sys.path.insert(0, str(fallback_project_root / "demo_server"))
    sys.path.insert(0, str(fallback_project_root / "build_scripts"))
    sys.path.insert(0, str(fallback_project_root / "security_service"))
    from demo_server.config import (
        DEFAULT_DEMO_USER_ID,
        DEFAULT_HOST,
        DEFAULT_PORT,
        ERROR_MESSAGES,
    LOG_DATE_FORMAT,
        LOG_FORMAT,
        MAX_FILE_SIZE,
    )
    PROJECT_ROOT = fallback_project_root
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent

WEB_DIR = PROJECT_ROOT / "web"
env_path = PROJECT_ROOT / ".env"
if env_path.exists():
    load_dotenv(env_path)

for extra_path in (
    PROJECT_ROOT,
    PROJECT_ROOT / "demo_server",
    PROJECT_ROOT / "build_scripts",
    PROJECT_ROOT / "security_service",
):
    path_str = str(extra_path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

try:
    from supabase_client import SupabaseFileManager
except ImportError as e:
    logging.warning(f"Supabase client not available: {e}")
    logging.warning("Running without Supabase - will use demo mode")
    SupabaseFileManager = None

logging.basicConfig(
    level=logging.DEBUG,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
)
logger = logging.getLogger(__name__)
logger.debug("Logging configured for demo server module import")

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


@app.errorhandler(404)
def not_found(error):
    return (
        jsonify(
            {"error": "Not found", "message": "The requested resource was not found"}
        ),
        404,
    )


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}", exc_info=True)
    return (
        jsonify(
            {
                "error": "Internal server error",
                "message": "An unexpected error occurred",
            }
        ),
        500,
    )


@app.errorhandler(Exception)
def handle_exception(error):
    logger.error(f"Unhandled exception: {error}", exc_info=True)
    return jsonify({"error": "Internal server error", "message": str(error)}), 500


# Initialize Supabase manager (lazy initialization for serverless)
# DO NOT initialize at module level - causes FUNCTION_INVOCATION_FAILED in Vercel
supabase_manager: Optional[SupabaseFileManager] = None
supabase_last_error: Optional[str] = None
demo_mode: bool = os.environ.get("DEMO_MODE", "true").lower() == "true"
_supabase_init_attempted = False


def _init_supabase():
    """Lazy initialization of Supabase manager - called on first request"""
    global supabase_manager, supabase_last_error, demo_mode, _supabase_init_attempted

    if supabase_manager is not None:
        return supabase_manager

    if SupabaseFileManager is None:
        if not demo_mode:
            logger.info("SupabaseFileManager not available - running in DEMO MODE")
            logger.info(
                "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables to use Supabase"
            )
        supabase_manager = None
        demo_mode = True
        _supabase_init_attempted = False
        return None

    try:
        logger.info("Initializing Supabase client...")
        supabase_url = os.environ.get("SUPABASE_URL", "")
        supabase_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
        logger.info("SUPABASE_URL env=%r", supabase_url)
        logger.info("SUPABASE_SERVICE_ROLE_KEY present=%s", bool(supabase_key))

        if not supabase_url or not supabase_key:
            raise ValueError("Supabase environment variables not configured")

        supabase_manager = SupabaseFileManager(use_service_role=True)
        demo_mode = False
        supabase_last_error = None
        _supabase_init_attempted = True
        logger.info("Supabase initialized successfully")
        return supabase_manager
    except (ValueError, ImportError) as e:
        logger.error(
            f"Supabase initialization failed (config error): {type(e).__name__}: {e}",
            exc_info=True,
        )
        logger.info(
            "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables to use Supabase"
        )
        supabase_last_error = f"{type(e).__name__}: {e}"
    except (ConnectionError, TimeoutError) as e:
        logger.error(
            f"Supabase initialization failed (connection error): {type(e).__name__}: {e}",
            exc_info=True,
        )
        logger.warning("Supabase connection failed - will retry on next request")
        supabase_last_error = f"{type(e).__name__}: {e}"
    except Exception as e:
        logger.error(
            f"Unexpected error during Supabase initialization: {type(e).__name__}: {e}",
            exc_info=True,
        )
        logger.warning("Falling back to DEMO MODE")
        supabase_last_error = f"{type(e).__name__}: {e}"

    supabase_manager = None
    if not supabase_last_error:
        supabase_last_error = "Unknown Supabase initialization error"
    demo_mode = True
    _supabase_init_attempted = False
    return None


# Demo mode: In-memory storage (always defined; toggled via demo_mode flag)
demo_files: Dict[str, Dict[str, Any]] = {}  # {file_id: file_data}
demo_versions: Dict[str, List[Dict[str, Any]]] = {}  # {file_id: [versions]}
next_file_id = 1


def validate_auth_header() -> Optional[str]:
    """Validate Authorization header and extract user_id from Supabase JWT"""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    # Extract Bearer token
    BEARER_PREFIX = "Bearer "
    if not auth_header.startswith(BEARER_PREFIX):
        return None

    _token = auth_header[len(BEARER_PREFIX) :]
    return request.json.get("user_id") if request.is_json else None


def get_user_id() -> str:
    """Get user_id from request (auth header, query param, or body)

    Returns:
        User ID string

    Raises:
        Unauthorized: If user_id cannot be determined
    """
    # Try to get from auth header first
    user_id = validate_auth_header()

    # Try query parameter (for GET requests)
    if not user_id:
        user_id = request.args.get("user_id")

    # Fallback to request body (for POST/PUT requests)
    if not user_id and request.is_json:
        user_id = request.json.get("user_id")

    # For form data (multipart/form-data)
    if not user_id and request.form:
        user_id = request.form.get("user_id")

    # For development/demo: allow user_id in request
    # In production, always verify JWT token
    # NOTE: JWT token verification is deferred for demo purposes
    # In production, implement proper JWT verification using Supabase Auth
    if not user_id:
        raise Unauthorized(ERROR_MESSAGES["auth_required"])

    return user_id


@app.route("/health", methods=["GET"])
def health() -> Tuple[Response, int]:
    """Health check endpoint

    Returns:
        Tuple of (JSON response, status code)
    """
    supabase_status = "connected" if supabase_manager else "disconnected"
    return jsonify(
        {
            "status": "healthy",
            "service": "text-file-signature-verification-server",
            "supabase": supabase_status,
        }
    )


@app.route("/api/files", methods=["POST"])
def upload_files() -> Tuple[Response, int]:
    """Upload multiple text files

    Request:
        - Form data with multiple 'files' (multipart/form-data)
        - Optional: 'user_id' in form data (if not in auth header)

    Returns:
        Tuple of (JSON response with list of uploaded file records, status code)
    """
    global next_file_id

    # Demo mode: use in-memory storage
    if demo_mode:
        return upload_files_demo()

    _init_supabase()  # Lazy initialization
    if not supabase_manager:
        return jsonify({"error": "Supabase not configured"}), 500

    try:
        # Get user_id from form data (for multipart/form-data)
        user_id = request.form.get("user_id")

        # If not in form, try to get from other sources
        if not user_id:
            try:
                user_id = get_user_id()
            except (Unauthorized, ValueError) as e:
                # For demo, use default user_id if not provided
                logger.debug(f"Could not get user_id from auth: {e}, using demo user")
                user_id = request.form.get("user_id", DEFAULT_DEMO_USER_ID)

        if "files" not in request.files:
            return jsonify({"error": ERROR_MESSAGES["no_files"]}), 400

        uploaded_files = request.files.getlist("files")
        if not uploaded_files or all(f.filename == "" for f in uploaded_files):
            return jsonify({"error": ERROR_MESSAGES["no_files"]}), 400

        results = []

        for file in uploaded_files:
            if file.filename == "":
                continue

            try:
                # Read file content
                file_bytes = file.read()
                file_path = Path(file.filename)

                if not file_bytes:
                    results.append(
                        {
                            "filename": file_path.name,
                            "error": ERROR_MESSAGES["no_files"],
                            "success": False,
                        }
                    )
                    continue

                file_content = file_bytes.decode("utf-8", errors="ignore")
                original_hash = hashlib.sha256(file_bytes).hexdigest()

                # Auto-generate key pair and signature
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend(),
                )
                public_key = private_key.public_key()

                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")

                signature_bytes = private_key.sign(
                    file_bytes,
                    crypto_padding.PKCS1v15(),
                    crypto_hashes.SHA256(),
                )
                signature_hex = signature_bytes.hex()
                public_key_hash = hashlib.sha256(
                    public_key_pem.encode("utf-8")
                ).hexdigest()

                post_hash = supabase_manager._calculate_post_hash(
                    original_hash, signature_hex
                )

                # Upload to Supabase
                logger.debug(f"Uploading file {file.filename} to Supabase...")
                file_record = supabase_manager.upload_file(
                    file_path=file_path,
                    user_id=user_id,
                    file_content=file_content,
                    original_hash=original_hash,
                    signature=signature_hex,
                    post_signature_hash=post_hash,
                    public_key_pem=public_key_pem,
                    public_key_hash=public_key_hash,
                )

                logger.info(f"Successfully uploaded file {file.filename}")

                # Trigger security verification if service is available
                security_status = None
                if security_service and file_record and file_record.get("id"):
                    try:
                        logger.info(
                            f"Triggering security verification for file {file.filename}"
                        )
                        assessment = security_service.verify_file(
                            file_record["id"], user_id
                        )
                        security_status = {
                            "status": assessment.get("security_status", "unknown"),
                            "score": assessment.get("security_score", 0),
                        }
                        logger.info(
                            f"Security verification completed: {security_status}"
                        )
                    except Exception as e:
                        logger.warning(
                            f"Security verification failed for {file.filename}: {e}"
                        )
                        # Don't fail the upload if verification fails

                result = {
                    "success": True,
                    "file": file_record,
                    "parsed": {
                        "original_hash": original_hash,
                        "signature": signature_hex,
                        "post_signature_hash": post_hash,
                        "public_key_hash": public_key_hash,
                        "public_key_pem": public_key_pem,
                    },
                }

                if security_status:
                    result["security"] = security_status

                results.append(result)

            except (ValueError, RuntimeError) as e:
                error_msg = f"{ERROR_MESSAGES['upload_failed']}: {str(e)}"
                logger.error(
                    f"Error processing file {file.filename}: {e}", exc_info=True
                )
                results.append(
                    {
                        "filename": file.filename,
                        "error": error_msg,
                        "success": False,
                        "error_type": type(e).__name__,
                    }
                )
            except Exception as e:
                error_msg = f"{ERROR_MESSAGES['upload_failed']}: {str(e)}"
                logger.error(
                    f"Unexpected error processing file {file.filename}: {e}",
                    exc_info=True,
                )
                results.append(
                    {
                        "filename": file.filename,
                        "error": error_msg,
                        "success": False,
                        "error_type": type(e).__name__,
                    }
                )

        return jsonify({"files": results}), 200

    except (ValueError, RuntimeError) as e:
        logger.error(f"Error in upload_files: {e}")
        return jsonify({"error": ERROR_MESSAGES["upload_failed"]}), 500
    except Exception as e:
        logger.error(f"Unexpected error in upload_files: {e}", exc_info=True)
        return jsonify({"error": ERROR_MESSAGES["upload_failed"]}), 500


def upload_files_demo() -> Tuple[Response, int]:
    """Demo mode: Upload files to in-memory storage

    Returns:
        Tuple of (JSON response, status code)
    """
    global next_file_id

    try:
        user_id = request.form.get("user_id", DEFAULT_DEMO_USER_ID)

        if "files" not in request.files:
            return jsonify({"error": ERROR_MESSAGES["no_files"]}), 400

        uploaded_files = request.files.getlist("files")
        if not uploaded_files or all(f.filename == "" for f in uploaded_files):
            return jsonify({"error": ERROR_MESSAGES["no_files"]}), 400

        results = []

        for file in uploaded_files:
            if file.filename == "":
                continue

            try:
                # Read file content
                file_bytes = file.read()
                file_path = Path(file.filename)

                if not file_bytes:
                    results.append(
                        {
                            "filename": file_path.name,
                            "error": ERROR_MESSAGES["no_files"],
                            "success": False,
                        }
                    )
                    continue

                file_content = file_bytes.decode("utf-8", errors="ignore")
                original_hash = hashlib.sha256(file_bytes).hexdigest()

                # Auto-generate key pair and signature
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend(),
                )
                public_key = private_key.public_key()

                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")

                signature_bytes = private_key.sign(
                    file_bytes,
                    crypto_padding.PKCS1v15(),
                    crypto_hashes.SHA256(),
                )
                signature_hex = signature_bytes.hex()
                public_key_hash = hashlib.sha256(
                    public_key_pem.encode("utf-8")
                ).hexdigest()

                post_hash = hashlib.sha256(
                    f"{original_hash}{signature_hex}".encode("utf-8")
                ).hexdigest()

                # Check if file already exists and make filename unique if needed (demo mode)
                final_filename = file_path.name
                counter = 1
                while any(
                    f["user_id"] == user_id and f["file_name"] == final_filename
                    for f in demo_files.values()
                ):
                    # Append counter to make filename unique
                    name_parts = file_path.name.rsplit(".", 1)
                    if len(name_parts) == 2:
                        base_name, ext = name_parts
                        final_filename = f"{base_name}_{counter}.{ext}"
                    else:
                        final_filename = f"{file_path.name}_{counter}"
                    counter += 1

                # Create new file record (always create new, never update)
                file_id = str(next_file_id)
                next_file_id += 1

                file_record = {
                    "id": file_id,
                    "user_id": user_id,
                    "file_name": final_filename,
                    "file_size": len(file_content.encode("utf-8")),
                    "storage_path": f"demo/{user_id}/{final_filename}",
                    "original_hash": original_hash,
                    "signature": signature_hex,
                    "post_signature_hash": post_hash,
                    "public_key_hash": public_key_hash,
                    "public_key_pem": public_key_pem,
                    "created_at": str(datetime.now()),
                    "updated_at": str(datetime.now()),
                    "content": file_content,
                }

                # Store in demo storage
                demo_files[file_id] = file_record
                demo_versions[file_id] = [
                    {
                        "id": f"{file_id}_v1",
                        "file_id": file_id,
                        "user_id": user_id,
                        "signature": signature_hex,
                        "previous_signature": None,
                        "post_signature_hash": post_hash,
                        "public_key_hash": public_key_hash,
                        "change_reason": "Initial version",
                        "created_at": str(datetime.now()),
                        "editor_id": user_id,
                    }
                ]

                results.append(
                    {
                        "success": True,
                        "file": file_record,
                        "parsed": {
                            "original_hash": original_hash,
                            "signature": signature_hex,
                            "post_signature_hash": post_hash,
                            "public_key_hash": public_key_hash,
                            "public_key_pem": public_key_pem,
                        },
                    }
                )

            except (ValueError, RuntimeError) as e:
                logger.error(f"Error processing file {file.filename} in demo mode: {e}")
                results.append(
                    {
                        "filename": file.filename,
                        "error": f"{ERROR_MESSAGES['upload_failed']}: {str(e)}",
                        "success": False,
                    }
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error processing file {file.filename} in demo mode: {e}",
                    exc_info=True,
                )
                results.append(
                    {
                        "filename": file.filename,
                        "error": f"{ERROR_MESSAGES['upload_failed']}: {str(e)}",
                        "success": False,
                    }
                )

        return jsonify({"files": results}), 200

    except (ValueError, RuntimeError) as e:
        logger.error(f"Error in upload_files_demo: {e}")
        return jsonify({"error": ERROR_MESSAGES["upload_failed"]}), 500
    except Exception as e:
        logger.error(f"Unexpected error in upload_files_demo: {e}", exc_info=True)
        return jsonify({"error": ERROR_MESSAGES["upload_failed"]}), 500


@app.route("/api/files", methods=["GET"])
def list_files() -> Tuple[Response, int]:
    """Get all files for the authenticated user

    Returns:
        List of file records
    """
    # Demo mode: use in-memory storage
    if demo_mode:
        try:
            user_id = request.args.get("user_id", DEFAULT_DEMO_USER_ID)
            files = [f for f in demo_files.values() if f["user_id"] == user_id]
            payload = {
                "files": files,
                "meta": {
                    "demo_mode": True,
                    "supabase_error": supabase_last_error,
                },
            }
            return jsonify(payload), 200
        except (KeyError, ValueError) as e:
            logger.error(f"Error in list_files (demo mode): {e}")
            return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
        except Exception as e:
            logger.error(
                f"Unexpected error in list_files (demo mode): {e}", exc_info=True
            )
            return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500

    _init_supabase()  # Lazy initialization
    if not supabase_manager:
        payload = {"error": ERROR_MESSAGES["supabase_not_configured"]}
        if supabase_last_error:
            payload["details"] = supabase_last_error
        return jsonify(payload), 500

    try:
        try:
            user_id = get_user_id()
        except (Unauthorized, ValueError) as e:
            # For demo, use default user_id if not provided
            logger.debug(f"Could not get user_id from auth: {e}, using demo user")
            user_id = request.args.get("user_id", DEFAULT_DEMO_USER_ID)

        files = supabase_manager.get_user_files(user_id)
        payload = {
            "files": files,
            "meta": {
                "demo_mode": False,
                "supabase_error": supabase_last_error,
            },
        }
        return jsonify(payload), 200
    except Unauthorized as e:
        logger.warning(f"Unauthorized access attempt: {e}")
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except (ValueError, RuntimeError) as e:
        logger.error(f"Error in list_files: {e}")
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
    except Exception as e:
        logger.error(f"Unexpected error in list_files: {e}", exc_info=True)
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500


@app.route("/api/files/<file_id>", methods=["GET"])
def get_file(file_id: str) -> Tuple[Response, int]:
    """Get a specific file by ID

    Returns:
        File record with version count
    """
    # Demo mode: use in-memory storage
    if demo_mode:
        try:
            user_id = request.args.get("user_id", DEFAULT_DEMO_USER_ID)
            if file_id not in demo_files:
                return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404

            file_record = demo_files[file_id]
            if file_record["user_id"] != user_id:
                return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404

            # Get version count
            versions = demo_versions.get(file_id, [])
            file_record_copy = file_record.copy()
            file_record_copy["version_count"] = len(versions)

            return jsonify({"file": file_record_copy}), 200
        except (KeyError, ValueError) as e:
            logger.error(f"Error in get_file (demo mode): {e}")
            return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
        except Exception as e:
            logger.error(
                f"Unexpected error in get_file (demo mode): {e}", exc_info=True
            )
            return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500

    _init_supabase()  # Lazy initialization
    if not supabase_manager:
        return jsonify({"error": ERROR_MESSAGES["supabase_not_configured"]}), 500

    try:
        user_id = get_user_id()
        file_record = supabase_manager.get_file(file_id, user_id)

        if not file_record:
            return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404

        # Get version count
        try:
            versions = supabase_manager.get_file_versions(file_id, user_id)
            file_record["version_count"] = len(versions)
        except (ValueError, RuntimeError) as e:
            logger.warning(f"Could not fetch version count for file {file_id}: {e}")
            file_record["version_count"] = 0

        return jsonify({"file": file_record}), 200
    except Unauthorized as e:
        logger.warning(f"Unauthorized access attempt for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except (ValueError, RuntimeError) as e:
        logger.error(f"Error in get_file: {e}")
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
    except Exception as e:
        logger.error(f"Unexpected error in get_file: {e}", exc_info=True)
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500


@app.route("/api/files/<file_id>/signature", methods=["PUT"])
def update_signature(file_id: str) -> Tuple[Response, int]:
    """Update signature for a file

    Request body:
        {
            "signature": "new_signature_hash",
            "change_reason": "Optional reason"
        }

    Returns:
        Updated file record
    """
    _init_supabase()  # Lazy initialization
    if not supabase_manager:
        return jsonify({"error": ERROR_MESSAGES["supabase_not_configured"]}), 500

    try:
        user_id = get_user_id()
        data = request.get_json()

        if not data or "signature" not in data:
            return jsonify({"error": ERROR_MESSAGES["signature_required"]}), 400

        new_signature = data["signature"]
        change_reason = data.get("change_reason")

        # Update signature
        updated_file = supabase_manager.update_signature(
            file_id=file_id,
            user_id=user_id,
            new_signature=new_signature,
            change_reason=change_reason,
        )

        return jsonify({"file": updated_file}), 200
    except ValueError as e:
        logger.warning(f"Invalid signature format for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["invalid_signature"]}), 400
    except Unauthorized as e:
        logger.warning(f"Unauthorized signature update attempt for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except (RuntimeError, KeyError) as e:
        logger.error(f"Error updating signature for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
    except Exception as e:
        logger.error(
            f"Unexpected error updating signature for file {file_id}: {e}",
            exc_info=True,
        )
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500


@app.route("/api/files/<file_id>/revert", methods=["POST"])
def revert_signature(file_id: str) -> Tuple[Response, int]:
    """Revert signature to a previous version

    Request body:
        {
            "version_id": "uuid_of_version_to_revert_to"
        }

    Returns:
        Updated file record
    """
    _init_supabase()  # Lazy initialization
    if not supabase_manager:
        return jsonify({"error": ERROR_MESSAGES["supabase_not_configured"]}), 500

    try:
        user_id = get_user_id()
        data = request.get_json()

        if not data or "version_id" not in data:
            return jsonify({"error": ERROR_MESSAGES["version_id_required"]}), 400

        version_id = data["version_id"]

        # Revert signature
        reverted_file = supabase_manager.revert_signature(
            file_id=file_id, user_id=user_id, version_id=version_id
        )

        return jsonify({"file": reverted_file}), 200
    except ValueError as e:
        logger.warning(f"Invalid revert request for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 400
    except Unauthorized as e:
        logger.warning(f"Unauthorized revert attempt for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except (RuntimeError, KeyError) as e:
        logger.error(f"Error reverting signature for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
    except Exception as e:
        logger.error(
            f"Unexpected error reverting signature for file {file_id}: {e}",
            exc_info=True,
        )
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500


@app.route("/api/files/<file_id>/versions", methods=["GET"])
def get_versions(file_id: str) -> Tuple[Response, int]:
    """Get version history for a file

    Returns:
        List of version records
    """
    # Demo mode: use in-memory storage
    if demo_mode:
        try:
            user_id = request.args.get("user_id", DEFAULT_DEMO_USER_ID)
            if file_id not in demo_files:
                return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404

            file_record = demo_files[file_id]
            if file_record["user_id"] != user_id:
                return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404

            versions = demo_versions.get(file_id, [])
            return jsonify({"versions": versions}), 200
        except (KeyError, ValueError) as e:
            logger.error(f"Error in get_versions (demo mode): {e}")
            return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
        except Exception as e:
            logger.error(
                f"Unexpected error in get_versions (demo mode): {e}", exc_info=True
            )
            return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500

    _init_supabase()  # Lazy initialization
    if not supabase_manager:
        return jsonify({"error": ERROR_MESSAGES["supabase_not_configured"]}), 500

    try:
        try:
            user_id = get_user_id()
        except (Unauthorized, ValueError) as e:
            # For demo, use default user_id if not provided
            logger.debug(f"Could not get user_id from auth: {e}, using demo user")
            user_id = request.args.get("user_id", DEFAULT_DEMO_USER_ID)

        versions = supabase_manager.get_file_versions(file_id, user_id)
        return jsonify({"versions": versions}), 200
    except Unauthorized as e:
        logger.warning(
            f"Unauthorized access attempt for versions of file {file_id}: {e}"
        )
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except (ValueError, RuntimeError) as e:
        logger.error(f"Error in get_versions: {e}")
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
    except Exception as e:
        logger.error(f"Unexpected error in get_versions: {e}", exc_info=True)
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500


@app.route("/api/files/<file_id>", methods=["DELETE"])
def delete_file(file_id: str) -> Tuple[Response, int]:
    """Delete a file

    Returns:
        Success message
    """
    _init_supabase()  # Lazy initialization
    if not supabase_manager:
        return jsonify({"error": ERROR_MESSAGES["supabase_not_configured"]}), 500

    try:
        user_id = get_user_id()
        supabase_manager.delete_file(file_id, user_id)
        logger.info(f"File {file_id} deleted by user {user_id}")
        return jsonify({"success": True, "message": "File deleted"}), 200
    except Unauthorized as e:
        logger.warning(f"Unauthorized delete attempt for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except (ValueError, RuntimeError) as e:
        logger.error(f"Error deleting file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
    except Exception as e:
        logger.error(f"Unexpected error deleting file {file_id}: {e}", exc_info=True)
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500


@app.route("/api/files/<file_id>/download", methods=["GET"])
def download_file(file_id: str) -> Tuple[Response, int]:
    """Download file bundle containing original file and public key for client-side verification.

    Bundle contents:
    - Original file (for hash recalculation)
    - public_key.pem (for signature decryption)

    Client can then:
    1. Decrypt signature using public key → get original hash
    2. Recalculate hash of file bytes → get new hash
    3. Compare hashes to detect tampering
    """
    try:
        user_id = get_user_id()

        if demo_mode:
            if file_id not in demo_files:
                return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404
            file_record = demo_files[file_id]
            if file_record["user_id"] != user_id:
                return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404
            filename = file_record["file_name"]
            file_content = demo_files[file_id].get("content") or ""

            # Get public key: first try stored public_key_pem (for text files), then extract from signature (for executables)
            public_key_pem = file_record.get("public_key_pem")

            # If no stored public key, try extracting from file signature (for executables)
            if not public_key_pem and security_service and file_content:
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="w", delete=False, suffix=".txt"
                    ) as tmp_file:
                        tmp_file.write(file_content)
                        tmp_path = tmp_file.name

                    public_key_info = (
                        security_service.verification_tools.extract_public_key(tmp_path)
                    )
                    if public_key_info:
                        public_key_pem = public_key_info.get("pem")

                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                except Exception as e:
                    logger.warning(
                        f"Unable to extract public key from file {file_id}: {e}"
                    )

            if not public_key_pem and security_tools:
                try:
                    verification = security_tools.get_verification_result(file_id)
                    if verification:
                        details = verification.get("verification_details") or {}
                        public_key_pem = details.get("public_key_pem")
                except Exception as e:
                    logger.warning(
                        f"Unable to fetch stored public key for file {file_id}: {e}"
                    )
        else:
            _init_supabase()  # Lazy initialization
            if not supabase_manager:
                return (
                    jsonify({"error": ERROR_MESSAGES["supabase_not_configured"]}),
                    500,
                )

            file_record = supabase_manager.get_file(file_id, user_id)
            if not file_record:
                return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404

            filename = file_record["file_name"]
            file_content = supabase_manager.download_file(file_id, user_id)
            if not file_content:
                return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404

            # Get public key: first try stored public_key_pem (for text files), then extract from signature (for executables)
            public_key_pem = file_record.get("public_key_pem")

            # If no stored public key, try extracting from file signature (for executables)
            if not public_key_pem and security_service:
                try:
                    # Download file to temp location for signature extraction
                    with tempfile.NamedTemporaryFile(
                        mode="w", delete=False, suffix=".txt"
                    ) as tmp_file:
                        tmp_file.write(file_content)
                        tmp_path = tmp_file.name

                    # Extract public key from file signature
                    public_key_info = (
                        security_service.verification_tools.extract_public_key(tmp_path)
                    )
                    if public_key_info:
                        public_key_pem = public_key_info.get("pem")

                    # Clean up temp file
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                except Exception as e:
                    logger.warning(
                        f"Unable to extract public key from file {file_id}: {e}"
                    )

            if not public_key_pem and security_tools:
                try:
                    verification = security_tools.get_verification_result(file_id)
                    if verification:
                        details = verification.get("verification_details") or {}
                        public_key_pem = details.get("public_key_pem")
                except Exception as e:
                    logger.warning(
                        f"Unable to fetch stored public key for file {file_id}: {e}"
                    )

        # Add signature content if stored
        signature_value = None
        if file_record:
            signature_value = file_record.get("signature")
            if signature_value is not None and isinstance(signature_value, bytes):
                signature_value = signature_value.hex()

        # Bundle contains: original file + public key (if available) + signature (if available)
        zip_buffer = io.BytesIO()
        zip_filename = f"{Path(filename).stem or 'file'}_bundle.zip"
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr(filename, file_content)
            if public_key_pem:
                zip_file.writestr("public_key.pem", public_key_pem)
            else:
                # If no public key found, still create bundle but log warning
                logger.warning(
                    f"No public key found for file {file_id} - bundle will only contain file"
                )
            if signature_value:
                sig_filename = f"{Path(filename).stem or 'file'}.sig"
                try:
                    signature_bytes = bytes.fromhex(signature_value)
                except ValueError:
                    signature_bytes = signature_value.encode("utf-8")
                zip_file.writestr(sig_filename, signature_bytes)
        zip_buffer.seek(0)

        return send_file(
            zip_buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name=zip_filename,
        )
    except Unauthorized as e:
        logger.warning(f"Unauthorized download attempt for file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except (ValueError, RuntimeError) as e:
        logger.error(f"Error downloading file {file_id}: {e}")
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500
    except Exception as e:
        logger.error(f"Unexpected error downloading file {file_id}: {e}", exc_info=True)
        return jsonify({"error": ERROR_MESSAGES["storage_error"]}), 500


# Import security verification service (lazy initialization)
security_service = None
security_tools = None


def _init_security_service():
    """Lazy initialization of security service"""
    global security_service, security_tools
    if security_service is None:
        try:
            from security_service.service import SecurityVerificationService
            from security_service.tools.supabase_tools import (
                SupabaseSecurityTools,
            )

            security_service = SecurityVerificationService()
            security_tools = SupabaseSecurityTools(use_service_role=True)
            
            logger.info("Security verification service initialized successfully")
        except ImportError as e:
            logger.warning(
                f"Security verification service not available (ImportError): {e}"
            )
            security_service = None
            security_tools = None
        except Exception as e:
            logger.warning(
                f"Security verification service initialization failed: {e}",
                exc_info=True,
            )
            security_service = None
            security_tools = None
    return security_service, security_tools


@app.route("/api/verify-security/<file_id>", methods=["GET"])
def verify_security(file_id: str) -> Tuple[Response, int]:
    """Verify file security using verification service

    Args:
        file_id: UUID of the file to verify

    Returns:
        JSON response with security assessment
    """
    _init_security_service()
    if not security_service:
        return jsonify({"error": "Security verification service not available"}), 503

    try:
        user_id = validate_auth_header() or DEFAULT_DEMO_USER_ID

        # Verify file security
        assessment = security_service.verify_file(file_id, user_id)

        return jsonify(assessment), 200

    except NotFound:
        return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404
    except Unauthorized:
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except Exception as e:
        logger.error(f"Error verifying security for file {file_id}: {e}", exc_info=True)
        return jsonify({"error": f"Security verification failed: {str(e)}"}), 500


@app.route("/api/security-status/<file_id>", methods=["GET"])
def get_security_status(file_id: str) -> Tuple[Response, int]:
    """Get stored security status for a file

    Args:
        file_id: UUID of the file

    Returns:
        JSON response with security status
    """
    _init_security_service()
    if not security_tools:
        return jsonify({"error": "Security tools not available"}), 503

    try:
        _ = validate_auth_header() or DEFAULT_DEMO_USER_ID

        # Get verification result
        verification = security_tools.get_verification_result(file_id)

        if not verification:
            return jsonify({"error": "No verification result found"}), 404

        return jsonify(verification), 200

    except NotFound:
        return jsonify({"error": ERROR_MESSAGES["file_not_found"]}), 404
    except Unauthorized:
        return jsonify({"error": ERROR_MESSAGES["auth_required"]}), 401
    except Exception as e:
        logger.error(
            f"Error getting security status for file {file_id}: {e}", exc_info=True
        )
        return jsonify({"error": f"Failed to get security status: {str(e)}"}), 500


@app.route("/api/trusted-keys", methods=["GET"])
def list_trusted_keys() -> Tuple[Response, int]:
    """List all trusted keys

    Returns:
        JSON response with list of trusted keys
    """
    _init_security_service()
    if not security_tools:
        return jsonify({"error": "Security tools not available"}), 503

    try:
        trust_level = request.args.get("trust_level")

        # List trusted keys
        keys = security_tools.list_trusted_keys(trust_level=trust_level)

        return jsonify({"keys": keys}), 200

    except Exception as e:
        logger.error(f"Error listing trusted keys: {e}", exc_info=True)
        return jsonify({"error": f"Failed to list trusted keys: {str(e)}"}), 500


@app.route("/api/trusted-keys", methods=["POST"])
def add_trusted_key() -> Tuple[Response, int]:
    """Add a trusted key (admin only)

    Returns:
        JSON response with created trusted key
    """
    _init_security_service()
    if not security_tools:
        return jsonify({"error": "Security tools not available"}), 503

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        required_fields = ["public_key_hash", "key_type"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        # Add trusted key
        key = security_tools.add_trusted_key(
            public_key_hash=data["public_key_hash"],
            key_type=data["key_type"],
            key_size=data.get("key_size"),
            owner_name=data.get("owner_name"),
            organization=data.get("organization"),
            trust_level=data.get("trust_level", "verified"),
            notes=data.get("notes"),
            added_by=data.get("added_by"),
        )

        if not key:
            return jsonify({"error": "Failed to add trusted key"}), 500

        return jsonify(key), 201

    except Exception as e:
        logger.error(f"Error adding trusted key: {e}", exc_info=True)
        return jsonify({"error": f"Failed to add trusted key: {str(e)}"}), 500


@app.route("/api/trusted-keys/<key_hash>", methods=["DELETE"])
def delete_trusted_key(key_hash: str) -> Tuple[Response, int]:
    """Delete a trusted key (admin only)

    Args:
        key_hash: SHA-256 hash of the public key

    Returns:
        JSON response with success status
    """
    _init_security_service()
    if not security_tools:
        return jsonify({"error": "Security tools not available"}), 503

    try:
        # Delete trusted key
        success = security_tools.delete_trusted_key(key_hash)

        if not success:
            return jsonify({"error": "Failed to delete trusted key"}), 500

        return jsonify({"success": True}), 200

    except Exception as e:
        logger.error(f"Error deleting trusted key: {e}", exc_info=True)
        return jsonify({"error": f"Failed to delete trusted key: {str(e)}"}), 500


@app.route("/assets/<path:filename>")
def serve_assets(filename: str) -> Response:
    """Serve static assets (JS, CSS, etc.)"""
    assets_dir = WEB_DIR / "assets"
    if (assets_dir / filename).exists():
        return send_from_directory(str(assets_dir), filename)
    return jsonify({"error": "Asset not found"}), 404


@app.route("/", methods=["GET"])
def index() -> Response:
    """Serve web interface"""
    web_index = WEB_DIR / "index.html"
    if web_index.exists():
        return send_from_directory(str(WEB_DIR), "index.html")
    return jsonify(
        {
            "service": "Text File Signature Verification Server",
            "endpoints": {
                "POST /api/files": "Upload multiple text files",
                "GET /api/files": "List user files",
                "GET /api/files/<id>": "Get file by ID",
                "PUT /api/files/<id>/signature": "Update signature",
                "POST /api/files/<id>/revert": "Revert signature",
                "GET /api/files/<id>/versions": "Get version history",
                "DELETE /api/files/<id>": "Delete file",
                "GET /api/files/<id>/download": "Download file",
                "GET /api/verify-security/<id>": "Verify file security",
                "GET /api/security-status/<id>": "Get security status",
                "GET /api/trusted-keys": "List trusted keys",
                "POST /api/trusted-keys": "Add trusted key",
                "DELETE /api/trusted-keys/<key_hash>": "Delete trusted key",
            },
        }
    )


def main() -> None:
    """Run the Flask server"""
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    host = os.environ.get("HOST", DEFAULT_HOST)
    debug = os.environ.get("DEBUG", "False").lower() == "true"

    logger.info("=" * 60)
    logger.info("Text File Signature Verification Server")
    logger.info("=" * 60)
    logger.info(f"Server starting on http://{host}:{port}")
    logger.info(f"Debug mode: {debug}")
    if demo_mode:
        logger.info("Running in DEMO MODE (in-memory storage)")
        logger.info("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to use Supabase")
    else:
        logger.info(
            f"Supabase: {'Connected' if supabase_manager else 'Not configured'}"
        )
    logger.info("=" * 60)

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
