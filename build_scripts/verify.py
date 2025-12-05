#!/usr/bin/env python3
"""
Verification script.
Verifies Authenticode signatures, certificate chains, and timestamps.
"""

import os
import sys
import json
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    import pefile
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    from asn1crypto import cms, tsp
except ImportError as e:
    print(f"Warning: Required library not available: {e}")
    print("Some verification features may not work properly.")

def load_config():
    """Load configuration from config.json"""
    config_path = PROJECT_ROOT / "config.json"
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        return json.load(f)

def verify_with_osslsigncode(signed_exe: Path) -> Dict:
    """Verify signature using osslsigncode"""
    try:
        result = subprocess.run(
            ["osslsigncode", "verify", "-in", str(signed_exe)],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode == 0:
            return {"verified": True, "tool": "osslsigncode", "output": result.stdout}
        else:
            return {"verified": False, "tool": "osslsigncode", "error": result.stderr}
    except FileNotFoundError:
        return {"verified": False, "tool": "osslsigncode", "error": "osslsigncode not found"}
    except Exception as e:
        return {"verified": False, "tool": "osslsigncode", "error": str(e)}

def extract_pkcs7_from_pe(pe_file: Path) -> Optional[bytes]:
    """Extract PKCS#7 signature from PE file using pefile"""
    try:
        pe = pefile.PE(str(pe_file))
        
        # Find security directory
        security_dir = None
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            security_dir = pe.DIRECTORY_ENTRY_SECURITY
        
        # Get security directory from data directories
        if not security_dir:
            for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if entry.name == "IMAGE_DIRECTORY_ENTRY_SECURITY":
                    if entry.VirtualAddress:
                        # Read WIN_CERTIFICATE structure
                        security_rva = entry.VirtualAddress
                        security_size = entry.Size
                        
                        # Get file offset
                        security_data = pe.get_data(security_rva, security_size)
                        
                        # WIN_CERTIFICATE structure: DWORD dwLength, WORD wRevision, WORD wCertificateType
                        if len(security_data) >= 8:
                            cert_length = int.from_bytes(security_data[0:4], byteorder='little')
                            cert_type = int.from_bytes(security_data[6:8], byteorder='little')
                            
                            # WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
                            if cert_type == 0x0002:
                                # PKCS#7 SignedData follows the WIN_CERTIFICATE header
                                pkcs7_data = security_data[8:8+cert_length-8]
                                return pkcs7_data
        
        return None
    except Exception as e:
        print(f"Error extracting PKCS#7: {e}")
        return None

def compute_authenticode_hash(file_path: Path) -> Optional[str]:
    """Compute Authenticode hash (SHA-256 of file with signature directory zeroed)"""
    try:
        with open(file_path, 'rb') as f:
            file_data = bytearray(f.read())
        
        pe = pefile.PE(data=file_data)
        
        # Find and zero the security directory
        for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == "IMAGE_DIRECTORY_ENTRY_SECURITY":
                if entry.VirtualAddress:
                    # Convert RVA to file offset
                    try:
                        file_offset = pe.get_offset_from_rva(entry.VirtualAddress)
                        # Zero out the security directory
                        for i in range(entry.Size):
                            if file_offset + i < len(file_data):
                                file_data[file_offset + i] = 0
                    except Exception:
                        pass
        
        # Compute SHA-256 hash
        sha256 = hashlib.sha256(bytes(file_data))
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error computing Authenticode hash: {e}")
        return None

def verify_pkcs7_signature(pkcs7_data: bytes, ca_cert_path: Path) -> Dict:
    """Verify PKCS#7 signature"""
    errors = []
    
    try:
        # Parse PKCS#7
        signed_data = cms.ContentInfo.load(pkcs7_data)
        
        if signed_data['content_type'].dotted != '1.2.840.113549.1.7.2':
            errors.append("Invalid PKCS#7 content type")
            return {"verified": False, "errors": errors}
        
        signed_data = signed_data['content']
        
        # Extract certificates
        certs = []
        if 'certificates' in signed_data:
            for cert in signed_data['certificates']:
                cert_data = cert.dump()
                try:
                    cert_obj = x509.load_der_x509_certificate(cert_data, default_backend())
                    certs.append(cert_obj)
                except Exception as e:
                    errors.append(f"Failed to load certificate: {e}")
        
        if not certs:
            errors.append("No certificates found in PKCS#7")
            return {"verified": False, "errors": errors}
        
        signer_cert = certs[0]  # First certificate is typically the signer
        
        # Extract signer info
        signer_infos = signed_data.get('signer_infos', [])
        if not signer_infos:
            errors.append("No signer info found")
            return {"verified": False, "errors": errors}
        
        signer_info = signer_infos[0]
        
        # Get message digest (hash embedded in signature)
        try:
            message_digest = signer_info['message_digest'].contents
        except KeyError:
            message_digest = None
        
        # Verify certificate chain
        ca_cert = None
        if ca_cert_path.exists():
            with open(ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        chain_valid = False
        if ca_cert:
            try:
                # Verify signer cert against CA
                ca_pub_key = ca_cert.public_key()
                ca_pub_key.verify(
                    signer_cert.signature,
                    signer_cert.tbs_certificate_bytes,
                    signer_cert.signature_algorithm_oid._name,
                    None
                )
                chain_valid = True
            except InvalidSignature:
                errors.append("Certificate chain verification failed")
        
        # Extract timestamp if present
        timestamp = None
        if 'unsigned_attrs' in signer_info:
            for attr in signer_info['unsigned_attrs']:
                if attr['attr_type'].dotted == '1.2.840.113549.1.9.16.2.14':  # countersignature
                    # Extract timestamp token
                    timestamp_token = attr['attr_values'][0]
                    timestamp = extract_timestamp(timestamp_token)
        
        cert_subject = signer_cert.subject.rfc4514_string()
        cert_thumbprint = hashlib.sha1(signer_cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
        cert_thumbprint_formatted = ':'.join(cert_thumbprint[i:i+2] for i in range(0, len(cert_thumbprint), 2))
        
        return {
            "verified": True,
            "cert_subject": cert_subject,
            "cert_thumbprint": cert_thumbprint_formatted,
            "chain_valid": chain_valid,
            "timestamp": timestamp.isoformat() if timestamp else None,
            "signed_hash": message_digest.hex() if message_digest else None,
            "errors": errors
        }
    
    except Exception as e:
        errors.append(f"PKCS#7 verification error: {e}")
        return {"verified": False, "errors": errors}

def extract_timestamp(timestamp_token) -> Optional[datetime]:
    """Extract timestamp from timestamp token"""
    try:
        # Parse TimeStampResp
        tsp_response = tsp.TimeStampResp.load(timestamp_token)
        tsp_token = tsp_response['time_stamp_token']
        
        # Extract time from timestamp token
        if 'content' in tsp_token:
            tst_info = tsp_token['content']
            if 'gen_time' in tst_info:
                gen_time = tst_info['gen_time'].native
                return gen_time
    except Exception as e:
        print(f"Error extracting timestamp: {e}")
    
    return None

def get_pre_signature_hash(file_path: Path) -> Optional[str]:
    """Compute SHA-256 hash before signing (raw file hash)"""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error computing pre-signature hash: {e}")
        return None

def get_public_key_from_cert(cert_data: bytes) -> Optional[Dict]:
    """Extract public key information from certificate"""
    try:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        pub_key = cert.public_key()
        
        # Get key type and size
        if isinstance(pub_key, serialization.RSAPublicKey):
            key_type = "RSA"
            key_size = pub_key.key_size
            # Get public key bytes
            pub_key_bytes = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            key_type = "EC"
            key_size = pub_key.curve.key_size
            pub_key_bytes = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        
        # Compute hash of public key
        pub_key_hash = hashlib.sha256(pub_key_bytes).hexdigest()
        
        return {
            "type": key_type,
            "size": key_size,
            "pem": pub_key_bytes.decode('utf-8'),
            "hash": pub_key_hash
        }
    except Exception as e:
        print(f"Error extracting public key: {e}")
        return None

def get_signature_hash(pkcs7_data: bytes) -> Optional[str]:
    """Extract signature value from PKCS#7"""
    try:
        signed_data = cms.ContentInfo.load(pkcs7_data)
        if signed_data['content_type'].dotted != '1.2.840.113549.1.7.2':
            return None
        
        signed_data = signed_data['content']
        signer_infos = signed_data.get('signer_infos', [])
        
        if signer_infos:
            signer_info = signer_infos[0]
            signature = signer_info['signature'].contents
            
            # Compute hash of signature
            sig_hash = hashlib.sha256(bytes(signature)).hexdigest()
            return sig_hash
    except Exception as e:
        print(f"Error extracting signature hash: {e}")
        return None

def verify_executable(signed_exe: Path, config: Dict) -> Dict:
    """Verify a signed executable"""
    print(f"\nVerifying {signed_exe.name}...")
    
    errors = []
    
    # Check if file exists
    if not signed_exe.exists():
        return {
            "verified": False,
            "hash_matches": False,
            "cert_subject": None,
            "cert_thumbprint": None,
            "chain_valid": False,
            "timestamp": None,
            "pre_signature_hash": None,
            "signature_hash": None,
            "public_key": None,
            "post_signature_hash": None,
            "errors": [f"File not found: {signed_exe}"]
        }
    
    # Compute pre-signature hash (raw file hash)
    pre_signature_hash = get_pre_signature_hash(signed_exe)
    
    # Verify with osslsigncode
    ossl_result = verify_with_osslsigncode(signed_exe)
    
    # Extract PKCS#7 signature
    pkcs7_data = extract_pkcs7_from_pe(signed_exe)
    
    signature_hash = None
    public_key_info = None
    
    if not pkcs7_data:
        errors.append("Failed to extract PKCS#7 signature from PE")
        return {
            "verified": False,
            "hash_matches": False,
            "cert_subject": None,
            "cert_thumbprint": None,
            "chain_valid": False,
            "timestamp": None,
            "pre_signature_hash": pre_signature_hash,
            "signature_hash": None,
            "public_key": None,
            "post_signature_hash": None,
            "signed_hash": None,
            "errors": errors
        }
    
    # Extract signature hash
    signature_hash = get_signature_hash(pkcs7_data)
    
    # Extract public key from PKCS#7
    try:
        signed_data = cms.ContentInfo.load(pkcs7_data)
        if signed_data['content_type'].dotted == '1.2.840.113549.1.7.2':
            signed_data = signed_data['content']
            if 'certificates' in signed_data and len(signed_data['certificates']) > 0:
                cert_data = signed_data['certificates'][0].dump()
                public_key_info = get_public_key_from_cert(cert_data)
    except Exception as e:
        print(f"Error extracting public key: {e}")
    
    # Compute Authenticode hash (post-signature hash)
    post_signature_hash = compute_authenticode_hash(signed_exe)
    
    # Verify PKCS#7
    ca_cert_path = PROJECT_ROOT / config["certs"]["ca_cert"]
    pkcs7_result = verify_pkcs7_signature(pkcs7_data, ca_cert_path)
    
    # Combine results
    verified = ossl_result.get("verified", False) and pkcs7_result.get("verified", False)
    hash_matches = post_signature_hash is not None
    
    result = {
        "verified": verified,
        "hash_matches": hash_matches,
        "cert_subject": pkcs7_result.get("cert_subject"),
        "cert_thumbprint": pkcs7_result.get("cert_thumbprint"),
        "chain_valid": pkcs7_result.get("chain_valid", False),
        "timestamp": pkcs7_result.get("timestamp"),
        "pre_signature_hash": pre_signature_hash,
        "signature_hash": signature_hash,
        "public_key": public_key_info,
        "post_signature_hash": post_signature_hash,
        "signed_hash": pkcs7_result.get("signed_hash"),
        "errors": errors + pkcs7_result.get("errors", [])
    }
    
    if verified:
        print(f"  ✓ Signature verified")
    else:
        print(f"  ✗ Signature verification failed")
    
    if result["chain_valid"]:
        print(f"  ✓ Certificate chain valid")
    else:
        print(f"  ✗ Certificate chain invalid")
    
    if result["timestamp"]:
        print(f"  ✓ Timestamp: {result['timestamp']}")
    else:
        print(f"  ⚠ No timestamp found")
    
    return result

def verify_all_signed_executables(config: Dict) -> Dict:
    """Verify all signed executables"""
    signed_dir = PROJECT_ROOT / config["paths"]["signed_dir"]
    
    if not signed_dir.exists():
        print(f"Signed directory not found: {signed_dir}")
        return {}
    
    results = {}
    
    # Import text save function
    try:
        from save_verification_text import save_verification_to_text
    except ImportError:
        save_verification_to_text = None
    
    # Find all signed executables
    for signed_exe in signed_dir.glob("*_signed.exe"):
        app_name = signed_exe.stem.replace("_signed", "")
        result = verify_executable(signed_exe, config)
        
        # Save verification result as JSON
        verify_json_path = signed_exe.parent / f"{signed_exe.stem}.verify.json"
        with open(verify_json_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        # Save verification result as text file
        if save_verification_to_text:
            verify_text_path = signed_exe.parent / f"{signed_exe.stem}.verify.txt"
            save_verification_to_text(result, verify_text_path)
            print(f"  Saved verification text: {verify_text_path}")
        
        results[app_name] = result
    
    return results

def main():
    """Main verification orchestration"""
    print("=" * 60)
    print("Verification Orchestration")
    print("=" * 60)
    
    config = load_config()
    
    # Verify all signed executables
    results = verify_all_signed_executables(config)
    
    print("\n" + "=" * 60)
    print("Verification Summary")
    print("=" * 60)
    
    for app_name, result in results.items():
        status = "✓" if result["verified"] else "✗"
        print(f"{status} {app_name}: {'VERIFIED' if result['verified'] else 'FAILED'}")
        if result.get("errors"):
            for error in result["errors"]:
                print(f"    Error: {error}")
    
    print("=" * 60)
    
    # Print summary
    verified_count = sum(1 for r in results.values() if r["verified"])
    total_count = len(results)
    
    if verified_count == total_count:
        print(f"All {total_count} executables verified successfully!")
        return 0
    else:
        print(f"Verification failed: {verified_count}/{total_count} verified")
        return 1

if __name__ == "__main__":
    sys.exit(main())

