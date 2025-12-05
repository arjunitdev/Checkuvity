#!/usr/bin/env python3
"""
Generate demo CA and code signing certificates using Python cryptography library.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend

CERT_DIR = Path(__file__).parent

def generate_ca_certificate():
    """Generate CA key and certificate"""
    print("Generating CA key and certificate...")
    
    # Generate CA private key (RSA 4096)
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Create CA certificate
    ca_subject = ca_issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Demo Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YourOrg"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save CA key
    ca_key_path = CERT_DIR / "ca.key.pem"
    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save CA cert
    ca_cert_path = CERT_DIR / "ca.cert.pem"
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"  CA cert saved: {ca_cert_path}")
    print(f"  CA key saved: {ca_key_path}")
    
    return ca_key, ca_cert

def generate_signer_certificate(ca_key, ca_cert):
    """Generate signer key and certificate signed by CA"""
    print("Generating signer key and certificate...")
    
    # Generate signer private key (RSA 3072)
    signer_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )
    
    # Create signer CSR
    signer_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Demo Code Signer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YourOrg"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    
    # Save CSR (optional, for reference)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        signer_subject
    ).sign(signer_key, hashes.SHA256(), default_backend())
    
    csr_path = CERT_DIR / "signer.csr.pem"
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    
    # Create signer certificate signed by CA
    signer_cert = x509.CertificateBuilder().subject_name(
        signer_subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        signer_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=825)  # ~2.25 years
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,  # nonRepudiation
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save signer key
    signer_key_path = CERT_DIR / "signer.key.pem"
    with open(signer_key_path, "wb") as f:
        f.write(signer_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save signer cert
    signer_cert_path = CERT_DIR / "signer.cert.pem"
    with open(signer_cert_path, "wb") as f:
        f.write(signer_cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"  Signer cert saved: {signer_cert_path}")
    print(f"  Signer key saved: {signer_key_path}")
    print(f"  CSR saved: {csr_path}")
    
    return signer_key, signer_cert

def main():
    """Generate all certificates"""
    print("=" * 60)
    print("Certificate Generation")
    print("=" * 60)
    
    # Generate CA
    ca_key, ca_cert = generate_ca_certificate()
    
    # Generate signer certificate
    signer_key, signer_cert = generate_signer_certificate(ca_key, ca_cert)
    
    print("\n" + "=" * 60)
    print("Certificate generation complete!")
    print(f"Certificate directory: {CERT_DIR}")
    print("=" * 60)

if __name__ == "__main__":
    main()

