#!/bin/bash
# Generate demo CA and code signing certificates

set -e

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CERT_DIR"

echo "Generating CA key and certificate..."
openssl genpkey -algorithm RSA -out ca.key.pem -pkeyopt rsa_keygen_bits:4096
openssl req -new -x509 -key ca.key.pem -days 3650 -subj "/CN=Demo Root CA/O=YourOrg" -out ca.cert.pem

echo "Generating signer key and CSR..."
openssl genpkey -algorithm RSA -out signer.key.pem -pkeyopt rsa_keygen_bits:3072
openssl req -new -key signer.key.pem -subj "/CN=Demo Code Signer/O=YourOrg/C=US" -out signer.csr.pem

echo "Issuing code signing certificate..."
openssl x509 -req -in signer.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out signer.cert.pem -days 825 -extfile signer_ext.cnf

echo "Certificate generation complete!"
echo "CA cert: $CERT_DIR/ca.cert.pem"
echo "Signer cert: $CERT_DIR/signer.cert.pem"
echo "Signer key: $CERT_DIR/signer.key.pem"

