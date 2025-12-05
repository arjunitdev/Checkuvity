# Generate demo CA and code signing certificates (PowerShell)

$ErrorActionPreference = "Stop"
$CERT_DIR = $PSScriptRoot

Write-Host "Generating CA key and certificate..."
& openssl genpkey -algorithm RSA -out "$CERT_DIR\ca.key.pem" -pkeyopt rsa_keygen_bits:4096
& openssl req -new -x509 -key "$CERT_DIR\ca.key.pem" -days 3650 -subj "/CN=Demo Root CA/O=YourOrg" -out "$CERT_DIR\ca.cert.pem"

Write-Host "Generating signer key and CSR..."
& openssl genpkey -algorithm RSA -out "$CERT_DIR\signer.key.pem" -pkeyopt rsa_keygen_bits:3072
& openssl req -new -key "$CERT_DIR\signer.key.pem" -subj "/CN=Demo Code Signer/O=YourOrg/C=US" -out "$CERT_DIR\signer.csr.pem"

Write-Host "Issuing code signing certificate..."
& openssl x509 -req -in "$CERT_DIR\signer.csr.pem" -CA "$CERT_DIR\ca.cert.pem" -CAkey "$CERT_DIR\ca.key.pem" -CAcreateserial -out "$CERT_DIR\signer.cert.pem" -days 825 -extfile "$CERT_DIR\signer_ext.cnf"

Write-Host "Certificate generation complete!"
Write-Host "CA cert: $CERT_DIR\ca.cert.pem"
Write-Host "Signer cert: $CERT_DIR\signer.cert.pem"
Write-Host "Signer key: $CERT_DIR\signer.key.pem"

