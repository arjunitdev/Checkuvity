#!/bin/bash
# Import signing key and certificate to SoftHSM token

set -e

HSM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HSM_DIR/.." && pwd)"
CERT_DIR="$PROJECT_ROOT/certs"

USER_PIN="1234"
KEY_LABEL="signer-key"
CERT_LABEL="signer-cert"

# Load slot ID and module path
if [ ! -f "$HSM_DIR/slot_id.txt" ]; then
    echo "Error: Token not initialized. Run init_hsm.sh first."
    exit 1
fi

SLOT_ID=$(cat "$HSM_DIR/slot_id.txt")
SOFTHSM_MODULE=$(cat "$HSM_DIR/module_path.txt")

if [ ! -f "$CERT_DIR/signer.key.pem" ] || [ ! -f "$CERT_DIR/signer.cert.pem" ]; then
    echo "Error: Signer key or certificate not found in $CERT_DIR"
    echo "Please generate certificates first (run generate_certs.sh)"
    exit 1
fi

echo "Importing key and certificate to SoftHSM..."
echo "Slot ID: $SLOT_ID"
echo "Key Label: $KEY_LABEL"
echo "Cert Label: $CERT_LABEL"

# Convert PEM key to PKCS#8 DER for import
TEMP_KEY_DER=$(mktemp)
openssl pkcs8 -topk8 -inform PEM -outform DER -in "$CERT_DIR/signer.key.pem" -nocrypt -out "$TEMP_KEY_DER"

# Import private key
pkcs11-tool --module "$SOFTHSM_MODULE" --slot "$SLOT_ID" --pin "$USER_PIN" \
    --write-object "$TEMP_KEY_DER" --type privkey --label "$KEY_LABEL" --id 01

# Convert cert to DER
TEMP_CERT_DER=$(mktemp)
openssl x509 -inform PEM -outform DER -in "$CERT_DIR/signer.cert.pem" -out "$TEMP_CERT_DER"

# Import certificate
pkcs11-tool --module "$SOFTHSM_MODULE" --slot "$SLOT_ID" --pin "$USER_PIN" \
    --write-object "$TEMP_CERT_DER" --type cert --label "$CERT_LABEL" --id 01

# Cleanup
rm -f "$TEMP_KEY_DER" "$TEMP_CERT_DER"

echo "Key and certificate imported successfully!"

# Verify import
echo ""
echo "Verifying import..."
pkcs11-tool --module "$SOFTHSM_MODULE" --slot "$SLOT_ID" --pin "$USER_PIN" --list-objects

