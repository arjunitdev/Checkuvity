#!/bin/bash
# Initialize SoftHSM token

set -e

HSM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKEN_LABEL="DemoToken"
USER_PIN="1234"
SO_PIN="5678"

echo "Initializing SoftHSM token..."
echo "Token Label: $TOKEN_LABEL"
echo "User PIN: $USER_PIN"
echo "SO PIN: $SO_PIN"

# Find SoftHSM module path
SOFTHSM_MODULE=$(find /usr/lib* -name "libsofthsm2.so" 2>/dev/null | head -1)

if [ -z "$SOFTHSM_MODULE" ]; then
    echo "Error: SoftHSM module not found. Please install SoftHSM v2."
    echo "On Debian/Ubuntu: sudo apt install softhsm2"
    exit 1
fi

echo "SoftHSM module found: $SOFTHSM_MODULE"

# Initialize token (use --free to find free slot)
SLOT_ID=$(softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$USER_PIN" --so-pin "$SO_PIN" | grep -oP 'Slot \K[0-9]+')

if [ -z "$SLOT_ID" ]; then
    echo "Error: Failed to initialize token"
    exit 1
fi

echo "Token initialized successfully!"
echo "Slot ID: $SLOT_ID"

# Save slot ID to config
echo "$SLOT_ID" > "$HSM_DIR/slot_id.txt"
echo "$SOFTHSM_MODULE" > "$HSM_DIR/module_path.txt"

echo "Configuration saved to $HSM_DIR/slot_id.txt and $HSM_DIR/module_path.txt"

