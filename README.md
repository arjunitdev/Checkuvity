# Checkuvity

**A digital signing service that creates cryptographic verification packages for your files.**

Checkuvity generates the signature files that others can use to verify your files haven't been tampered with. Think of it as a **digital notary stamp generator** - you upload a file, and it creates the cryptographic proof of authenticity.

---

## What Does Checkuvity Do?

Checkuvity **creates verification packages** for your files:

1. **Upload a file** → System generates cryptographic signatures
2. **Get a bundle** → Download file + signature (.sig) + public key (.pem)
3. **Share with others** → Recipients can verify file authenticity using the bundle
4. **Track versions** → All signature versions stored with full history
5. **Manage trust** → Mark public keys as trusted/untrusted in your registry

### What You Receive

After uploading a file, you get:
- **`.sig` file** - Cryptographic signature (proof of authenticity)
- **`.pem` file** - Public key (for verification)
- **Original file** - Your uploaded content
- **Metadata** - Hashes, timestamps, version info

### Real-World Use Case

**Scenario:** You're distributing software or documents and need to prove authenticity.

**Without Checkuvity:**
- Manually create signatures using command-line tools
- Manually manage public/private keys
- No central tracking or version history
- Complex for non-technical users

**With Checkuvity:**
- Upload file → Get instant signature bundle
- Public keys managed automatically
- Full version history tracked
- Simple web interface + API
- Recipients verify using standard tools (openssl, gpg, etc.)

**Example:**
```
You upload: config.yaml
You receive: config.yaml + config.yaml.sig + public_key.pem

Recipients can verify:
$ openssl dgst -sha256 -verify public_key.pem -signature config.yaml.sig config.yaml
Verified OK ✓
```

---

## How It Works (Simple Explanation)

### Step 1: Upload Your File
```
Your file → Checkuvity → Signature generated
```
Upload any text file through the web UI or API.

### Step 2: Cryptographic Signing
```
File content → SHA-256 hash → RSA signature (2048-bit)
```
Checkuvity automatically:
1. **Calculates SHA-256 hash** - Creates unique fingerprint of your file
2. **Generates RSA key pair** - 2048-bit private/public keys
3. **Signs the hash** - Encrypts hash with private key
4. **Creates post-signature hash** - Additional tamper protection
5. **Stores everything** - File, signatures, keys, metadata

### Step 3: Download Verification Bundle
```
Download → ZIP file with: file + .sig + .pem
```
You receive a complete verification package:
- **`yourfile.txt`** - Original file
- **`yourfile.txt.sig`** - Cryptographic signature (512-char hex)
- **`public_key.pem`** - Public key for verification

### Step 4: Recipients Verify (Outside Checkuvity)
Recipients use standard tools to verify:

**Using OpenSSL:**
```bash
openssl dgst -sha256 -verify public_key.pem \
  -signature yourfile.txt.sig yourfile.txt
# Output: Verified OK ✓
```

**What verification proves:**
- ✓ File hasn't been modified
- ✓ Signature was created by holder of private key
- ✓ File is authentic

### Internal Security Scoring
Checkuvity also provides a 0-100 security score for internal tracking:
- Signature validity
- Public key trust level
- Hash consistency
- Timestamp presence
- Threat intelligence (placeholder)

**Score ranges:** 70-100 (secure) | 50-69 (warning) | 30-49 (unknown) | 0-29 (blocked)

---

## Why Checkuvity?

Creating cryptographic signatures manually is complex and error-prone:

**❌ Problem 1: Manual Signature Creation**
```bash
# Traditional manual process:
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl dgst -sha256 -sign private.pem -out file.sig file.txt
# Then manually manage all these files...
```
- Too technical for most users
- Easy to make mistakes
- No version tracking
- No centralized key management

**❌ Problem 2: Distribution Challenges**
- Where to store signatures?
- How to distribute public keys?
- How to track which signature goes with which version?
- No audit trail

**✅ Checkuvity Solution**
- **One-click signing** - Upload file, get instant signatures
- **Automatic key management** - Keys generated and stored securely
- **Bundle downloads** - Everything packaged in one ZIP
- **Version history** - Full audit trail of all signatures
- **Trust registry** - Central management of public keys
- **Web interface + API** - Both technical and non-technical users
- **Optional cloud storage** - Keep everything backed up (Supabase)

---

## How Recipients Verify (Outside Checkuvity)

**Important:** Checkuvity creates the signatures. Recipients verify using standard tools.

### Verification Process (Recipient Side)

1. **Receive bundle** from you (file + .sig + .pem)
2. **Verify using OpenSSL:**
```bash
openssl dgst -sha256 -verify public_key.pem \
  -signature file.sig file.txt
```
3. **Result:** `Verified OK` = file is authentic and unmodified

### Other Verification Tools
- **GPG/PGP** - Can verify with key conversion
- **Python cryptography** - Programmatic verification
- **Custom tools** - Any tool that supports RSA + SHA-256

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Checkuvity (Signature Creation Service)            │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Frontend (React)  →  Flask API  →  Storage         │
│  - Upload UI           - Sign files    - Supabase   │
│  - Download UI         - Manage keys   - Demo mode  │
│                        - Track history              │
│                                                      │
│  Security Service (Internal checks only)            │
│  - Validates stored signatures                      │
│  - Tracks trust levels                              │
│                                                      │
└─────────────────────────────────────────────────────┘
                         ↓
                   Bundle Output
                         ↓
         ┌───────────────────────────┐
         │ file.txt                  │
         │ file.txt.sig              │
         │ public_key.pem            │
         └───────────────────────────┘
                         ↓
              Recipient Verifies
              (OpenSSL, GPG, etc.)
```

**Key Components:**
- **`demo_server/`** - Flask API for signature generation
- **`security_service/`** - Internal security checks (not external verification)
- **`frontend/`** - React UI for uploads/downloads
- **`supabase/`** - Optional persistent storage

---

## Key Features

### 🔐 Signature Creation
- **Automatic RSA signing** - 2048-bit cryptographic signatures generated instantly
- **SHA-256 hashing** - Industry-standard file fingerprinting
- **Key pair generation** - Private/public keys created and managed automatically
- **Post-signature hashing** - Additional integrity layer for signatures themselves

### 📦 Bundle Generation
- **One-click download** - Get file + `.sig` + `.pem` in a single ZIP
- **Standard formats** - Compatible with OpenSSL, GPG, and other verification tools
- **Complete packages** - Everything needed for verification included
- **Shareable** - Easy to distribute to recipients

### 📝 File & Version Management
- **Upload via UI or API** - Support for both interfaces
- **Automatic versioning** - Every upload tracked with full history
- **Version revert** - Roll back to any previous signature
- **Metadata tracking** - Timestamps, hashes, and change reasons stored

### 🛡️ Trust & Security
- **Public key registry** - Central store for trusted keys
- **Trust levels** - Mark keys as trusted/verified/suspicious/blocked
- **Internal scoring** - 0-100 security assessment for tracking
- **Audit trail** - Complete history of all operations

### 💾 Flexible Deployment
- **Demo mode** - Run entirely in-memory (no setup needed)
- **Supabase mode** - Cloud persistence with automatic backups
- **Local or cloud** - Deploy anywhere Python runs
- **REST API** - Integrate with existing workflows

---

## Quick Start (5 Minutes)

### Option 1: Full Stack (Backend + Frontend)

**1. Start the backend server:**
```powershell
cd demo_server
pip install -r requirements.txt
$env:DEMO_MODE="true"
$env:FLASK_APP="server.py"
python -m flask run --host=0.0.0.0 --port=5000
```

**2. In a new terminal, start the frontend:**
```powershell
cd frontend
npm install
npm run dev
```

**3. Open in browser:**
```
http://localhost:5173  (Frontend UI)
http://localhost:5000  (Backend API)
```

### Option 2: Backend Only (API Testing)

Just run step 1 above, then test with curl:

```powershell
# Upload a file
curl -X POST http://localhost:5000/api/files -F "files=@yourfile.txt"

# List files
curl http://localhost:5000/api/files

# Download bundle
curl http://localhost:5000/api/files/<file-id>/download -o bundle.zip
```

---

## What You Get

When running locally in **demo mode** (default):
- ✅ All features work
- ✅ Files stored in memory
- ✅ No database setup needed
- ✅ Perfect for testing
- ⚠️ Data lost on restart

When running with **Supabase mode**:
- ✅ Persistent storage
- ✅ Cloud backup
- ✅ Multi-user support
- ✅ Production-ready
- ⚙️ Requires Supabase setup

---

## Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `DEMO_MODE` | `true` disables Supabase, stores everything in memory | `true` |
| `SUPABASE_URL` | Supabase project URL | _(required for Supabase mode)_ |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key | _(required for Supabase mode)_ |
| `FLASK_APP` | Entry file for Flask | `server.py` |
| `FLASK_ENV` | Set to `development` for debug reload | _(optional)_ |

You can copy `.env.example` (if present) or create your own `.env` at the repo root. The server reads it automatically.

---

## API Overview

### Signature Generation
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/files` | `POST` | Upload file → Get instant cryptographic signature |
| `/api/files/<file_id>/download` | `GET` | Download complete bundle (file + .sig + .pem) |
| `/api/files/<file_id>/sign` | `PUT` | Re-sign file (create new signature) |

### File Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/files` | `GET` | List all signed files |
| `/api/files/<file_id>` | `GET` | Get file metadata + signatures |
| `/api/files/<file_id>` | `DELETE` | Remove file and signatures |
| `/api/files/<file_id>/versions` | `GET` | View signature version history |
| `/api/files/<file_id>/revert` | `POST` | Revert to previous signature version |

### Trust Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/trusted-keys` | `GET` | List trusted public keys |
| `/api/trusted-keys` | `POST` | Add public key to trust registry |
| `/api/trusted-keys` | `DELETE` | Remove public key from registry |
| `/api/verify-security/<file_id>` | `GET` | Check internal security status (signature validity, trust level) |
| `/api/security-status/<file_id>` | `GET` | Get latest security assessment |

**Note:** Authentication defaults to demo mode (`DEFAULT_DEMO_USER_ID`). Production deployments should enable Supabase JWT verification—see `validate_auth_header()` in the code.

---

## Internal Security Service

The security service checks the integrity and security status of **files stored in Checkuvity**:

**What it checks:**
- Signature validity (cryptographic correctness)
- Public key trust level (from registry)
- Hash consistency (file hasn't changed since signing)
- Timestamp presence
- Security scoring (0-100 risk assessment)

**Note:** This is for internal tracking only. Recipients verify files using standard tools like OpenSSL.

```powershell
cd security_service
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

The Flask server automatically uses this service for `/api/verify-security` and `/api/security-status` endpoints.

---

## Supabase Integration (Optional)

By default, Checkuvity runs in **demo mode** (in-memory). Enable Supabase for:
- **Persistent storage** - Files and signatures survive restarts
- **Cloud backup** - Automatic backup and recovery
- **Multi-user** - Proper user isolation and authentication
- **Production ready** - Scale to many users

### Setup Steps

1. **Create Supabase project** at https://supabase.com

2. **Apply database schema:**
   - Run SQL files in `supabase/migrations/` in order
   - Creates tables: `files`, `signatures`, `trusted_keys`, `security_verifications`

3. **Configure environment:**
```powershell
$env:DEMO_MODE="false"
$env:SUPABASE_URL="https://your-project.supabase.co"
$env:SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"
```

4. **Restart server** - Files now persist to Supabase

### Storage Structure
```
Supabase Storage:
└── files/
    └── {user_id}/
        └── {file_id}/
            ├── original_file.txt
            ├── original_file.txt.sig
            └── public_key.pem

Supabase Tables:
- files: File metadata and hashes
- signatures: Signature history
- trusted_keys: Public key registry
- security_verifications: Security assessments
```

---

## Example Usage

### Upload and Sign a File

**Using the API:**
```bash
# Upload file
curl -X POST http://localhost:5000/api/files \
  -F "files=@myfile.txt"

# Response includes file_id
# Example: {"files": [{"file": {"id": "abc123", ...}}]}

# Download bundle
curl -O http://localhost:5000/api/files/abc123/download

# Extract and verify
unzip bundle.zip
openssl dgst -sha256 -verify public_key.pem \
  -signature myfile.txt.sig myfile.txt
```

**Using the Web UI:**
1. Open http://localhost:5000
2. Click "Upload File"
3. Select your file
4. Click "Download Bundle"
5. Share bundle with recipients

---

## Production Deployment

### Security Considerations
- **Use HTTPS** - Protect file uploads and downloads
- **Enable authentication** - Implement Supabase JWT validation
- **Key storage** - Consider HSM for private key storage
- **CORS policy** - Restrict to trusted origins only
- **Rate limiting** - Prevent abuse of signature generation
- **Audit logging** - Track all signature operations

### Deployment Options

**Docker:**
```dockerfile
FROM python:3.11
WORKDIR /app
COPY . .
RUN pip install -r demo_server/requirements.txt
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]
```

**Cloud Platforms:**
- Configure environment variables in dashboard
- Set `DEMO_MODE=false` for production
- Add `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
- Enable SSL/TLS certificates

**Reverse Proxy (nginx example):**
```nginx
server {
    listen 443 ssl;
    server_name checkuvity.example.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
    }
}
```

---

## Customization & Extensions

### Change Signature Algorithm
Edit `demo_server/server.py` to use different cryptography:

```python
# Current: RSA 2048-bit
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Alternative: ECDSA
from cryptography.hazmat.primitives.asymmetric import ec
private_key = ec.generate_private_key(ec.SECP256R1())

# Alternative: Ed25519
from cryptography.hazmat.primitives.asymmetric import ed25519
private_key = ed25519.Ed25519PrivateKey.generate()
```

### Add Custom Metadata
Extend signature metadata in `demo_server/server.py`:

```python
file_record = {
    "id": file_id,
    "signature": signature_hex,
    "custom_field": "your_value",  # Add here
    # ... existing fields
}
```

### Custom Storage Backend
Implement interface compatible with `SupabaseFileManager`:

```python
class MyStorageManager:
    def upload_file(self, file_path, user_id): ...
    def download_file(self, file_id): ...
    def list_files(self, user_id): ...
```

### Webhook Integration
Add webhooks to notify external systems when files are signed:

```python
# In demo_server/server.py after signing
requests.post("https://your-webhook.com/signed", json={
    "file_id": file_id,
    "signature": signature_hex,
    "timestamp": datetime.now().isoformat()
})
```

### Custom UI
Modify frontend in `frontend/src/` or build your own using the API.

---

## Summary

**Checkuvity in 3 Sentences:**
1. You upload files → Checkuvity generates cryptographic signatures
2. You download bundles → Contains everything needed for verification
3. Recipients verify → Using standard tools like OpenSSL (outside Checkuvity)

**What Checkuvity IS:**
- ✅ Signature generation service
- ✅ Key management system
- ✅ Bundle distribution platform
- ✅ Version tracking system

**What Checkuvity is NOT:**
- ❌ Not a file verification tool (recipients verify)
- ❌ Not a certificate authority (self-signed keys)
- ❌ Not a malware scanner
- ❌ Not a file hosting service (signatures only)

---

## License

MIT. Attribution is appreciated but not required. Use this as a foundation for your own file signing service.
