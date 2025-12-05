# Text File Signature Verification System

This project lets users upload text files and automatically produces a **signed baseline**:
`<file>`, `<file>.sig`, and `public_key.pem`. Downloads always contain the same triplet so
clients can verify signatures offline.

## What’s included

- **Frontend (`/frontend`)** – Vite + React SPA (builds to `/frontend/dist` for Flask to serve).
- **Demo server (`/demo_server/server.py`)** – Flask API that auto-generates RSA key pairs,
  signs uploads, persists metadata in Supabase, and streams bundles.
- **Verification service (`/verification_service`)** – REST service exposing verification,
  status, and human-readable diff/risk reports.
- **Supabase configuration (`/supabase`)** – schema and migrations (includes `public_key_pem`).

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate  # or source .venv/bin/activate
pip install -r requirements.txt
pip install -r demo_server/requirements.txt

# Frontend (React + Vite)
cd frontend
npm install
npm run build
```

Set the Supabase credentials (service-role key is required so the server can write bundles):

```
SUPABASE_URL=...
SUPABASE_SERVICE_ROLE_KEY=...
```

Run migrations (SQL editor or CLI):
```sql
-- supabase/schema.sql
-- supabase/migrations/* (ensure files.public_key_pem exists)
```

## Running the servers

```bash
# Demo API + web UI
python demo_server/server.py  # http://127.0.0.1:5000

# Standalone verification API
python verification_service/app.py  # http://127.0.0.1:6000
```

## Upload workflow

1. POST `/api/files` with a raw `.txt` file (via the UI or API).
2. The server:
   - hashes the file (`SHA-256`)
   - generates a fresh RSA key pair
   - signs the file (`PKCS#1 v1.5` / SHA-256)
   - stores the signature hex, `public_key.pem`, and hash metadata in Supabase.
3. The download bundle always contains:
   - the original text (`<name>.txt`)
   - the binary signature (`<name>.sig`)
   - the generated PEM (`public_key.pem`)

## Verification service endpoints (`http://127.0.0.1:6000`)

- `POST /api/verification/verify` – run the security agent and diff analysis.
- `GET /api/verification/status/<file_id>` – raw verification record from Supabase.
- `GET /api/verification/report/<file_id>` – summarized risk/diff report.
- `GET /api/verification/health` – health check.

## Directory layout (pruned)

```
/build_scripts          # Supabase client + helpers
/demo_server            # Auto-signing Flask API
/verification_service   # Independent verification REST API
/security_agent_service # Multi-agent security pipeline reused by both services
/supabase               # Schema & migrations
/frontend               # Vite + React SPA (run `npm run build` to create /frontend/dist)
```

## Notes

- The demo mode keeps everything in memory; Supabase is optional for local trials.
- The generated `private_key.pem` is not stored—if you need reproducible signatures,
  adapt the upload flow to accept user-supplied keys instead.
- `requirements.txt` includes `cryptography`, so make sure OpenSSL libraries are present.

## License

MIT License