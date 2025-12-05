# Checkuvity

Checkuvity is a full-stack reference implementation of an authenticated file-signature verification service. It demonstrates how to ingest text files, sign them using asymmetric crypto, track versions, and run AI-assisted security checks while optionally backing storage with Supabase.

---

## Why this project exists

Traditional file scanning pipelines either:

- blindly trust signatures, or  
- analyze content without any tamper evidence.

Checkuvity brings both together:

1. **Hash + RSA signature** gives tamper detection.
2. **Version history** lets you revert to a known good artifact when signatures go bad.
3. **Security agent service** (pluggable) runs higher-level heuristics or AI analysis.
4. **Supabase integration** is optional—flip `DEMO_MODE=true` to run entirely in-memory.

---

## High-level architecture

```
frontend/          React + Vite client (upload wizard, status views)
demo_server/       Flask API server (file + signature lifecycle)
security_agent_service/
                   Optional AI/security orchestration service
supabase/          Database schema + migrations (optional)
```

- **Flask API (`demo_server/server.py`)** exposes `/api/files`, `/api/verify-security`, `/api/trusted-keys`, etc. It can run completely in demo mode without Supabase.
- **Security agent service** (in `security_agent_service/`) provides hooks for threat intel, signature verification, and reporting.
- **Supabase adapter** (in `build_scripts/` and `security_agent_service/tools/`) provides persistent storage when enabled.
- **Frontend** is a Vite-powered React app that consumes the Flask API.

---

## Key features

- Upload text files, store raw content + signatures + metadata.
- Automatically create RSA key pairs (or ingest trusted keys).
- Maintain version history with reversible updates.
- Download "bundle" ZIP containing original file, signature, public key.
- Run AI-driven file risk assessments (when security agent is available).
- Works offline via in-memory demo mode or online with Supabase.

---

## Running locally

### 1. Python backend
```powershell
cd demo_server
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
set DEMO_MODE=true               # skip Supabase
set FLASK_APP=server.py
flask run --host=0.0.0.0 --port=5000
```

By default the server logs that it's in demo mode and keeps state in memory. If you want Supabase persistence instead, set the variables shown below before starting.

### 2. React frontend
```powershell
cd frontend
npm install
npm run dev
```

The dev server proxies API calls to `http://localhost:5000`.

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

## API overview

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/files` | `POST` | Upload new file (text body + signature metadata) |
| `/api/files` | `GET` | List files belonging to the authenticated user |
| `/api/files/<file_id>` | `GET` | Get metadata + signatures for one file |
| `/api/files/<file_id>` | `DELETE` | Remove file from Supabase and storage |
| `/api/files/<file_id>/download` | `GET` | Download ZIP bundle with file/public key/signature |
| `/api/files/<file_id>/sign` | `PUT` | Update signature |
| `/api/files/<file_id>/versions` | `GET` | List version history |
| `/api/files/<file_id>/revert` | `POST` | Revert to specific version ID |
| `/api/verify-security/<file_id>` | `GET` | Trigger AI security verification |
| `/api/security-status/<file_id>` | `GET` | Fetch latest security verdict |
| `/api/trusted-keys` | `GET / POST / DELETE` | Manage trusted public keys |

Authentication defaults to a simple demo mode (`DEFAULT_DEMO_USER_ID`) but the code has hooks for Supabase JWT verification—check `validate_auth_header()`.

---

## Security agent service

When you want richer analysis, start the security agent service:

```powershell
cd security_agent_service
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

The Flask server lazily imports it; if unavailable, the API falls back gracefully with `503` responses for agent-only endpoints.

---

## Supabase integration

To enable real persistence:

1. Set `DEMO_MODE=false`.
2. Export `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`.
3. Apply migrations from `supabase/migrations/` (use the SQL in order).
4. Launch the Flask app—uploads/signatures now save to Supabase storage and tables.

The helper scripts in `build_scripts/` and `setup_supabase.py` automate schema creation if you want to bootstrap programmatically.

---

## Tests

- Python tests (API + security) live under the repo root (`test_*.py`). Run with `pytest`.
- Frontend tests (if added) run via `npm test`.
- CI samples exist for GitHub Actions and GitLab in `ci/`.

---

## Production deployment notes

- Put Flask behind a reverse proxy (nginx, Caddy, etc.) and lock down CORS.
- Move key material off disk into an HSM; scripts under `hsm/` give a starting point.
- Rotate Supabase service-role keys regularly.
- For Vercel/Netlify deployments, configure environment variables in the platform dashboard.

---

## Extending the system

- Swap out RSA for ECDSA or Ed25519 by editing `demo_server/server.py`.
- Integrate a different storage backend by implementing a new `SupabaseFileManager`-like class.
- Add more AI agents in `security_agent_service/agents/` and wire flows in `workflows/`.
- Hook the frontend to your own API base by adjusting `frontend/src/main.tsx`.

---

## License

MIT. Attribution is appreciated but not required. Use this as a boilerplate for your own signature verification workflows.
