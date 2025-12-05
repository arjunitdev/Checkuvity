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
