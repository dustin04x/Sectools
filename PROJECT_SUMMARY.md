# Project Summary

SecTools is now a browser-only application.

## Current Architecture

- Next.js frontend served on `http://localhost:3000`
- FastAPI backend served on `http://127.0.0.1:8000`
- Frontend communicates with backend over HTTP

## Included Functional Areas

- Port scanning and service mapping
- Crypto helper (cipher/hash/HMAC/JWT/password/RSA keygen)
- IP intelligence (geolocation/reverse DNS/WHOIS)
- Reverse shell payload generation

## Removed

- Electron runtime
- Tauri/Rust runtime
- Desktop IPC bridge logic

## Run Flow

1. Start backend: `cd python_backend && py main.py`
2. Start frontend: `npm run dev`
3. Open browser at `http://localhost:3000`
