# SecTools Quick Start (Browser-Only)

## Prerequisites

- Node.js 18+
- Python 3.11+

## Install

```bash
npm install
cd python_backend
py -m pip install -r requirements.txt
cd ..
```

If `py` is not available, use `python3` instead.

### Windows (recommended)

Run:

```cmd
scripts\setup-windows.cmd
```

## Run

Terminal 1:

```bash
scripts\run-backend.cmd
```

Terminal 2:

```bash
npm run dev
```

Open `http://localhost:3000`.

## Build

```bash
npm run build
```

## Notes

- This project is now web-only.
- Electron and Tauri runtimes are removed.
