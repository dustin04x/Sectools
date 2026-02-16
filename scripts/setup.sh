#!/bin/bash

# SecTools setup script (browser-only)

set -e

echo "Setting up SecTools..."

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js not found. Install Node.js 18+."
  exit 1
fi

echo "Node: $(node -v)"

if command -v py >/dev/null 2>&1; then
  PY_CMD="py"
elif command -v python3 >/dev/null 2>&1; then
  PY_CMD="python3"
elif command -v python >/dev/null 2>&1; then
  PY_CMD="python"
else
  echo "Python 3.11+ not found."
  exit 1
fi

echo "Python command: $PY_CMD"

echo "Installing frontend dependencies..."
npm install

echo "Installing backend dependencies..."
cd python_backend
$PY_CMD -m pip install -r requirements.txt
cd ..

echo ""
echo "Setup complete."
echo "Start backend: cd python_backend && $PY_CMD main.py"
echo "Start frontend: npm run dev"
