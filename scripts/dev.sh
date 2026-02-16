#!/bin/bash

# SecTools development startup (browser-only)

set -e

if command -v py >/dev/null 2>&1; then
  PY_CMD="py"
elif command -v python3 >/dev/null 2>&1; then
  PY_CMD="python3"
elif command -v python >/dev/null 2>&1; then
  PY_CMD="python"
else
  echo "Python not found."
  exit 1
fi

cleanup() {
  echo ""
  echo "Stopping servers..."
  kill $PYTHON_PID $NODE_PID 2>/dev/null || true
  exit 0
}

trap cleanup INT TERM

echo "Starting backend..."
cd python_backend
$PY_CMD main.py &
PYTHON_PID=$!
cd ..

echo "Starting frontend..."
npm run dev &
NODE_PID=$!

echo "Frontend: http://localhost:3000"
echo "Backend:  http://127.0.0.1:8000"
echo "Press Ctrl+C to stop."

wait
