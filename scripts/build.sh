#!/bin/bash

# SecTools production build script (browser-only)

set -e

echo "Building SecTools web app..."

VERSION=$(node -p "require('./package.json').version")
echo "Version: $VERSION"

echo "Cleaning previous build output..."
rm -rf dist/

echo "Building Next.js..."
npm run build

echo ""
echo "Build complete."
echo "Output: dist/"
