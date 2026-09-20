#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_DIR="$SCRIPT_DIR/release"
mkdir -p "$RELEASE_DIR"

cd "$SCRIPT_DIR"
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$RELEASE_DIR/securebox-darwin-arm64" .
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o "$RELEASE_DIR/securebox-darwin-amd64" .
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$RELEASE_DIR/securebox-linux-arm64" .
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o "$RELEASE_DIR/securebox-linux-amd64" .
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o "$RELEASE_DIR/securebox-windows-amd64.exe" .
