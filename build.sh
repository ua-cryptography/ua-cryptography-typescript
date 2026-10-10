#!/usr/bin/env bash
# Builds build/ua-signature.html, installing the dependencies on the first run.
# `./build.sh --watch` rebuilds on every change.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 22 or later is needed: https://nodejs.org/" >&2
  exit 1
fi
major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$major" -lt 22 ]; then
  echo "Node.js 22 or later is needed (found $(node -v))." >&2
  exit 1
fi

if [ ! -d node_modules ]; then
  npm ci
fi

node build.mjs "$@"
echo "Open $(pwd)/build/ua-signature.html in a browser."
