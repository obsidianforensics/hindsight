#!/usr/bin/env sh
set -e

# Install
if [ "$1" = "-u" ] || [ "$1" = "--update" ]; then
  npm update --include=dev
elif [ "$1" != "--no-http" ]; then
  npm install
fi
export PATH="$PATH:$PWD/node_modules/.bin"

# Build
vite build node_modules/sqlite-view --outDir "$(pwd)/pyhindsight/static/web_modules"
rm pyhindsight/static/web_modules/sqlite-view.umd.cjs
