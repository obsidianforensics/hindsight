#!/usr/bin/env sh
set -e

# Install
if [ "$1" = "-u" ] || [ "$1" = "--update" ]; then
  npm update --dev
elif [ "$1" != "--no-http" ]; then
  npm install
fi
export PATH="$PATH:$PWD/node_modules/.bin"

# Bundle
node --input-type=module --eval "
import { install } from 'esinstall';

install(
  [
    'sqlite-view'
  ],
  {
    dest: './pyhindsight/static/web_modules',
    polyfillNode: true,
  }
);
"
rm ./pyhindsight/static/web_modules/import-map.json

# Optimize
bundle="pyhindsight/static/web_modules/sqlite-view.js"
terser $bundle --output $bundle --compress --mangle
