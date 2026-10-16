#!/usr/bin/env bash
# Link this checkout into a NullByte install and install dev dependencies.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${NULLBYTE_CONFIG:-$HOME/.config/nullbyte}"

if [ ! -d "$CONFIG_DIR" ]; then
  echo "error: NullByte config dir not found: $CONFIG_DIR" >&2
  echo "       set NULLBYTE_CONFIG=/path/to/.config/nullbyte and retry" >&2
  exit 1
fi

echo "→ repo:   $REPO_DIR"
echo "→ config: $CONFIG_DIR"

mkdir -p "$CONFIG_DIR/plugin"

link() {
  local src="$1" dest="$2"
  if [ -e "$dest" ] && [ ! -L "$dest" ]; then
    local backup="$dest.bak.$(date +%Y%m%d%H%M%S)"
    echo "  backing up existing $(basename "$dest") → $(basename "$backup")"
    mv "$dest" "$backup"
  fi
  rm -f "$dest"
  ln -s "$src" "$dest"
  echo "  linked $(basename "$dest") → $src"
}

link "$REPO_DIR/security-lib" "$CONFIG_DIR/security-lib"
link "$REPO_DIR/plugin/nullbyte-security.ts" "$CONFIG_DIR/plugin/nullbyte-security.ts"

echo "→ installing dependencies"
cd "$REPO_DIR"
if command -v npm >/dev/null 2>&1; then
  npm install --silent --no-audit --no-fund
else
  echo "  npm not found — install @opencode-ai/plugin manually for type checking" >&2
fi

# The host CLI resolves @opencode-ai/plugin from its own tree; make sure it exists there too.
if [ ! -d "$CONFIG_DIR/node_modules/@opencode-ai/plugin" ]; then
  echo "  note: $CONFIG_DIR/node_modules/@opencode-ai/plugin is missing."
  echo "        the CLI normally provides it; if tools fail to load, install it there."
fi

echo
echo "done. verify with:"
echo "  cd $REPO_DIR && npm test"
echo "  nullbyte run \"call sec_scope with action=check target=example.com\""
