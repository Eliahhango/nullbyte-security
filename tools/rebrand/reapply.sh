#!/usr/bin/env bash
# Re-apply the nullbyte rebrand after an upgrade overwrites the binary.
# Usage: reapply.sh [path-to-binary]   (default: ~/.nullbyte/bin/nullbyte)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-$HOME/.nullbyte/bin/nullbyte}"

[ -f "$TARGET" ] || { echo "no binary at $TARGET"; exit 1; }

if grep -aq "NullByte" "$TARGET" && ! grep -aq "OpenCode" "$TARGET"; then
  echo "[+] $TARGET already rebranded. Nothing to do."
  exit 0
fi

STOCK="$HERE/nullbyte.stock"
# keep a pristine vanilla copy for safety
if [ ! -f "$STOCK" ]; then
  cp "$TARGET" "$STOCK"
  echo "[+] saved stock copy -> $STOCK"
fi

TMP="$(mktemp "$(dirname "$TARGET")/.nullbyte.new.XXXX")"
chmod +x "$TMP"
python3 "$HERE/rebrand.py" "$TARGET" "$TMP"

# rename-over-inode: safe even if the binary is currently running
mv -f "$TMP" "$TARGET"
chmod +x "$TARGET"
mkdir -p "$HOME/.local/bin"
ln -sf "$TARGET" "$HOME/.local/bin/nullbyte"
echo "[+] rebranded $TARGET  (run: nullbyte)"
