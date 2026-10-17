#!/usr/bin/env bash
# Scrub the ollama API key from any plaintext it may have leaked into:
#   - config files under ~/.config/nullbyte (except the 600 key file itself)
#   - the session store (~/.local/share/nullbyte/nullbyte.db: event.data/part.data)
# The key is read from ~/.config/nullbyte/ollama.key and never printed.
#
# Run AFTER closing all running nullbyte sessions for a full on-disk wipe
# (a live session keeps the WAL open and can re-append history).
set -uo pipefail

KEYFILE="${KEYFILE:-$HOME/.config/nullbyte/ollama.key}"
DB="${DB:-$HOME/.local/share/nullbyte/nullbyte.db}"

[ -f "$KEYFILE" ] || { echo "no key file at $KEYFILE"; exit 1; }
KEY="$(cat "$KEYFILE")"
[ -n "$KEY" ] || { echo "key file is empty"; exit 1; }

echo "[*] key: ${#KEY} bytes"

echo "[*] scanning config dir…"
found=0
while IFS= read -r -d '' f; do
  [ "$f" = "$KEYFILE" ] && continue
  if grep -aq -- "$KEY" "$f" 2>/dev/null; then
    sed -i "s|$KEY|[redacted]|g" "$f" 2>/dev/null && echo "    scrubbed $f" && found=$((found+1))
  fi
done < <(find "$HOME/.config/nullbyte" -type f -print0 2>/dev/null)
echo "    files scrubbed: $found"

if [ -f "$DB" ]; then
  echo "[*] scrubbing session db…"
  sqlite3 "$DB" "PRAGMA busy_timeout=20000;
    BEGIN IMMEDIATE;
    UPDATE event SET data=replace(data,'$KEY','[redacted]') WHERE data LIKE '%'||'$KEY'||'%' AND instr(data,'$KEY')>0;
    UPDATE part  SET data=replace(data,'$KEY','[redacted]') WHERE instr(data,'$KEY')>0;
    COMMIT;" 2>&1 | sed 's/^/    /'
  left=$(sqlite3 "$DB" "SELECT (SELECT count(*) FROM event WHERE instr(data,'$KEY')>0)+(SELECT count(*) FROM part WHERE instr(data,'$KEY')>0);")
  echo "    rows still holding the key: $left"

  if [ "${VACUUM:-0}" = "1" ]; then
    echo "[*] VACUUM (purging freed pages)…"
    sqlite3 "$DB" "PRAGMA busy_timeout=120000; VACUUM; PRAGMA wal_checkpoint(TRUNCATE);" 2>&1 | sed 's/^/    /'
    echo "    vacuum done"
  fi
fi

echo "[*] done. If the key was ever shared/committed anywhere, ROTATE it at ollama.com."
