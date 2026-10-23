#!/usr/bin/env bash
# One-command installer and repair tool for the NullByte security layer.
#
# The first phase inspects the checkout and the installed files, then repairs
# anything missing or broken. Safe to re-run: conflicting files are backed up,
# never deleted, and existing configuration/engagement data is left alone.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${NULLBYTE_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/nullbyte}"
RUN_DEPS=1
RUN_TESTS=1
CHECK_ONLY=0
ISSUES=0
FIXED=0
NEED_DEPS=0
NEED_MCP_DEPS=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Inspects, installs or repairs the NullByte security layer. Re-running is safe.

Options:
  --check      Inspect only, change nothing, exit 1 if issues are found
  --no-deps    Skip dependency installation
  --no-test    Skip the test suite
  -h, --help   Show this help
EOF
}

say() { printf '→ %s\n' "$*"; }
note() { printf '  %s\n' "$*"; }
ok() { printf '  ok   %s\n' "$*"; }
fixed() { printf '  fix  %s\n' "$*"; FIXED=$((FIXED + 1)); }
issue() { printf '  warn %s\n' "$*" >&2; ISSUES=$((ISSUES + 1)); }

for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1; RUN_DEPS=0; RUN_TESTS=0 ;;
    --no-deps) RUN_DEPS=0 ;;
    --no-test|--skip-tests) RUN_TESTS=0 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "error: unknown option: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

say "repo:   $REPO_DIR"
say "config: $CONFIG_DIR"
[ "$CHECK_ONLY" -eq 1 ] && say "mode:   check only (no changes)"

# ---- inspect the checkout ------------------------------------------------
say "inspecting installation"

SOURCE_BROKEN=0
for rel in \
  "package.json" \
  "plugin/nullbyte-security.ts" \
  "security-lib/tools/index.ts" \
  "security-lib/toolguard.ts" \
  "security-lib/config.ts"
do
  if [ -e "$REPO_DIR/$rel" ]; then
    ok "source: $rel"
  else
    issue "source is missing: $rel"
    SOURCE_BROKEN=1
  fi
done

if [ "$SOURCE_BROKEN" -eq 1 ]; then
  echo "error: this checkout is incomplete; re-clone the repository" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "error: node not found; Node.js >= 22.6.0 is required" >&2
  exit 1
fi

NODE_VERSION="$(node -p 'process.versions.node' 2>/dev/null || true)"
IFS=. read -r NODE_MAJOR NODE_MINOR _ <<< "${NODE_VERSION:-0.0.0}"
if [ "${NODE_MAJOR:-0}" -lt 22 ] || { [ "${NODE_MAJOR:-0}" -eq 22 ] && [ "${NODE_MINOR:-0}" -lt 6 ]; }; then
  echo "error: Node $NODE_VERSION found; >= 22.6.0 is required" >&2
  echo "       (the test runner uses --experimental-strip-types)" >&2
  exit 1
fi
ok "node $NODE_VERSION"

if ! command -v npm >/dev/null 2>&1; then
  if [ "$RUN_DEPS" -eq 1 ]; then
    echo "error: npm not found; install npm or rerun with --no-deps" >&2
    exit 1
  fi
  note "npm not found (dependency install skipped)"
fi

# ---- inspect and repair the config tree ---------------------------------
ensure_dir() {
  local dir="$1"
  if [ -L "$dir" ] && [ ! -e "$dir" ]; then
    note "removing dangling link $dir"
    rm -f "$dir"
  fi
  if [ -e "$dir" ] && [ ! -d "$dir" ]; then
    local backup="$dir.bak.$(date +%Y%m%d%H%M%S)"
    note "backing up non-directory $dir → $(basename "$backup")"
    mv "$dir" "$backup"
  fi
  mkdir -p "$dir"
}

inspect_dir() {
  local dir="$1" label="$2"
  if [ -L "$dir" ] && [ ! -e "$dir" ]; then
    issue "$label is a dangling symlink"
  elif [ -e "$dir" ] && [ ! -d "$dir" ]; then
    issue "$label is not a directory"
  elif [ ! -d "$dir" ]; then
    issue "$label is missing"
  else
    ok "$label exists"
    return 0
  fi
  [ "$CHECK_ONLY" -eq 1 ] && return 0
  ensure_dir "$dir"
  fixed "$label repaired"
}

repair_link() {
  local src="$1" dest="$2" label="$3"

  if [ -L "$dest" ] && [ -e "$dest" ] && [ "$(readlink "$dest")" = "$src" ]; then
    ok "$label is linked"
    return 0
  fi

  if [ -L "$dest" ] && [ ! -e "$dest" ]; then
    issue "$label is a broken symlink"
  elif [ -L "$dest" ]; then
    issue "$label points elsewhere: $(readlink "$dest")"
  elif [ -e "$dest" ]; then
    issue "$label is a regular file/directory"
  else
    issue "$label is missing"
  fi

  [ "$CHECK_ONLY" -eq 1 ] && return 0

  if [ -e "$dest" ] && [ ! -L "$dest" ]; then
    local backup="$dest.bak.$(date +%Y%m%d%H%M%S)"
    note "backing up existing $(basename "$dest") → $(basename "$backup")"
    mv "$dest" "$backup"
  fi
  rm -f "$dest"
  ln -s "$src" "$dest"
  fixed "$label linked to $src"
}

inspect_dir "$CONFIG_DIR" "config root"
inspect_dir "$CONFIG_DIR/plugin" "plugin directory"
repair_link "$REPO_DIR/security-lib" "$CONFIG_DIR/security-lib" "security-lib"
repair_link "$REPO_DIR/plugin/nullbyte-security.ts" "$CONFIG_DIR/plugin/nullbyte-security.ts" "security plugin"

# ---- inspect dependencies and the CLI -----------------------------------
if [ -d "$REPO_DIR/node_modules/@opencode-ai/plugin" ]; then
  ok "plugin dependencies present"
else
  issue "plugin dependencies missing"
  NEED_DEPS=1
fi

if [ -f "$REPO_DIR/mcp/stitch/package.json" ]; then
  if [ -d "$REPO_DIR/mcp/stitch/node_modules/@modelcontextprotocol/sdk" ] &&
     [ -d "$REPO_DIR/mcp/stitch/node_modules/@google/stitch-sdk" ]; then
    ok "Stitch MCP dependencies present"
  else
    issue "Stitch MCP dependencies missing"
    NEED_MCP_DEPS=1
  fi
fi

if CLI_PATH="$(command -v nullbyte 2>/dev/null)"; then
  ok "CLI: $CLI_PATH"
else
  note "CLI: nullbyte not found on PATH (install NullByte separately)"
fi

if [ "$ISSUES" -eq 0 ]; then
  say "inspection: installation healthy"
else
  say "inspection: $ISSUES issue(s) found"
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  if [ "$ISSUES" -eq 0 ]; then
    exit 0
  fi
  echo "check failed: run ./install.sh to repair the issues above" >&2
  exit 1
fi

# ---- repair dependencies -------------------------------------------------
if [ "$RUN_DEPS" -eq 1 ]; then
  if [ "$NEED_DEPS" -eq 1 ]; then
    say "repairing missing plugin dependencies"
  else
    say "refreshing plugin dependencies"
  fi
  (cd "$REPO_DIR" && npm install --silent --no-audit --no-fund)
  if [ "$NEED_DEPS" -eq 1 ]; then
    fixed "plugin dependencies installed"
    NEED_DEPS=0
  fi

  if [ -f "$REPO_DIR/mcp/stitch/package.json" ]; then
    if [ "$NEED_MCP_DEPS" -eq 1 ]; then
      say "repairing missing Stitch MCP dependencies"
    else
      say "refreshing Stitch MCP dependencies"
    fi
    (cd "$REPO_DIR/mcp/stitch" && npm install --silent --no-audit --no-fund)
    if [ "$NEED_MCP_DEPS" -eq 1 ]; then
      fixed "Stitch MCP dependencies installed"
      NEED_MCP_DEPS=0
    fi
  fi
elif [ "$NEED_DEPS" -eq 1 ] || [ "$NEED_MCP_DEPS" -eq 1 ]; then
  note "dependency repair skipped (--no-deps); installation may be incomplete"
fi

# ---- tests ---------------------------------------------------------------
if [ "$RUN_TESTS" -eq 1 ]; then
  say "running tests"
  TEST_LOG="$(mktemp "${TMPDIR:-/tmp}/nullbyte-install.XXXXXX")"
  if ! (cd "$REPO_DIR" && npm test --silent >"$TEST_LOG" 2>&1); then
    cat "$TEST_LOG" >&2
    rm -f "$TEST_LOG"
    echo "error: test suite failed; installation left in place for inspection" >&2
    exit 1
  fi
  tail -n 10 "$TEST_LOG"
  rm -f "$TEST_LOG"
fi

# ---- verify the result ---------------------------------------------------
say "verifying install"
for path in \
  "$CONFIG_DIR/security-lib" \
  "$CONFIG_DIR/plugin/nullbyte-security.ts"
do
  if [ ! -e "$path" ]; then
    echo "error: missing $path" >&2
    exit 1
  fi
done

if [ "$(readlink "$CONFIG_DIR/security-lib")" != "$REPO_DIR/security-lib" ]; then
  echo "error: security-lib still does not point at this checkout" >&2
  exit 1
fi
if [ "$(readlink "$CONFIG_DIR/plugin/nullbyte-security.ts")" != "$REPO_DIR/plugin/nullbyte-security.ts" ]; then
  echo "error: plugin still does not point at this checkout" >&2
  exit 1
fi

UNRESOLVED=$((ISSUES - FIXED))
echo
if [ "$UNRESOLVED" -le 0 ]; then
  echo "done. NullByte security layer installed."
else
  echo "done with $UNRESOLVED unresolved issue(s); see the messages above." >&2
fi
echo "  re-run ./install.sh anytime to inspect or repair"
echo "  use ./install.sh --check for an inspection-only pass"
echo "  config and engagement data are preserved"
echo "  next: cd <project> && nullbyte run \"recon example.com\""
