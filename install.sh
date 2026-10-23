#!/usr/bin/env bash
# One-command installer and repair tool for the NullByte security layer.
#
# The first phase inspects the checkout and the installed files, then repairs
# anything missing or broken. Safe to re-run: conflicting files are backed up,
# never deleted, and existing configuration/engagement data is left alone.
set -euo pipefail

CONFIG_DIR="${NULLBYTE_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/nullbyte}"
RUN_DEPS=1
RUN_TESTS=1
CHECK_ONLY=0
UNINSTALL=0
PURGE=0
ISSUES=0
FIXED=0
NEED_DEPS=0
NEED_MCP_DEPS=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]
       curl -fsSL https://github.com/Eliahhango/nullbyte-security/raw/main/install.sh | bash

Inspects, installs or repairs the NullByte security layer. Re-running is safe.

Options:
  --check      Inspect only, change nothing, exit 1 if issues are found
  --no-deps    Skip dependency installation
  --no-test    Skip the test suite
  --uninstall  Remove installed links and the managed checkout; keep config and project data
  --purge      Uninstall and also remove the NullByte config directory
  -h, --help   Show this help
EOF
}

UI_TTY=0
[ -t 1 ] && UI_TTY=1

if [ "$UI_TTY" -eq 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  C_GRAY=$'\033[90m'
  C_BLUE=$'\033[34m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'
  C_MAGENTA=$'\033[35m'
  C_DIM=$'\033[2m'
  C_RESET=$'\033[0m'
else
  C_GRAY="" C_BLUE="" C_GREEN="" C_YELLOW="" C_RED="" C_MAGENTA="" C_DIM="" C_RESET=""
fi

case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
  *UTF-8*|*utf8*|*UTF8*|*utf-8*) UI_UNICODE=1 ;;
  *) UI_UNICODE=0 ;;
esac
if [ "$UI_UNICODE" -eq 1 ]; then
  BAR_START="┌"; BAR="│"; BAR_END="└"
  SYM_INFO="●"; SYM_SUCCESS="◆"; SYM_STEP="◇"; SYM_WARN="▲"; SYM_ERROR="■"; SYM_OK="✓"
  SPIN_FRAMES=("◒" "◐" "◓" "◑")
else
  BAR_START="T"; BAR="|"; BAR_END="—"
  SYM_INFO="•"; SYM_SUCCESS="*"; SYM_STEP="o"; SYM_WARN="!"; SYM_ERROR="x"; SYM_OK="+"
  SPIN_FRAMES=("•" "o" "O" "0")
fi

ui_intro() { printf '%s  %s\n' "${C_GRAY}${BAR_START}${C_RESET}" "$*"; }
ui_outro() { printf '%s\n%s  %s\n\n' "${C_GRAY}${BAR}${C_RESET}" "${C_GRAY}${BAR_END}${C_RESET}" "$*"; }
ui_line() {
  local symbol="$1" color="$2"
  shift 2
  printf '%s\n%s  %s\n' "${C_GRAY}${BAR}${C_RESET}" "${color}${symbol}${C_RESET}" "$*"
}
ui_info() { ui_line "$SYM_INFO" "$C_BLUE" "$*"; }
ui_success() { ui_line "$SYM_SUCCESS" "$C_GREEN" "$*"; }
ui_warn() { ui_line "$SYM_WARN" "$C_YELLOW" "$*"; }
ui_error() { ui_line "$SYM_ERROR" "$C_RED" "$*" >&2; }
ui_detail() { printf '%s  %s%s%s\n' "${C_GRAY}${BAR}${C_RESET}" "$C_DIM" "$*" "$C_RESET"; }
ui_ok() { printf '%s  %s%s%s %s\n' "${C_GRAY}${BAR}${C_RESET}" "$C_GREEN" "$SYM_OK" "$C_RESET" "$*"; }

SPIN_PID=""
ui_spin_start() {
  local msg="$1" i=0 frame dots
  SPIN_PID=""
  if [ "$UI_TTY" -eq 1 ]; then
    printf '%s\n' "${C_GRAY}${BAR}${C_RESET}"
    (
      while :; do
        frame="${SPIN_FRAMES[$((i % 4))]}"
        case $((i % 4)) in
          0) dots="" ;;
          1) dots="." ;;
          2) dots=".." ;;
          *) dots="..." ;;
        esac
        printf '\r\033[2K%s  %s%s' "${C_MAGENTA}${frame}${C_RESET}" "$msg" "$dots"
        i=$((i + 1))
        sleep 0.08
      done
    ) &
    SPIN_PID=$!
  else
    printf '%s  %s...\n' "${C_MAGENTA}${SPIN_FRAMES[0]}${C_RESET}" "$msg"
  fi
}
ui_spin_stop() {
  local msg="$1" status="${2:-0}"
  if [ -n "$SPIN_PID" ]; then
    kill "$SPIN_PID" 2>/dev/null || true
    wait "$SPIN_PID" 2>/dev/null || true
    SPIN_PID=""
    [ "$UI_TTY" -eq 1 ] && printf '\r\033[2K'
  fi
  if [ "$status" -eq 0 ]; then
    printf '%s  %s\n' "${C_GREEN}${SYM_STEP}${C_RESET}" "$msg"
  else
    printf '%s  %s\n' "${C_RED}${SYM_ERROR}${C_RESET}" "$msg"
  fi
}
ui_spin_abort() {
  if [ -n "$SPIN_PID" ]; then
    kill "$SPIN_PID" 2>/dev/null || true
    wait "$SPIN_PID" 2>/dev/null || true
    SPIN_PID=""
    [ "$UI_TTY" -eq 1 ] && printf '\r\033[2K'
  fi
}
trap ui_spin_abort EXIT INT TERM

run_spin() {
  local start_msg="$1" done_msg="$2" fail_msg="$3"
  shift 3
  local log rc
  log="$(mktemp "${TMPDIR:-/tmp}/nullbyte-install.XXXXXX")"
  ui_spin_start "$start_msg"
  if "$@" >"$log" 2>&1; then
    ui_spin_stop "$done_msg"
    rc=0
  else
    rc=$?
    ui_spin_stop "$fail_msg" 1
    cat "$log" >&2
  fi
  rm -f "$log"
  return "$rc"
}

note() { ui_detail "$*"; }
ok() { ui_ok "$*"; }
fixed() { ui_success "$*"; FIXED=$((FIXED + 1)); }
issue() { ui_warn "$*"; ISSUES=$((ISSUES + 1)); }
drain_stdin() {
  if [ -z "${BASH_SOURCE[0]:-}" ]; then
    cat >/dev/null 2>&1 || true
  fi
}

for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1; RUN_DEPS=0; RUN_TESTS=0 ;;
    --no-deps) RUN_DEPS=0 ;;
    --no-test|--skip-tests) RUN_TESTS=0 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) UNINSTALL=1; PURGE=1 ;;
    -h|--help) usage; drain_stdin; exit 0 ;;
    *)
      echo "error: unknown option: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ui_intro "NullByte Security"

# ---- locate or bootstrap the checkout -----------------------------------
REPO_URL="${NULLBYTE_SECURITY_REPO:-https://github.com/Eliahhango/nullbyte-security.git}"
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
FROM_CURL=1

if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
  case "$SCRIPT_DIR" in
    /dev/fd/*|/proc/self/fd/*) ;;
    *)
      if [ -f "$SCRIPT_DIR/package.json" ] &&
         grep -q '"name"[[:space:]]*:[[:space:]]*"nullbyte-security"' "$SCRIPT_DIR/package.json"; then
        REPO_DIR="$SCRIPT_DIR"
        FROM_CURL=0
      fi
      ;;
  esac
fi

if [ "$FROM_CURL" -eq 1 ]; then
  if [ -n "${NULLBYTE_SECURITY_HOME:-}" ]; then
    REPO_DIR="$NULLBYTE_SECURITY_HOME"
  elif [ -d "$HOME/nullbyte-security/.git" ]; then
    REPO_DIR="$HOME/nullbyte-security"
  else
    REPO_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/nullbyte-security"
  fi
fi

bootstrap_repo() {
  if ! command -v git >/dev/null 2>&1; then
    echo "error: git is required for the curl installer" >&2
    echo "       install git, or clone the repo and run ./install.sh" >&2
    exit 1
  fi

  if [ -d "$REPO_DIR/.git" ]; then
    ui_spin_start "Updating existing checkout"
    if GIT_TERMINAL_PROMPT=0 git -C "$REPO_DIR" pull --ff-only --quiet; then
      ui_spin_stop "Checkout ready"
    else
      ui_spin_stop "Update skipped, using existing checkout"
      note "could not fast-forward; continuing with the existing checkout"
    fi
    note "$REPO_DIR"
    return 0
  fi

  if [ -e "$REPO_DIR" ] || [ -L "$REPO_DIR" ]; then
    if [ -d "$REPO_DIR" ] && [ -z "$(ls -A "$REPO_DIR" 2>/dev/null)" ]; then
      rmdir "$REPO_DIR"
    else
      local backup="$REPO_DIR.bak.$(date +%Y%m%d%H%M%S)"
      note "backing up existing $REPO_DIR → $(basename "$backup")"
      mv "$REPO_DIR" "$backup"
    fi
  fi

  mkdir -p "$(dirname "$REPO_DIR")"
  if ! run_spin "Cloning NullByte security" "Repository ready" "Could not clone repository" \
    env GIT_TERMINAL_PROMPT=0 git clone --depth 1 --quiet "$REPO_URL" "$REPO_DIR"; then
    ui_error "Could not clone $REPO_URL"
    note "check your network, or clone the repo and run ./install.sh"
    exit 1
  fi
  note "$REPO_DIR"
}

remove_installed_link() {
  local dest="$1" label="$2"
  if [ -L "$dest" ]; then
    rm -f -- "$dest"
    ui_success "$label removed"
  elif [ -e "$dest" ]; then
    ui_warn "$label is not a symlink; leaving it in place"
  else
    note "$label was not installed"
  fi
}

uninstall_layer() {
  ui_info "Uninstalling NullByte security"

  remove_installed_link "$CONFIG_DIR/plugin/nullbyte-security.ts" "security plugin"
  remove_installed_link "$CONFIG_DIR/security-lib" "security-lib"

  if [ -d "$CONFIG_DIR/plugin" ] && [ -z "$(ls -A "$CONFIG_DIR/plugin" 2>/dev/null)" ]; then
    rmdir "$CONFIG_DIR/plugin" 2>/dev/null || true
  fi

  if [ "$PURGE" -eq 1 ]; then
    if [ -e "$CONFIG_DIR" ] || [ -L "$CONFIG_DIR" ]; then
      rm -rf -- "$CONFIG_DIR"
      ui_success "Removed config: $CONFIG_DIR"
    else
      note "Config already absent: $CONFIG_DIR"
    fi
  else
    note "Config preserved: $CONFIG_DIR"
  fi

  if [ "$FROM_CURL" -eq 1 ]; then
    if [ -d "$REPO_DIR/.git" ] && [ -f "$REPO_DIR/package.json" ] &&
       grep -q '"name"[[:space:]]*:[[:space:]]*"nullbyte-security"' "$REPO_DIR/package.json"; then
      rm -rf -- "$REPO_DIR"
      ui_success "Removed managed checkout: $REPO_DIR"
    elif [ -e "$REPO_DIR" ] || [ -L "$REPO_DIR" ]; then
      ui_warn "Left unexpected path in place: $REPO_DIR"
    else
      note "No managed checkout at $REPO_DIR"
    fi
  else
    note "Local checkout preserved: $REPO_DIR"
  fi

  note "Project data under .nullbyte/security/ was not touched"
  note "The NullByte CLI itself is separate and was not removed"
  ui_outro "Done"
}

if [ "$UNINSTALL" -eq 1 ]; then
  uninstall_layer
  drain_stdin
  exit 0
fi

if [ "$FROM_CURL" -eq 1 ]; then
  if [ "$CHECK_ONLY" -eq 1 ] && [ ! -d "$REPO_DIR/.git" ]; then
    echo "error: no existing checkout at $REPO_DIR" >&2
    echo "       run the installer once without --check first" >&2
    exit 1
  fi
  if [ "$CHECK_ONLY" -eq 0 ]; then
    bootstrap_repo
  fi
fi

ui_info "Repository  $REPO_DIR"
ui_info "Config      $CONFIG_DIR"
[ "$CHECK_ONLY" -eq 1 ] && ui_info "Mode        check only (no changes)"

# ---- inspect the checkout ------------------------------------------------
ui_info "Inspecting installation"

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
  ui_error "This checkout is incomplete; re-clone the repository"
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  ui_error "Node.js not found; >= 22.6.0 is required"
  exit 1
fi

NODE_VERSION="$(node -p 'process.versions.node' 2>/dev/null || true)"
IFS=. read -r NODE_MAJOR NODE_MINOR _ <<< "${NODE_VERSION:-0.0.0}"
if [ "${NODE_MAJOR:-0}" -lt 22 ] || { [ "${NODE_MAJOR:-0}" -eq 22 ] && [ "${NODE_MINOR:-0}" -lt 6 ]; }; then
  ui_error "Node $NODE_VERSION found; >= 22.6.0 is required"
  note "the test runner uses --experimental-strip-types"
  exit 1
fi
ok "node $NODE_VERSION"

if ! command -v npm >/dev/null 2>&1; then
  if [ "$RUN_DEPS" -eq 1 ]; then
    ui_error "npm not found; install npm or rerun with --no-deps"
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
  ui_success "Inspection passed: installation healthy"
else
  ui_warn "Inspection found $ISSUES issue(s)"
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  drain_stdin
  if [ "$ISSUES" -eq 0 ]; then
    ui_outro "Done"
    exit 0
  fi
  note "run the installer without --check to repair the issues above"
  ui_outro "Done with issues"
  exit 1
fi

# ---- repair dependencies -------------------------------------------------
install_plugin_deps() { (cd "$REPO_DIR" && npm install --silent --no-audit --no-fund); }
install_mcp_deps() { (cd "$REPO_DIR/mcp/stitch" && npm install --silent --no-audit --no-fund); }

if [ "$RUN_DEPS" -eq 1 ]; then
  if [ "$NEED_DEPS" -eq 1 ]; then
    dep_label="Installing plugin dependencies"
  else
    dep_label="Refreshing plugin dependencies"
  fi
  run_spin "$dep_label" "Plugin dependencies ready" "Plugin dependency install failed" install_plugin_deps
  if [ "$NEED_DEPS" -eq 1 ]; then
    FIXED=$((FIXED + 1))
    NEED_DEPS=0
  fi

  if [ -f "$REPO_DIR/mcp/stitch/package.json" ]; then
    if [ "$NEED_MCP_DEPS" -eq 1 ]; then
      mcp_label="Installing Stitch MCP dependencies"
    else
      mcp_label="Refreshing Stitch MCP dependencies"
    fi
    run_spin "$mcp_label" "Stitch MCP dependencies ready" "Stitch MCP dependency install failed" install_mcp_deps
    if [ "$NEED_MCP_DEPS" -eq 1 ]; then
      FIXED=$((FIXED + 1))
      NEED_MCP_DEPS=0
    fi
  fi
elif [ "$NEED_DEPS" -eq 1 ] || [ "$NEED_MCP_DEPS" -eq 1 ]; then
  note "dependency repair skipped (--no-deps); installation may be incomplete"
fi

# ---- tests ---------------------------------------------------------------
if [ "$RUN_TESTS" -eq 1 ]; then
  TEST_LOG="$(mktemp "${TMPDIR:-/tmp}/nullbyte-install.XXXXXX")"
  ui_spin_start "Running tests"
  if ! (cd "$REPO_DIR" && npm test --silent >"$TEST_LOG" 2>&1); then
    ui_spin_stop "Tests failed" 1
    cat "$TEST_LOG" >&2
    rm -f "$TEST_LOG"
    ui_error "Test suite failed; installation left in place for inspection"
    exit 1
  fi
  ui_spin_stop "Tests passed"
  TEST_SUMMARY="$(awk '/^ℹ (tests|pass|fail) / { printf "%s%s %s", sep, $2, $3; sep="  ·  " }' "$TEST_LOG")"
  [ -n "$TEST_SUMMARY" ] && note "$TEST_SUMMARY"
  rm -f "$TEST_LOG"
fi

# ---- verify the result ---------------------------------------------------
ui_info "Verifying installation"
for path in \
  "$CONFIG_DIR/security-lib" \
  "$CONFIG_DIR/plugin/nullbyte-security.ts"
do
  if [ ! -e "$path" ]; then
    ui_error "Missing $path"
    exit 1
  fi
done

if [ "$(readlink "$CONFIG_DIR/security-lib")" != "$REPO_DIR/security-lib" ]; then
  ui_error "security-lib still does not point at this checkout"
  exit 1
fi
if [ "$(readlink "$CONFIG_DIR/plugin/nullbyte-security.ts")" != "$REPO_DIR/plugin/nullbyte-security.ts" ]; then
  ui_error "plugin still does not point at this checkout"
  exit 1
fi
ui_success "Installation verified"

UNRESOLVED=$((ISSUES - FIXED))
note "Re-run ./install.sh anytime to inspect or repair"
note "Use ./install.sh --check for an inspection-only pass"
note "Config and engagement data are preserved"
note "Next: cd <project> && nullbyte run \"recon example.com\""
if [ "$UNRESOLVED" -le 0 ]; then
  ui_outro "Done"
else
  note "$UNRESOLVED unresolved issue(s); see the messages above"
  ui_outro "Done with issues"
fi
