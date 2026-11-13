#!/usr/bin/env bash
# Install lambda-tools from a pinned git commit into user space.
#
#   ./install.sh [--ref REF] [--execute]   install REF (default HEAD); dry-run unless --execute
#   ./install.sh --status                  show what is installed
#   ./install.sh --uninstall [--execute]   remove what this script installed
#
# Each commit gets its own directory and virtualenv under
# ${XDG_DATA_HOME:-~/.local/share}/lambda-tools/install/<commit>; a `current`
# link is repointed only after a successful install, so a failed install
# leaves the previous one working.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/lambda-tools/install"
BIN_DIR="${LAMBDA_TOOLS_BIN_DIR:-$HOME/.local/bin}"
BIN_LINK="$BIN_DIR/lambda-tools"
LINK_TARGET="$PREFIX/current/venv/bin/lambda-tools"

die() { echo "error: $*" >&2; exit 2; }
say() { echo "$*" >&2; }

[ "$(id -u)" -ne 0 ] || die "do not run as root; lambda-tools installs into your home directory"

ACTION=install REF=HEAD EXECUTE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:?--ref needs a value}"; shift 2 ;;
    --execute|--apply) EXECUTE=1; shift ;;
    --status) ACTION=status; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

find_python() {
  for p in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$p" >/dev/null 2>&1 &&
       "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      command -v "$p"; return 0
    fi
  done
  die "Python 3.11 or newer is required"
}

ours() { [ -L "$BIN_LINK" ] && [ "$(readlink "$BIN_LINK")" = "$LINK_TARGET" ]; }

status() {
  if [ -L "$PREFIX/current" ]; then
    installed="$(cat "$PREFIX/current/COMMIT" 2>/dev/null || echo unknown)"
    echo "installed commit: $installed"
    head="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo none)"
    [ "$installed" = "$head" ] && echo "matches repository HEAD" || echo "repository HEAD is $head"
  else
    echo "not installed"
  fi
  if ours; then echo "command: $BIN_LINK"; elif [ -e "$BIN_LINK" ]; then echo "warning: $BIN_LINK exists but was not installed by this script"; fi
  case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "note: $BIN_DIR is not on PATH" ;; esac
}

install() {
  commit="$(git -C "$REPO" rev-parse --verify "$REF^{commit}" 2>/dev/null)" || die "unknown git ref: $REF (commit first; installs never use the working tree)"
  dest="$PREFIX/$commit"
  py="$(find_python)"
  if [ -e "$BIN_LINK" ] && ! ours; then die "$BIN_LINK exists and was not installed by this script; remove it first"; fi
  if [ "$EXECUTE" -eq 0 ]; then
    say "[DRY-RUN] Would install commit $commit from $REPO"
    say "[DRY-RUN]   source:  git archive $commit -> $dest/src"
    say "[DRY-RUN]   venv:    $py -m venv $dest/venv"
    say "[DRY-RUN]   current: $PREFIX/current -> $commit"
    say "[DRY-RUN]   command: $BIN_LINK -> $LINK_TARGET"
    say "Pass --execute to install."
    return
  fi
  mkdir -p "$PREFIX" "$BIN_DIR"
  if [ -f "$dest/COMMIT" ]; then
    say "[EXECUTE] Commit $commit is already installed; repointing current"
  else
    # Venvs cannot be moved (scripts embed absolute interpreter paths), so build
    # in place; COMMIT is written last and marks the install complete.
    rm -rf "$dest"
    mkdir -p "$dest/src"
    git -C "$REPO" archive "$commit" | tar -x -C "$dest/src"
    "$py" -m venv "$dest/venv"
    "$dest/venv/bin/python" -m pip install --quiet --disable-pip-version-check "$dest/src" >&2
    echo "$commit" > "$dest/COMMIT"
    say "[EXECUTE] Installed commit $commit into $dest"
  fi
  # Atomic link swaps (mv onto a directory symlink would move into it on macOS).
  ln -sfn "$commit" "$PREFIX/.current.tmp"
  "$py" -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$PREFIX/.current.tmp" "$PREFIX/current"
  ln -sfn "$LINK_TARGET" "$BIN_DIR/.lambda-tools.tmp"
  "$py" -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$BIN_DIR/.lambda-tools.tmp" "$BIN_LINK"
  say "[EXECUTE] $BIN_LINK -> commit $commit"
  status
}

uninstall() {
  prefix_word="[DRY-RUN] Would remove"
  [ "$EXECUTE" -eq 1 ] && prefix_word="[EXECUTE] Removing"
  if ours; then
    say "$prefix_word $BIN_LINK"
    [ "$EXECUTE" -eq 1 ] && rm -f "$BIN_LINK"
  elif [ -e "$BIN_LINK" ]; then
    say "Leaving $BIN_LINK: it was not installed by this script"
  fi
  if [ -d "$PREFIX" ]; then
    for dir in "$PREFIX"/*/; do
      dir="${dir%/}"
      name="$(basename "$dir")"
      # Only directories this script created: named by a commit, with a matching COMMIT file.
      # Incomplete installs (a commit-named dir with no COMMIT file) are ours too.
      if [ ! -L "$dir" ] && { { [ -f "$dir/COMMIT" ] && [ "$(cat "$dir/COMMIT")" = "$name" ]; } ||
         { [ ! -e "$dir/COMMIT" ] && [[ "$name" =~ ^[0-9a-f]{40}$ ]] && [ -d "$dir/src" ]; }; }; then
        say "$prefix_word $dir"
        [ "$EXECUTE" -eq 1 ] && rm -rf "$dir"
      fi
    done
    for link in "$PREFIX/current" "$PREFIX/.current.tmp"; do
      if [ -L "$link" ]; then
        say "$prefix_word $link"
        [ "$EXECUTE" -eq 1 ] && rm -f "$link"
      fi
    done
    [ "$EXECUTE" -eq 1 ] && rmdir "$PREFIX" 2>/dev/null || true
  fi
  [ "$EXECUTE" -eq 0 ] && say "Pass --execute to uninstall."
  return 0
}

"$ACTION"
