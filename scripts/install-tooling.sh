#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install-tooling.sh [--gnupg] [--bin-dir path]

Install optional GnuPG into ~/.local/bin for Passeport's Pluggable Scdaemon backend.

Options:
  --gnupg        Install/refresh only gnupg.
  --bin-dir PATH Override the destination directory (default: ~/.local/bin).
  --help         Show this help text.

Passeport provides its own age, minisign, and GNU-free gpg commands. This
script only installs GnuPG for the optional Pluggable Scdaemon backend.
It uses Homebrew for installation.
EOF
}

install_gnupg() {
  ensure_toolbox

  if ! brew list --formula gnupg >/dev/null 2>&1; then
    brew install gnupg
  fi

  local prefix
  prefix="$(brew --prefix gnupg)"
  local tools=(
    gpg
    gpg-agent
    gpgconf
    gpg-connect-agent
    gpg-wks-server
    gpg-wks-client
    gpgsm
  )
  for tool in "${tools[@]}"; do
    link_tool "${prefix}/bin/${tool}"
  done
}

ensure_toolbox() {
  if [[ -z "${HOMEBREW_PREFIX:-}" ]]; then
    if ! command -v brew >/dev/null 2>&1; then
      echo "Homebrew is required but not found. Install it first: https://brew.sh/" >&2
      exit 1
    fi
  fi
}

link_tool() {
  local source="$1"
  local dst="${BIN_DIR}/$(basename "$source")"

  if [[ ! -x "${source}" ]]; then
    echo "warning: missing executable ${source}, skipping" >&2
    return 0
  fi

  mkdir -p "${BIN_DIR}"

  if [[ -L "${dst}" || -e "${dst}" ]]; then
    if [[ -L "${dst}" ]] && [[ "$(readlink "${dst}")" == "${source}" ]]; then
      echo "link already present: ${dst} -> ${source}"
      return 0
    fi
    local backup="${dst}.passeport-backup"
    rm -f "${backup}" || true
    mv "${dst}" "${backup}"
    echo "replaced existing ${dst} with ${source} (backup: ${backup})"
  fi

  ln -s "${source}" "${dst}"
  echo "linked ${dst} -> ${source}"
}

main() {
  if [[ "${#}" -eq 0 ]]; then
    INSTALL_GNUPG=true
  fi

  while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
      --gnupg)
        INSTALL_GNUPG=true
        shift
        ;;
      --bin-dir)
        if [[ "${#}" -lt 2 ]]; then
          echo "missing value for --bin-dir" >&2
          exit 1
        fi
        BIN_DIR="${2}"
        shift 2
        ;;
      --help)
        usage
        exit 0
        ;;
      *)
        echo "unknown flag: ${1}" >&2
        usage
        exit 1
        ;;
    esac
  done

  if [[ "${INSTALL_GNUPG:-false}" == "false" ]]; then
    echo "nothing requested, use --gnupg" >&2
    exit 1
  fi

  if [[ "${INSTALL_GNUPG:-false}" == "true" ]]; then
    install_gnupg
  fi

  if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo "note: add ${BIN_DIR} to PATH (for example, in ~/.zshrc):"
    echo "  export PATH=\"${BIN_DIR}:\$PATH\""
  fi
}

BIN_DIR="${HOME}/.local/bin"
INSTALL_GNUPG=false
main "$@"
