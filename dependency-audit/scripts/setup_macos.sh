#!/usr/bin/env bash

set -euo pipefail

MODE="${1:---check}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TOOL_CACHE="${DEPENDENCY_AUDIT_TOOL_CACHE:-${HOME}/Library/Caches/dependency-audit}"
VENV_DIR="${TOOL_CACHE}/python"
MANAGED_PYTHON="${VENV_DIR}/bin/python3"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This setup script supports macOS only." >&2
  exit 2
fi

pdf_ready() {
  local interpreter="$1"
  [[ -x "${interpreter}" ]] && "${interpreter}" -c 'import reportlab' >/dev/null 2>&1
}

if pdf_ready "${MANAGED_PYTHON}"; then
  echo "PDF support is ready: ${MANAGED_PYTHON}"
  exit 0
fi

if command -v python3 >/dev/null 2>&1 && python3 -c 'import reportlab' >/dev/null 2>&1; then
  echo "PDF support is ready: $(command -v python3)"
  exit 0
fi

if [[ "${MODE}" == "--check" ]]; then
  echo "PDF support is not configured. Run this script with --install after reviewing the changes." >&2
  exit 1
fi

if [[ "${MODE}" != "--install" ]]; then
  echo "Usage: setup_macos.sh [--check|--install]" >&2
  exit 2
fi

if command -v python3 >/dev/null 2>&1; then
  SYSTEM_PYTHON="$(command -v python3)"
elif command -v brew >/dev/null 2>&1; then
  echo "Python 3 was not found. Installing it with Homebrew..."
  brew install python
  SYSTEM_PYTHON="$(command -v python3)"
else
  echo "Python 3 and Homebrew were not found." >&2
  echo "Install Python 3 from https://www.python.org/downloads/macos/ or install Homebrew, then rerun this script." >&2
  exit 3
fi

mkdir -p "${TOOL_CACHE}"
if [[ ! -x "${MANAGED_PYTHON}" ]]; then
  "${SYSTEM_PYTHON}" -m venv "${VENV_DIR}"
fi

"${MANAGED_PYTHON}" -m pip install --disable-pip-version-check -r "${SKILL_DIR}/requirements.txt"
"${MANAGED_PYTHON}" -c 'import reportlab; print("PDF support installed with reportlab " + reportlab.Version)'
