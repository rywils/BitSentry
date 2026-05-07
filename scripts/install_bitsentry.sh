#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
BITSENTRY_PY="${REPO_ROOT}/bitsentry.py"
VENV_DIR="${REPO_ROOT}/.venv"
ENV_FILE="${REPO_ROOT}/.env"
ENV_EXAMPLE="${REPO_ROOT}/.env.example"

OS_NAME="$(uname -s)"

if [[ -z "${INSTALL_BIN_DIR:-}" ]]; then
  if [[ "${OS_NAME}" == "Darwin" ]]; then
    INSTALL_BIN_DIR="/usr/local/bin"
  elif [[ "${OS_NAME}" == "Linux" ]]; then
    if [[ ":${PATH}:" == *":/usr/local/bin:"* ]]; then
      INSTALL_BIN_DIR="/usr/local/bin"
    else
      INSTALL_BIN_DIR="/usr/bin"
    fi
  else
    INSTALL_BIN_DIR="/usr/local/bin"
  fi
fi

INSTALL_BIN_PATH="${INSTALL_BIN_DIR}/bitsentry"

SHELL_NAME="$(basename "${SHELL:-}")"
RC_FILE=""
if [[ "${SHELL_NAME}" == "zsh" ]]; then
  RC_FILE="${HOME}/.zshrc"
elif [[ "${SHELL_NAME}" == "bash" ]]; then
  if [[ "${OS_NAME}" == "Darwin" ]]; then
    RC_FILE="${HOME}/.bash_profile"
  else
    RC_FILE="${HOME}/.bashrc"
  fi
fi

echo "[*] BitSentry installer"
echo "[*] Repo root: ${REPO_ROOT}"

if [[ ! -f "${BITSENTRY_PY}" ]]; then
  echo "[!] Could not find bitsentry.py at ${BITSENTRY_PY}" >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  if [[ -f "${ENV_EXAMPLE}" ]]; then
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    echo "[+] Created .env from .env.example"
  else
    cat > "${ENV_FILE}" <<'EOF'
EOF
    echo "[+] Created .env template"
  fi
else
  echo "[=] .env already exists"
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  python3 -m venv "${VENV_DIR}"
  echo "[+] Created virtual environment at ${VENV_DIR}"
else
  echo "[=] Virtual environment already exists"
fi

VENV_PY="${VENV_DIR}/bin/python"
if [[ ! -x "${VENV_PY}" ]]; then
  if [[ -x "${VENV_DIR}/bin/python3" ]]; then
    VENV_PY="${VENV_DIR}/bin/python3"
    echo "[=] Using ${VENV_PY}"
  else
    echo "[!] Virtualenv interpreter missing; recreating ${VENV_DIR}"
    rm -rf "${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    VENV_PY="${VENV_DIR}/bin/python"
    if [[ ! -x "${VENV_PY}" && -x "${VENV_DIR}/bin/python3" ]]; then
      VENV_PY="${VENV_DIR}/bin/python3"
    fi
  fi
fi

if [[ ! -x "${VENV_PY}" ]]; then
  echo "[!] Virtualenv python missing after recreation: ${VENV_PY}" >&2
  exit 1
fi

if [[ -f "${REPO_ROOT}/requirements.txt" ]]; then
  "${VENV_PY}" -m pip install --upgrade pip
  "${VENV_PY}" -m pip install -r "${REPO_ROOT}/requirements.txt"
  echo "[+] Installed requirements.txt into venv"
else
  echo "[!] requirements.txt not found in ${REPO_ROOT}" >&2
  exit 1
fi

echo ""
echo "[*] ASN database (local status, no network):"
"${VENV_PY}" -c "
import os
import sys
sys.path.insert(0, '${REPO_ROOT}/bitprobe')
from scanner.asn_db_updater import ASN_DB_PATH, describe_asn_db_local_status

status = describe_asn_db_local_status()
tty = sys.stdout.isatty() and not os.environ.get('NO_COLOR', '').strip()
print(f'    File: {ASN_DB_PATH}')
if 'missing' in status or 'outdated' in status:
    if tty:
        print(f'    Status: \\033[1;31m{status}\\033[0m')
        print('    \\033[33mRun: bitsentry update-db\\033[0m')
    else:
        print(f'    Status: {status}')
        print('    Run: bitsentry update-db')
else:
    if tty:
        print(f'    Status: \\033[1;32m{status}\\033[0m')
    else:
        print(f'    Status: {status}')
"

LAUNCHER_TMP="$(mktemp)"
cat > "${LAUNCHER_TMP}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

BITSENTRY_REPO="${REPO_ROOT}"
VENV_PY="\${BITSENTRY_REPO}/.venv/bin/python"
BITSENTRY_PY="\${BITSENTRY_REPO}/bitsentry.py"
ENV_FILE="\${BITSENTRY_REPO}/.env"

if [[ ! -x "\${VENV_PY}" && -x "\${BITSENTRY_REPO}/.venv/bin/python3" ]]; then
  VENV_PY="\${BITSENTRY_REPO}/.venv/bin/python3"
fi

if [[ -f "\${ENV_FILE}" ]]; then
  set -a
  source "\${ENV_FILE}"
  set +a
fi

exec "\${VENV_PY}" "\${BITSENTRY_PY}" "\$@"
EOF
chmod +x "${LAUNCHER_TMP}"

mkdir -p "${INSTALL_BIN_DIR}" 2>/dev/null || true
if install -m 0755 "${LAUNCHER_TMP}" "${INSTALL_BIN_PATH}" 2>/dev/null; then
  echo "[+] Installed launcher to ${INSTALL_BIN_PATH}"
else
  echo "[!] Could not write ${INSTALL_BIN_PATH} without elevated permissions."
  echo "[*] Retrying with sudo..."
  sudo mkdir -p "${INSTALL_BIN_DIR}"
  sudo install -m 0755 "${LAUNCHER_TMP}" "${INSTALL_BIN_PATH}"
  echo "[+] Installed launcher to ${INSTALL_BIN_PATH} (sudo)"
fi
rm -f "${LAUNCHER_TMP}"

if [[ "${OS_NAME}" == "Darwin" ]] && [[ "${INSTALL_BIN_PATH}" == *"/sbin/"* ]]; then
  MAC_BIN="/usr/local/bin/bitsentry"
  if [[ ! -f "${MAC_BIN}" ]] || [[ "${INSTALL_BIN_PATH}" -nt "${MAC_BIN}" ]] 2>/dev/null; then
    if install -m 0755 "${INSTALL_BIN_PATH}" "${MAC_BIN}" 2>/dev/null; then
      echo "[+] Also installed launcher to ${MAC_BIN} (macOS PATH compatibility)"
    else
      echo "[*] Could not copy to ${MAC_BIN} without elevated permissions; retrying with sudo..."
      sudo install -m 0755 "${INSTALL_BIN_PATH}" "${MAC_BIN}"
      echo "[+] Also installed launcher to ${MAC_BIN} (sudo)"
    fi
  fi
fi

if ! command -v bitsentry >/dev/null 2>&1; then
  ALT_BIN=""
  if [[ "${OS_NAME}" == "Linux" ]]; then
    if [[ "${INSTALL_BIN_DIR}" != "/usr/local/bin" ]]; then
      ALT_BIN="/usr/local/bin/bitsentry"
    fi
  elif [[ "${OS_NAME}" == "Darwin" ]]; then
    if [[ "${INSTALL_BIN_DIR}" != "/usr/local/bin" ]]; then
      ALT_BIN="/usr/local/bin/bitsentry"
    fi
  fi

  if [[ -n "${ALT_BIN}" ]]; then
    if install -m 0755 "${INSTALL_BIN_PATH}" "${ALT_BIN}" 2>/dev/null; then
      echo "[+] Copied launcher to ${ALT_BIN}"
    else
      echo "[*] Could not copy to ${ALT_BIN} without elevated permissions."
      echo "[*] Retrying with sudo..."
      sudo install -m 0755 "${INSTALL_BIN_PATH}" "${ALT_BIN}"
      echo "[+] Copied launcher to ${ALT_BIN} (sudo)"
    fi
    INSTALL_BIN_PATH="${ALT_BIN}"
  fi

  if [[ -n "${RC_FILE}" ]]; then
    if [[ ":${PATH}:" != *":${INSTALL_BIN_DIR}:"* ]]; then
      if ! grep -F "export PATH=\"${INSTALL_BIN_DIR}:\$PATH\"" "${RC_FILE}" >/dev/null 2>&1; then
        {
          echo ""
          echo "export PATH=\"${INSTALL_BIN_DIR}:\$PATH\""
        } >> "${RC_FILE}"
        echo "[+] Added ${INSTALL_BIN_DIR} to PATH in ${RC_FILE}"
      else
        echo "[=] PATH export already present in ${RC_FILE}"
      fi
    fi
  elif [[ "${SHELL_NAME}" == "fish" ]]; then
    echo "[*] fish shell detected."
    echo "[*] Add once (universal): set -U fish_user_paths ${INSTALL_BIN_DIR} \$fish_user_paths"
  else
    echo "[*] Unknown shell '${SHELL_NAME:-unknown}'."
    echo "[*] Ensure ${INSTALL_BIN_DIR} is in your PATH."
  fi
fi

echo ""
echo "[✓] Install complete"
echo "[*] Try: bitsentry scan example.com"
if [[ -n "${RC_FILE}" ]]; then
  echo "[*] If command is still not found: source ${RC_FILE} && hash -r"
elif [[ "${SHELL_NAME}" == "fish" ]]; then
  echo "[*] If command is still not found: run the fish_user_paths command above, then open a new shell."
else
  echo "[*] If command is still not found: refresh your shell and ensure ${INSTALL_BIN_DIR} is on PATH."
fi
