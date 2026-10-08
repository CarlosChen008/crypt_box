#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pip install --upgrade pyinstaller

python3 -m PyInstaller --noconfirm --onefile --windowed --name Cryptobox \
  --workpath build/pyinstaller --distpath dist \
  --add-data "cryptobox/data/common_passwords.txt:cryptobox/data" \
  run_gui.py

echo "Built dist/Cryptobox.app"
