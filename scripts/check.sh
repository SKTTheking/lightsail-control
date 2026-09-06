#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash -n scripts/prepare.sh scripts/setup.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
node --check control/static/app.js
bash scripts/prepare.sh
cd .build/komari
go test ./lightsail
go build -trimpath -o ../lightsail-control ./lightsail
