#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
commit=bf6b45ec3abfc56bba5e9223650a47a72f665371
mkdir -p .build
if [ ! -d .build/komari/.git ]; then
  git clone --depth 1 --branch 1.4.3 https://github.com/komari-monitor/komari.git .build/komari
fi
test "$(git -C .build/komari rev-parse HEAD)" = "$commit"
mkdir -p .build/komari/lightsail
cp -R control/. .build/komari/lightsail/
cp agent/agent.py .build/komari/lightsail/agent.py
cp dependencies/go.mod dependencies/go.sum .build/komari/
