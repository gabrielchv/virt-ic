#!/usr/bin/env bash
# Executa o POC de ponta a ponta: sobe o cenário, coleta um Traço, analisa.
set -euo pipefail
cd "$(dirname "$0")"

echo "== subindo o cenário =="
docker compose up -d --build --wait

echo
echo "== coletando o Traço (precisa de root para entrar nos namespaces) =="
sudo python3 poc/capture.py "$@"

echo
echo "== analisando =="
python3 poc/analyze.py --traco "traces/ultimo"
