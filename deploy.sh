#!/usr/bin/env bash
# Deploy: trae los últimos cambios de origin/main y reinicia el servicio.
# Uso remoto:  ssh t800@<ip-este-equipo> 'cd ~/Desktop/SISTA/monitor_noticias && ./deploy.sh'
set -e
cd "$(dirname "$0")"

echo "== git pull =="
git pull --ff-only

echo "== restart monitor.service =="
sudo systemctl restart monitor.service
sleep 1
systemctl is-active monitor.service && echo "OK — servicio arriba"
