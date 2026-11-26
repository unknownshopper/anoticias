#!/usr/bin/env bash
# Deploy: trae los últimos cambios de origin/main y reinicia el servicio.
# Uso remoto:  ssh t800@<ip-este-equipo> 'cd ~/Desktop/SISTA/monitor_noticias && ./deploy.sh'
set -e
cd "$(dirname "$0")"

echo "== git pull =="
git pull --ff-only

echo "== unit file =="
# el ExecStart vive en /etc/systemd/system — si el repo trae una
# versión distinta (flags nuevos/quitados) hay que copiarla y recargar
if ! cmp -s monitor.service /etc/systemd/system/monitor.service; then
  sudo cp monitor.service /etc/systemd/system/monitor.service
  sudo systemctl daemon-reload
  echo "unit actualizado"
else
  echo "unit sin cambios"
fi

echo "== restart monitor.service =="
sudo systemctl restart monitor.service
sleep 1
systemctl is-active monitor.service && echo "OK — servicio arriba"
