#!/usr/bin/env bash
# Läuft auf dem PROXMOX-HOST: bash -c "$(wget -qLO - https://raw.githubusercontent.com/waytoabv/uip-rs/main/lxc/proxmox-lxc.sh)"
set -euo pipefail

CTID="${CTID:-$(pvesh get /cluster/nextid)}"
HOSTNAME="${HOSTNAME_CT:-uip}"
STORAGE="${STORAGE:-local-lvm}"
DISK_GB="${DISK_GB:-10}"
MEMORY="${MEMORY:-2048}"
CORES="${CORES:-2}"
BRIDGE="${BRIDGE:-vmbr0}"
RAW_BASE="${UIP_RAW_BASE:-https://raw.githubusercontent.com/waytoabv/uip-rs/main}"

TEMPLATE=$(pveam available --section system | awk '/debian-13-standard/ {print $2}' | sort -V | tail -1)
[ -n "$TEMPLATE" ] || { echo "Kein Debian-13-Template gefunden (pveam update ausführen)"; exit 1; }
pveam list local | grep -q "$TEMPLATE" || pveam download local "$TEMPLATE"

echo "==> Erzeuge LXC ${CTID} (${HOSTNAME})"
pct create "$CTID" "local:vztmpl/${TEMPLATE}" \
  --hostname "$HOSTNAME" --cores "$CORES" --memory "$MEMORY" \
  --rootfs "${STORAGE}:${DISK_GB}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
  --features nesting=1 --unprivileged 1 --onboot 1
pct start "$CTID"
sleep 5

echo "==> Installiere uip im Container"
pct exec "$CTID" -- bash -c "curl -fsSL ${RAW_BASE}/lxc/install.sh -o /root/install.sh && bash /root/install.sh"

IP=$(pct exec "$CTID" -- hostname -I | awk '{print $1}')
echo "==> Fertig. UI: http://${IP}:8080 — Gateway-Syslog auf ${IP}:514 richten."
