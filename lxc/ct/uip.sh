#!/usr/bin/env bash

# Copyright (c) 2026 waytoabv
# Author: waytoabv
# License: MIT
# Source: https://github.com/waytoabv/uip-rs

# Der Einstiegspunkt in der Bauart der community-scripts: auf dem Proxmox-Host
# aufgerufen legt er den Container an, im Container aufgerufen aktualisiert er
# ihn. TUI, Speicher-Auswahl, "Advanced Settings", Fehler-Dialog und
# Wiederholung kommen vollständig aus der Engine — hier steht nur, was uip
# davon unterscheidet.
#
# Die Engine kennt zwei getrennte Wurzeln (siehe core/build.func): sich selbst
# und das Repo, aus dem ct/ und install/ stammen. Ohne COMMUNITY_SCRIPTS_URL
# suchte sie install/uip-install.sh im ProxmoxVE-Repo und fände dort nichts.
# Der Zeiger geht auf lxc/, weil ct/ und install/ hier darunter liegen und die
# Engine beide Ordner nebeneinander erwartet.
COMMUNITY_SCRIPTS_URL="${COMMUNITY_SCRIPTS_URL:-https://raw.githubusercontent.com/waytoabv/uip-rs/main/lxc}"
export COMMUNITY_SCRIPTS_URL

_cs_core_url="${COMMUNITY_SCRIPTS_CORE_URL:-https://raw.githubusercontent.com/community-scripts/core/main}"
_cs_boot="${COMMUNITY_SCRIPTS_CORE_DIR:-}/core/build.func"
# shellcheck disable=SC1090 # beide Quellen stehen erst zur Laufzeit fest
source "$_cs_boot" 2>/dev/null || source <(curl -fsSL "${_cs_core_url}/core/build.func")

APP="uip"
var_tags="${var_tags:-network;monitoring;syslog}"
var_cpu="${var_cpu:-2}"
# Der Release-Build der Rust-Workspace ist der Spitzenverbrauch, nicht der
# Betrieb: unter 3 GB fängt der Linker an zu swappen.
var_ram="${var_ram:-3072}"
# Platte: Quellbaum plus cargo-Zielverzeichnis sind rund 4 GB, der Rest ist
# TimescaleDB. Bei viel Syslog-Aufkommen lohnt es sich, hier mehr zu geben und
# die Aufbewahrung in migrations/0001_init.sql anzuschauen.
var_disk="${var_disk:-12}"
var_os="${var_os:-debian}"
var_version="${var_version:-13}"
var_unprivileged="${var_unprivileged:-1}"

header_info "$APP"
variables
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources

  if [[ ! -d /opt/uip-src ]]; then
    msg_error "No ${APP} Installation Found!"
    exit
  fi

  # Ein nicht-Login-Shell liest /etc/profile.d nicht, und dort hat setup_rust
  # den Pfad hinterlegt. Ohne das findet die Aktualisierung ihr eigenes cargo
  # nicht wieder.
  export PATH="${HOME}/.cargo/bin:${PATH}"

  # Zuerst anhalten, dann tauschen: die alte Instanz darf nicht mehr schreiben,
  # wenn die neue ihre Migrationen fährt.
  msg_info "Stopping Service"
  systemctl stop uip
  msg_ok "Stopped Service"

  msg_info "Updating ${APP} (Patience)"
  cd /opt/uip-src || exit
  $STD git pull --ff-only
  # Das Frontend zuerst: rust-embed backt ui/dist/ in das Binary ein, ein
  # späterer Frontend-Build käme zu spät.
  cd /opt/uip-src/ui || exit
  $STD npm ci
  $STD npm run build
  cd /opt/uip-src || exit
  $STD cargo build --release -p uip
  install -m 755 /opt/uip-src/target/release/uip /usr/local/bin/uip
  msg_ok "Updated ${APP}"

  # Migrationen laufen beim Start, vor dem HTTP-Listener. Der erste Start nach
  # einer Aktualisierung darf deshalb länger brauchen, ohne dass etwas hängt.
  msg_info "Starting Service"
  systemctl start uip
  msg_ok "Started Service"

  msg_ok "Updated successfully!"
  exit
}

start
build_container
description

msg_ok "Completed successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW}Access it using the following URL:${CL}"
echo -e "${GATEWAY}${BGN}http://${IP}:8080${CL}"
echo -e "${INFO}${YW}Point your UniFi gateway's remote syslog at ${IP}, UDP 514.${CL}"
