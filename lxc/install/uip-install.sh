#!/usr/bin/env bash

# Copyright (c) 2026 waytoabv
# Author: waytoabv
# License: MIT
# Source: https://github.com/waytoabv/uip-rs

# Läuft IM Container, gestartet von ct/uip.sh über die Engine. Alles, was hier
# an Ausgabe erscheint, geht durch msg_info/msg_ok; $STD schluckt die
# Ausgabe der Befehle, solange der Verbose-Modus aus ist.

source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

# Woher der Quellcode kommt. Überschreibbar, damit ein Fork oder ein Branch
# ohne Änderung an diesem Skript installiert werden kann.
UIP_REPO_URL="${UIP_REPO_URL:-https://github.com/waytoabv/uip-rs.git}"
UIP_BRANCH="${UIP_BRANCH:-main}"
SRC_DIR=/opt/uip-src

msg_info "Installing Dependencies"
$STD apt install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  git \
  gnupg \
  ca-certificates
msg_ok "Installed Dependencies"

PG_VERSION="17" setup_postgresql

# TimescaleDB kommt nicht aus PGDG, sondern aus dem Repo von Timescale — also
# von Hand, nach setup_postgresql und vor dem Anlegen der Datenbank: das
# CREATE EXTENSION dort schlägt sonst fehl, und timescaledb-tune muss die
# shared_preload_libraries gesetzt haben, bevor die Erweiterung lädt.
msg_info "Setup TimescaleDB"
curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey |
  gpg --dearmor -o /usr/share/keyrings/timescaledb.gpg
cat <<EOF >/etc/apt/sources.list.d/timescaledb.list
deb [signed-by=/usr/share/keyrings/timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/debian/ $(get_os_info codename) main
EOF
$STD apt update
$STD apt install -y timescaledb-2-postgresql-17
$STD timescaledb-tune --quiet --yes
$STD systemctl restart postgresql
msg_ok "Setup TimescaleDB"

# Legt Rolle, Datenbank und Erweiterung an, würfelt das Passwort und schreibt
# es nach ~/uip.creds.
PG_DB_NAME="uip" PG_DB_USER="uip" PG_DB_EXTENSIONS="timescaledb" setup_postgresql_db

NODE_VERSION="22" setup_nodejs
# minimal: gebaut wird hier nur, clippy und rustfmt fehlen niemandem im
# Container. rust-toolchain.toml im Repo bestimmt die tatsächliche Version.
RUST_TOOLCHAIN="stable" RUST_PROFILE="minimal" setup_rust

msg_info "Building ${APPLICATION} (Patience)"
$STD git clone --branch "$UIP_BRANCH" "$UIP_REPO_URL" "$SRC_DIR"
# Das Frontend zuerst: rust-embed backt ui/dist/ in das Binary ein. Andersherum
# landete ein leeres oder veraltetes dist/ in der Auslieferung.
cd "${SRC_DIR}/ui" || exit
$STD npm ci
$STD npm run build
cd "$SRC_DIR" || exit
$STD cargo build --release -p uip
install -m 755 "${SRC_DIR}/target/release/uip" /usr/local/bin/uip
msg_ok "Built ${APPLICATION}"

msg_info "Creating Service"
id -u uip >/dev/null 2>&1 ||
  useradd --system --home /var/lib/uip --create-home --shell /usr/sbin/nologin uip
mkdir -p /etc/uip /var/lib/uip/geoip
cat <<EOF >/etc/uip/uip.env
UIP_DB_URL=postgres://${PG_DB_USER}:${PG_DB_PASS}@127.0.0.1/${PG_DB_NAME}
UIP_HTTP_ADDR=0.0.0.0:8080
UIP_SYSLOG_ADDR=0.0.0.0:514
UIP_WAN_IFACES=ppp0
UIP_GEOIP_DIR=/var/lib/uip/geoip
#UIP_ABUSEIPDB_KEY=
#UIP_MAXMIND_ACCOUNT_ID=${MAXMIND_ACCOUNT_ID:-}
#UIP_MAXMIND_LICENSE_KEY=${MAXMIND_LICENSE_KEY:-}
TZ=$(cat /etc/timezone 2>/dev/null || echo Etc/UTC)
EOF
chmod 600 /etc/uip/uip.env
chown -R uip:uip /var/lib/uip
install -m 644 "${SRC_DIR}/lxc/systemd/uip.service" /etc/systemd/system/uip.service
systemctl enable -q --now uip
msg_ok "Created Service"

# GeoIP holt die Anwendung selbst (crates/uip-enrich/src/maxmind.rs), nicht
# mehr geoipupdate über einen systemd-Timer. Damit lassen sich die Zugangsdaten
# auch nachträglich im Einstellungs-Dialog setzen — wer sie beim Installieren
# noch nicht hatte, war vorher ausgesperrt.
if [[ -n "${MAXMIND_ACCOUNT_ID:-}" && -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
  msg_info "Setup GeoIP"
  sed -i "s|^#UIP_MAXMIND_ACCOUNT_ID=.*|UIP_MAXMIND_ACCOUNT_ID=${MAXMIND_ACCOUNT_ID}|" /etc/uip/uip.env
  sed -i "s|^#UIP_MAXMIND_LICENSE_KEY=.*|UIP_MAXMIND_LICENSE_KEY=${MAXMIND_LICENSE_KEY}|" /etc/uip/uip.env
  $STD systemctl restart uip
  msg_ok "Setup GeoIP"
else
  msg_warn "No MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY given — country and ASN stay empty. Add them later under Settings; the databases are fetched within the hour."
fi

motd_ssh
customize
cleanup_lxc
