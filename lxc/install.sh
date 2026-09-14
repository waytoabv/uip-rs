#!/usr/bin/env bash
# uip installer v0 — läuft IM Debian-13-LXC als root.
set -euo pipefail

REPO_URL="${UIP_REPO_URL:-https://github.com/waytoabv/uip-rs.git}"
BRANCH="${UIP_BRANCH:-main}"
DB_NAME=uip
DB_USER=uip
SRC_DIR=/opt/uip-src

msg() { echo -e "\e[1;32m==>\e[0m $*"; }

msg "Pakete"
apt-get update -qq
apt-get install -y -qq curl git build-essential pkg-config libssl-dev \
  postgresql-common gnupg ca-certificates geoipupdate >/dev/null

msg "PostgreSQL 17 + TimescaleDB Repos"
/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y >/dev/null
curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey \
  | gpg --dearmor -o /usr/share/keyrings/timescaledb.gpg
echo "deb [signed-by=/usr/share/keyrings/timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/debian/ $(. /etc/os-release; echo "$VERSION_CODENAME") main" \
  > /etc/apt/sources.list.d/timescaledb.list
apt-get update -qq
apt-get install -y -qq postgresql-17 timescaledb-2-postgresql-17 >/dev/null
timescaledb-tune --quiet --yes >/dev/null
systemctl restart postgresql

msg "Datenbank"
DB_PASS=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}'"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 \
  || sudo -u postgres createdb -O "${DB_USER}" -E UTF8 "${DB_NAME}"
sudo -u postgres psql -d "${DB_NAME}" -c "CREATE EXTENSION IF NOT EXISTS timescaledb"

msg "Rust-Toolchain"
command -v cargo >/dev/null || {
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
  source "$HOME/.cargo/env"
}

msg "Node (Frontend-Build)"
command -v node >/dev/null || {
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
  apt-get install -y -qq nodejs >/dev/null
}

msg "Quellcode + Build"
if [ -d "${SRC_DIR}/.git" ]; then
  git -C "${SRC_DIR}" fetch -q && git -C "${SRC_DIR}" checkout -q "${BRANCH}" && git -C "${SRC_DIR}" pull -q
else
  git clone -q --branch "${BRANCH}" "${REPO_URL}" "${SRC_DIR}"
fi
(cd "${SRC_DIR}/ui" && npm ci --silent && npm run build --silent)
(cd "${SRC_DIR}" && "$HOME/.cargo/bin/cargo" build --release -p uip)
install -m 755 "${SRC_DIR}/target/release/uip" /usr/local/bin/uip

msg "Service"
id -u uip >/dev/null 2>&1 || useradd --system --home /var/lib/uip --create-home --shell /usr/sbin/nologin uip
mkdir -p /etc/uip
if [ ! -f /etc/uip/uip.env ]; then
  cat > /etc/uip/uip.env <<EOF
UIP_DB_URL=postgres://${DB_USER}:${DB_PASS}@127.0.0.1/${DB_NAME}
UIP_HTTP_ADDR=0.0.0.0:8080
UIP_SYSLOG_ADDR=0.0.0.0:514
UIP_WAN_IFACES=ppp0
UIP_GEOIP_DIR=/var/lib/uip/geoip
#UIP_ABUSEIPDB_KEY=
TZ=$(cat /etc/timezone 2>/dev/null || echo UTC)
EOF
  chmod 600 /etc/uip/uip.env
fi
install -m 644 "${SRC_DIR}/lxc/systemd/uip.service" /etc/systemd/system/uip.service
systemctl daemon-reload
systemctl enable --now uip

msg "GeoIP"
mkdir -p /var/lib/uip/geoip
chown -R uip:uip /var/lib/uip
if [ -n "${MAXMIND_ACCOUNT_ID:-}" ] && [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
  cat > /etc/uip/GeoIP.conf <<EOF
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs GeoLite2-City GeoLite2-ASN
EOF
  chmod 600 /etc/uip/GeoIP.conf
  install -m 644 "${SRC_DIR}/lxc/systemd/uip-geoip.service" /etc/systemd/system/
  install -m 644 "${SRC_DIR}/lxc/systemd/uip-geoip.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now uip-geoip.timer
  # Einmal sofort, damit nicht bis zum ersten Timer-Lauf gewartet wird.
  systemctl start uip-geoip.service || msg "GeoIP-Download fehlgeschlagen — Timer versucht es erneut"
else
  msg "Ohne MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY bleibt GeoIP leer."
  msg "Später nachrüstbar: /etc/uip/GeoIP.conf anlegen und uip-geoip.timer aktivieren."
fi

msg "Fertig: http://$(hostname -I | awk '{print $1}'):8080 — Syslog auf UDP 514"
