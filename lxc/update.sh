#!/usr/bin/env bash
# Läuft IM Container: aktualisiert Quellcode, baut neu, tauscht Binary. Migrationen laufen beim Start.
set -euo pipefail
SRC_DIR=/opt/uip-src
git -C "${SRC_DIR}" pull -q
(cd "${SRC_DIR}/ui" && npm ci --silent && npm run build --silent)
(cd "${SRC_DIR}" && "$HOME/.cargo/bin/cargo" build --release -p uip)
systemctl stop uip
install -m 755 "${SRC_DIR}/target/release/uip" /usr/local/bin/uip
systemctl start uip
echo "uip aktualisiert: $(git -C "${SRC_DIR}" rev-parse --short HEAD)"
