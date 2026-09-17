# uip-rs

Complete native rewrite of [UniFi Insights Plus](https://github.com/jmasarweh/UniFi-Insights-Plus) —
real-time syslog analysis for UniFi gateways, rebuilt from scratch:

- **Rust** (tokio) — single binary: UDP syslog receiver, state-machine parsers (no regex),
  decoupled enrichment workers, axum REST API + SSE live stream
- **PostgreSQL + TimescaleDB** — hypertables, native compression and retention policies
- **SolidJS** frontend — fine-grained reactivity for the live log stream, no VDOM diffing
- **Proxmox LXC** deployment — classic community install script, systemd. No Docker.

## Install

On the Proxmox host — the same flow as any community script: a whiptail dialog
offering default or advanced settings, then the container, then the install:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/waytoabv/uip-rs/main/lxc/ct/uip.sh)"
```

`lxc/ct/uip.sh` and `lxc/install/uip-install.sh` follow the
[community-scripts](https://github.com/community-scripts/ProxmoxVE) layout and
run on their engine (`community-scripts/core`); `COMMUNITY_SCRIPTS_URL` points
the engine at this repository so it finds `install/uip-install.sh` here rather
than in the upstream one. Everything that is not specific to uip — storage
selection, resource prompts, verbose mode, the error dialog and its retry —
comes from the engine.

To update, run the same script **inside** the container; it detects where it is
and takes the update path (stop, pull, rebuild frontend then binary, swap,
start). Migrations run at startup, so the first start after an update takes
longer than usual.

The container defaults to 2 cores, 3 GB RAM and 12 GB disk: the release build
is the peak, not the running service. The generated database password is
written to `~/uip.creds` and to `/etc/uip/uip.env`.

`MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` in the environment enable GeoIP
at install time, but they are no longer required then: the application fetches
the GeoLite2 databases itself over MaxMind's direct-download API and checks
daily for a newer build, so the credentials can just as well be entered under
Settings afterwards. Without them country and ASN stay empty and everything
else works.

## Coming from the fork

`scripts/import-abuseipdb.sh` carries the AbuseIPDB results over. Those answers
cost quota rather than money, but a thousand lookups a day goes quickly, and
what the old instance already asked need not be asked again.

```bash
scripts/import-abuseipdb.sh --from-dsn postgres://unifi@old-host/unifi_logs
```

Where the old database sits in Docker with no exposed port, the script's
`--help` prints the psql command to dump it to CSV instead, and takes that with
`--from-csv`. `--backfill-logs` additionally fills in stored log rows that have
no score yet, for the imported addresses only. Running it twice changes
nothing: an entry is taken over only where none exists here or where the one
here is older.

## Build

The frontend is built first, then embedded into the `uip` binary via `rust-embed`
(`crates/uip-api/src/static_files.rs` embeds `ui/dist/`). Building the Rust binary
without a prior frontend build will embed a stale or missing `ui/dist/`, so the
order matters:

```bash
cd ui && npm ci && npm run build
cd .. && cargo build --release
```

## Searching

The search box takes whatever you know — an address, a port, a device name —
and works out what it is, rather than comparing everything as text. That
distinction matters: compared as text, a search for `10.10.10.10` also returns
`10.10.10.100`, and the address columns fall out of reach of their index.

Terms are separated by spaces and must **all** match, so the box doubles as a
way to stack filters:

```
10.10.30.0/24 443 !tcp        that subnet, port 443, not TCP
src:10.0.0.5 rule:"LAN to"    each scoped to one field
nas denied                    both words, anywhere they are shown
```

| You type | Read as |
|---|---|
| `10.0.0.5` | an address — exact, indexed |
| `10.10.30.0/24`, `10.10.30.`, `10.10.30.*` | a network |
| `443` | a port (source or destination) |
| `aa:bb:cc:dd:ee:ff` | a MAC address |
| anything else | text; `*` is a wildcard |

`!term` or `-term` negates. A prefix scopes a term to one field: `src dst ip
port sport dport rule country asn proto iface host action type`.

Every filter is also a query parameter on `/api/logs`, `/api/export` (CSV) and
`/api/stream` (SSE). The live stream applies the same filter, but suspends
visibly when asked about country, ASN or threat score — a row that has just
arrived has not been enriched yet, so filtering it on those fields would drop
everything. Reload to see the enriched rows.

## Status

Early development — ingest, enrichment, filtering, search and export work.
See the [design doc](docs/superpowers/specs/2026-09-13-uip-rs-rewrite-design.md)
for architecture and the phased roadmap; dashboard, threat map and flow view
are still ahead.

## Origin & license

This project is a from-scratch rewrite inspired by
[jmasarweh/UniFi-Insights-Plus](https://github.com/jmasarweh/UniFi-Insights-Plus)
(originally MIT, BSL 1.1 since v3.2.0) and the fork
[waytoabv/UniFi-Insights-Plus](https://github.com/waytoabv/UniFi-Insights-Plus).
No code is copied from either. This repository is private; no license is granted yet.
