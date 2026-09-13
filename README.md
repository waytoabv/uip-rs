# uip-rs

Complete native rewrite of [UniFi Insights Plus](https://github.com/jmasarweh/UniFi-Insights-Plus) —
real-time syslog analysis for UniFi gateways, rebuilt from scratch:

- **Rust** (tokio) — single binary: UDP syslog receiver, state-machine parsers (no regex),
  decoupled enrichment workers, axum REST API + SSE live stream
- **PostgreSQL + TimescaleDB** — hypertables, native compression and retention policies
- **SolidJS** frontend — fine-grained reactivity for the live log stream, no VDOM diffing
- **Proxmox LXC** deployment — classic community install script, systemd. No Docker.

## Status

Early development. See [design doc](docs/superpowers/specs/2026-09-13-uip-rs-rewrite-design.md)
for architecture and the phased roadmap.

## Origin & license

This project is a from-scratch rewrite inspired by
[jmasarweh/UniFi-Insights-Plus](https://github.com/jmasarweh/UniFi-Insights-Plus)
(originally MIT, BSL 1.1 since v3.2.0) and the fork
[waytoabv/UniFi-Insights-Plus](https://github.com/waytoabv/UniFi-Insights-Plus).
No code is copied from either. This repository is private; no license is granted yet.
