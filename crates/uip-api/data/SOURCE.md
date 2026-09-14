# service-names-port-numbers.csv

Bundled copy of the IANA Service Name and Transport Protocol Port Number
Registry: https://www.iana.org/assignments/service-names-port-numbers/

This data is maintained by IANA and is in the public domain / free to reuse.
Copied here (unmodified) from the previous project's
`receiver/data/service-names-port-numbers.csv` for use by
`crates/uip-api/src/services.rs`, which loads it at start-up to seed the
`services` lookup table (see `migrations/0003_services.sql`).

To refresh: download the current CSV from the URL above and replace this
file; the seeder only inserts on first boot (empty table), so existing
deployments won't pick up a refreshed file until the `services` table is
truncated or the row set changes are migrated in separately.
