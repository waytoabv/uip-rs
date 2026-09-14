//! IANA service name lookup for the log table's SERVICE column.
//!
//! The registry CSV (`data/service-names-port-numbers.csv`, see
//! `data/SOURCE.md`) is embedded into the binary at compile time and, on
//! first boot, bulk-inserted into the `services` table (empty-table check,
//! then a single multi-row INSERT — not 14 000 round trips). Later boots see
//! a non-empty table and skip straight past the parse.
//!
//! Lives in `uip-api`, not `uip-core`: the `csv` dependency and the bundled
//! data file already belong here, and `logs.rs` (the only consumer of the
//! resolved name) lives in this crate too — no reason to add `csv` to
//! `uip-core` just to relocate this.

use sqlx::PgPool;

const SERVICES_CSV: &str = include_str!("../data/service-names-port-numbers.csv");

/// Transport protocols the registry actually distinguishes; everything else
/// in the `Transport Protocol` column is blank (reserved/unassigned rows).
fn is_known_protocol(p: &str) -> bool {
    matches!(p, "tcp" | "udp" | "sctp" | "dccp")
}

/// Parses the registry CSV into `(port, proto, name)` triples, skipping rows
/// with no usable service name and rows whose "Port Number" is a range
/// (e.g. "1000-1004") rather than a single port.
pub fn parse_service_rows(csv_data: &str) -> Vec<(i32, String, String)> {
    let mut out = Vec::new();
    let mut reader = csv::ReaderBuilder::new().from_reader(csv_data.as_bytes());
    for record in reader.records().flatten() {
        let name = record.get(0).unwrap_or("").trim();
        let port_str = record.get(1).unwrap_or("").trim();
        let proto = record.get(2).unwrap_or("").trim().to_ascii_lowercase();

        if name.is_empty() || port_str.contains('-') || !is_known_protocol(&proto) {
            continue;
        }
        let Ok(port) = port_str.parse::<i32>() else { continue };
        out.push((port, proto, name.to_string()));
    }
    out
}

/// Loads the bundled CSV into `services` if the table is currently empty.
/// Idempotent: a second call sees a non-empty table and returns immediately,
/// and even a concurrent first call can't duplicate rows thanks to
/// `ON CONFLICT DO NOTHING` on the shared (port, proto) primary key.
pub async fn seed_if_empty(pool: &PgPool) -> Result<(), sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM services").fetch_one(pool).await?;
    if count > 0 {
        return Ok(());
    }

    let rows = parse_service_rows(SERVICES_CSV);
    if rows.is_empty() {
        return Ok(());
    }

    // A single multi-row INSERT: ~11.5k rows in one round trip, not one per row.
    let mut qb = sqlx::QueryBuilder::new("INSERT INTO services (port, proto, name) ");
    qb.push_values(rows.iter(), |mut b, (port, proto, name)| {
        b.push_bind(*port).push_bind(proto.as_str()).push_bind(name.as_str());
    });
    // The registry lists the same (port, proto) more than once (e.g. a
    // non-standard entry alongside an RFC one) — first one seen wins, rest
    // are silently dropped rather than erroring the whole batch.
    qb.push(" ON CONFLICT (port, proto) DO NOTHING");
    qb.build().execute(pool).await?;
    Ok(())
}

/// Display name for a resolved service row: uppercased, with the one
/// override the original project made — `domain` reads as `DNS`.
pub fn display_name(raw: &str) -> String {
    if raw.eq_ignore_ascii_case("domain") {
        "DNS".to_string()
    } else {
        raw.to_uppercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_ranges_and_empty_names() {
        let csv = "Service Name,Port Number,Transport Protocol,Description\n\
                    http,80,tcp,World Wide Web HTTP\n\
                    ,90,tcp,Reserved without a name\n\
                    dixie,1000-1004,udp,DIXIE Protocol Specification\n\
                    https,443,tcp,HTTP over TLS/SSL\n\
                    weird,123,carrier-pigeon,not a real transport\n";
        let rows = parse_service_rows(csv);
        assert_eq!(rows.len(), 2, "only http and https should survive: {rows:?}");
        assert!(rows.contains(&(80, "tcp".to_string(), "http".to_string())));
        assert!(rows.contains(&(443, "tcp".to_string(), "https".to_string())));
    }

    #[test]
    fn display_name_applies_the_dns_override_and_uppercases() {
        assert_eq!(display_name("domain"), "DNS");
        assert_eq!(display_name("DOMAIN"), "DNS");
        assert_eq!(display_name("https"), "HTTPS");
        assert_eq!(display_name("secure-mqtt"), "SECURE-MQTT");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn seeds_known_rows_and_is_idempotent(pool: sqlx::PgPool) {
        seed_if_empty(&pool).await.unwrap();

        let https: Option<String> =
            sqlx::query_scalar("SELECT name FROM services WHERE port = 443 AND proto = 'tcp'")
                .fetch_optional(&pool).await.unwrap();
        assert_eq!(https.as_deref(), Some("https"));

        let dns: Option<String> =
            sqlx::query_scalar("SELECT name FROM services WHERE port = 53 AND proto = 'udp'")
                .fetch_optional(&pool).await.unwrap();
        assert_eq!(dns.map(|n| display_name(&n)), Some("DNS".to_string()));

        let mqtt: Option<String> =
            sqlx::query_scalar("SELECT name FROM services WHERE port = 8883 AND proto = 'tcp'")
                .fetch_optional(&pool).await.unwrap();
        assert_eq!(mqtt.as_deref(), Some("secure-mqtt"));

        let count_after_first: i64 =
            sqlx::query_scalar("SELECT count(*) FROM services").fetch_one(&pool).await.unwrap();
        assert!(count_after_first > 10_000, "expected the full registry, got {count_after_first}");

        // Idempotent: running again against a non-empty table changes nothing.
        seed_if_empty(&pool).await.unwrap();
        let count_after_second: i64 =
            sqlx::query_scalar("SELECT count(*) FROM services").fetch_one(&pool).await.unwrap();
        assert_eq!(count_after_first, count_after_second);
    }
}
