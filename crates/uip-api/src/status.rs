//! Der Zustand der Anreicherungsquellen, für die Statusleiste der Kopfzeile.
//!
//! Alles hier ist Beobachtung, keine Vorhersage — mit einer Ausnahme, die
//! unten benannt ist. Was die App nicht weiß, meldet sie als `null` statt als
//! geratene Zahl: die Leiste soll den Unterschied zwischen „nichts übrig" und
//! „noch nie gefragt" zeigen können.

use axum::extract::State;
use axum::Json;
use chrono::{DateTime, Datelike, Duration, Local, TimeZone, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::path::Path;
use std::time::SystemTime;

use crate::error::ApiError;

/// Dasselbe Verzeichnis, das `uip-core::Settings` als Vorgabe kennt.
const DEFAULT_GEOIP_DIR: &str = "/var/lib/uip/geoip";

/// Der Zufallsversatz aus `lxc/systemd/uip-geoip.timer` (`RandomizedDelaySec`).
const GEOIP_JITTER_HOURS: i64 = 6;

/// Der nächste GeoIP-Lauf als Zeitfenster.
///
/// Abgeleitet aus `lxc/systemd/uip-geoip.timer`: `OnCalendar=weekly` liest
/// systemd als Montag 00:00 Ortszeit, `RandomizedDelaySec=6h` schiebt den Lauf
/// um bis zu sechs Stunden nach hinten. Deshalb ein Fenster und kein Zeitpunkt
/// — ein exakter Termin wäre hier gelogen.
///
/// Das ist die eine Stelle, an der die App etwas behauptet, das sie nicht
/// beobachtet: sie läuft unter systemd, statt es zu befragen. Wer die
/// Timer-Datei ändert, muss die beiden Werte hier mitziehen.
fn next_geoip_run(now: DateTime<Local>) -> (DateTime<Local>, DateTime<Local>) {
    let days_to_monday = (7 - now.weekday().num_days_from_monday() as i64) % 7;
    let midnight = now.date_naive() + Duration::days(days_to_monday);
    let naive = midnight.and_hms_opt(0, 0, 0).expect("Mitternacht gibt es");
    // `earliest` statt `unwrap`: in der Nacht der Zeitumstellung kann
    // Mitternacht mehrdeutig sein oder ganz fehlen.
    let mut start = Local
        .from_local_datetime(&naive)
        .earliest()
        .unwrap_or_else(|| now + Duration::days(days_to_monday));
    if start <= now {
        start += Duration::days(7);
    }
    (start, start + Duration::hours(GEOIP_JITTER_HOURS))
}

/// Wann die Datei zuletzt geschrieben wurde — `None`, wenn es sie nicht gibt.
fn modified_at(path: &Path) -> Option<DateTime<Utc>> {
    let t: SystemTime = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(t.into())
}

async fn config(pool: &PgPool, key: &str) -> Option<Value> {
    sqlx::query_scalar::<_, Value>("SELECT value FROM system_config WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

pub async fn get_status(State(pool): State<PgPool>) -> Result<Json<Value>, ApiError> {
    let dir = config(&pool, "geoip_dir")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_GEOIP_DIR.to_string());
    let dir = Path::new(&dir);

    // Beide Dateien, nicht nur die Stadt-Datenbank: fehlt eine, ist der Grund
    // für leere Spalten sichtbar, statt dass „MaxMind: 12. Sep" Vollständigkeit
    // behauptet, während die ASN-Namen fehlen.
    let city = modified_at(&dir.join("GeoLite2-City.mmdb"));
    let asn = modified_at(&dir.join("GeoLite2-ASN.mmdb"));

    let (next_from, next_until) = next_geoip_run(Local::now());

    Ok(Json(json!({
        // Vom Anreicherungs-Worker geschrieben; `null`, solange es keine
        // Antwort von AbuseIPDB gab, aus der ein Kontingent hervorginge.
        "abuseipdb": config(&pool, "abuseipdb_quota").await,
        "maxmind": {
            "last_update": city.max(asn).map(|t| t.to_rfc3339()),
            "city": city.map(|t| t.to_rfc3339()),
            "asn": asn.map(|t| t.to_rfc3339()),
        },
        "maxmind_next_update": {
            "from": next_from.with_timezone(&Utc).to_rfc3339(),
            "until": next_until.with_timezone(&Utc).to_rfc3339(),
        },
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::NaiveDate;
    use tower::ServiceExt;

    fn local(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Local> {
        Local
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(y, m, d).unwrap().and_hms_opt(h, min, 0).unwrap(),
            )
            .earliest()
            .unwrap()
    }

    /// Der Timer steht auf „weekly", und das heißt bei systemd Montag 00:00 —
    /// nicht „sieben Tage nach dem letzten Lauf".
    #[test]
    fn the_next_run_is_the_coming_monday() {
        // Dienstag → der Montag darauf.
        let (from, until) = next_geoip_run(local(2026, 9, 15, 22, 30));
        assert_eq!(from, local(2026, 9, 21, 0, 0));
        assert_eq!(until, local(2026, 9, 21, 6, 0));

        // Sonntagnacht → derselbe kommende Montag, wenige Stunden später.
        let (from, _) = next_geoip_run(local(2026, 9, 20, 23, 59));
        assert_eq!(from, local(2026, 9, 21, 0, 0));
    }

    /// Am Montag selbst darf nicht der heutige, schon vergangene Termin
    /// stehen bleiben — sonst zeigte die Leiste den ganzen Montag über einen
    /// Lauf an, der bereits hinter uns liegt.
    #[test]
    fn monday_points_at_the_next_one_not_todays() {
        let (from, _) = next_geoip_run(local(2026, 9, 21, 9, 0));
        assert_eq!(from, local(2026, 9, 28, 0, 0));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn unknown_sources_report_null_rather_than_zero(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app
            .oneshot(Request::get("/api/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        )
        .unwrap();

        // Kein Worker gelaufen, kein Kontingent bekannt.
        assert!(body["abuseipdb"].is_null(), "unbekannt ist nicht 0");
        // Das Vorgabeverzeichnis gibt es im Test nicht — also kein Stand.
        assert!(body["maxmind"]["last_update"].is_null());
        assert!(body["maxmind_next_update"]["from"].is_string());
    }

    /// Was der Worker hinterlegt, muss unverändert wieder herauskommen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_quota_written_by_the_worker_is_served(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO system_config (key, value) VALUES ('abuseipdb_quota',
             '{\"remaining\": 987, \"paused_until\": 0}'::jsonb)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app
            .oneshot(Request::get("/api/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        )
        .unwrap();
        assert_eq!(body["abuseipdb"]["remaining"].as_i64(), Some(987));
    }

    /// Der Stand kommt aus dem eingestellten Verzeichnis, nicht aus dem
    /// eingebauten Vorgabepfad — sonst zeigte jede Nicht-Standardinstallation
    /// dauerhaft „—".
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_maxmind_date_follows_the_configured_directory(pool: sqlx::PgPool) {
        let dir = std::env::temp_dir().join(format!("uip-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("GeoLite2-City.mmdb"), b"not really a database").unwrap();
        sqlx::query("INSERT INTO system_config (key, value) VALUES ('geoip_dir', $1)")
            .bind(Value::from(dir.to_string_lossy().to_string()))
            .execute(&pool)
            .await
            .unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app
            .oneshot(Request::get("/api/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        )
        .unwrap();
        assert!(body["maxmind"]["city"].is_string(), "die Stadt-Datenbank liegt dort");
        assert!(body["maxmind"]["asn"].is_null(), "die ASN-Datenbank nicht");
        assert_eq!(body["maxmind"]["last_update"], body["maxmind"]["city"]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
