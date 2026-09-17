//! Der Zustand der Anreicherungsquellen, für die Statusleiste der Kopfzeile.
//!
//! Alles hier ist Beobachtung, keine Vorhersage — mit einer Ausnahme, die
//! unten benannt ist. Was die App nicht weiß, meldet sie als `null` statt als
//! geratene Zahl: die Leiste soll den Unterschied zwischen „nichts übrig" und
//! „noch nie gefragt" zeigen können.

use axum::extract::State;
use axum::Json;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::path::Path;
use std::time::SystemTime;

use crate::error::ApiError;

/// Dasselbe Verzeichnis, das `uip-core::Settings` als Vorgabe kennt.
const DEFAULT_GEOIP_DIR: &str = "/var/lib/uip/geoip";

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
    let status = config(&pool, "maxmind_status").await;

    // Der Punkt in der Kopfzeile soll drei Fälle unterscheiden: abgeschaltet,
    // verbunden, gestört. Ohne `enabled` wäre „nie gemeldet" nicht von „gerade
    // abgestürzt" zu trennen.
    let pihole = json!({
        "enabled": config(&pool, "pihole_enabled").await.and_then(|v| v.as_bool()).unwrap_or(false),
        "last": config(&pool, "pihole_status").await,
    });

    let unifi = json!({
        "enabled": config(&pool, "unifi_enabled").await.and_then(|v| v.as_bool()).unwrap_or(false),
        "last": config(&pool, "unifi_status").await,
    });

    Ok(Json(json!({
        // Vom Anreicherungs-Worker geschrieben; `null`, solange es keine
        // Antwort von AbuseIPDB gab, aus der ein Kontingent hervorginge.
        "abuseipdb": config(&pool, "abuseipdb_quota").await,
        "pihole": pihole,
        "unifi": unifi,
        // Der Empfänger zählt, was ankommt. Das ist die einzige belastbare
        // Aussage darüber, ob das Gateway seine Meldungen wirklich hierher
        // schickt — und sie kostet keine einzige gespeicherte Zeile.
        "syslog": config(&pool, "syslog_stats").await,
        "maxmind": {
            "last_update": city.max(asn).map(|t| t.to_rfc3339()),
            "city": city.map(|t| t.to_rfc3339()),
            "asn": asn.map(|t| t.to_rfc3339()),
        },
        // Beobachtet, nicht abgeleitet: der Aktualisierer schreibt hier hin,
        // wann er das nächste Mal nachsieht. Vorher stand der Termin in einer
        // systemd-Unit, die diese Anwendung nicht liest — sie musste ihn
        // nachbauen und lag daneben, sobald jemand die Datei änderte.
        "maxmind_next_update": status.as_ref().and_then(|v| v.get("next_check").cloned()),
        "maxmind_error": status.as_ref().and_then(|v| v.get("error").cloned()),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

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
        // Kein Aktualisierer gelaufen: der nächste Termin ist unbekannt und
        // wird als solcher gemeldet, nicht als erfundenes Datum.
        assert!(body["maxmind_next_update"].is_null());
    }

    /// Der nächste Abruf kommt aus dem, was der Aktualisierer hinterlassen
    /// hat — er wird nicht aus einem Zeitplan errechnet, den diese Anwendung
    /// gar nicht kennt.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_next_maxmind_check_is_the_one_the_updater_recorded(pool: sqlx::PgPool) {
        sqlx::query(
            r#"INSERT INTO system_config (key, value) VALUES ('maxmind_status',
             '{"next_check": "2026-09-18T06:00:00+00:00", "error": "401 Unauthorized"}'::jsonb)"#,
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
        assert_eq!(body["maxmind_next_update"].as_str(), Some("2026-09-18T06:00:00+00:00"));
        assert_eq!(body["maxmind_error"].as_str(), Some("401 Unauthorized"));
    }

    /// Der Punkt muss „aus", „läuft" und „gestört" auseinanderhalten können.
    #[sqlx::test(migrations = "../../migrations")]
    async fn pihole_reports_off_running_and_broken(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        let get = |app: axum::Router| async move {
            let res = app
                .oneshot(Request::get("/api/status").body(Body::empty()).unwrap())
                .await
                .unwrap();
            serde_json::from_slice::<Value>(
                &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
            )
            .unwrap()
        };

        // Aus: nichts eingerichtet.
        let body = get(app.clone()).await;
        assert_eq!(body["pihole"]["enabled"], false);
        assert!(body["pihole"]["last"].is_null());

        // An, aber noch kein Durchlauf — „enabled" allein macht keinen Punkt grün.
        sqlx::query("INSERT INTO system_config (key, value) VALUES ('pihole_enabled', 'true'::jsonb)")
            .execute(&pool).await.unwrap();
        let body = get(app.clone()).await;
        assert_eq!(body["pihole"]["enabled"], true);
        assert!(body["pihole"]["last"].is_null());

        // Gestört: der Abruf hinterlässt seinen Fehler.
        sqlx::query(
            r#"INSERT INTO system_config (key, value) VALUES ('pihole_status',
             '{"ok": false, "at": "2026-09-15T20:00:00Z", "error": "connection refused"}'::jsonb)"#,
        ).execute(&pool).await.unwrap();
        let body = get(app).await;
        assert_eq!(body["pihole"]["last"]["ok"], false);
        assert_eq!(body["pihole"]["last"]["error"], "connection refused");
    }

    /// Was der Worker hinterlegt, muss unverändert wieder herauskommen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_quota_written_by_the_worker_is_served(pool: sqlx::PgPool) {
        sqlx::query(
            r#"INSERT INTO system_config (key, value) VALUES ('abuseipdb_quota',
             '{"remaining": 987, "limit": 1000,
               "reset_at": "2026-09-16T02:00:00+00:00", "paused_until": null}'::jsonb)"#,
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
        assert_eq!(body["abuseipdb"]["limit"].as_i64(), Some(1000));
        assert_eq!(body["abuseipdb"]["reset_at"].as_str(), Some("2026-09-16T02:00:00+00:00"));
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
