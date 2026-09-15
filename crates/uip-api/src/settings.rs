//! Lesen und Schreiben der Laufzeit-Einstellungen.
//!
//! Alles liegt in `system_config` (JSONB), wie es `uip-core::Settings` beim
//! Start liest. Diese Endpunkte sind die Bedienoberfläche dazu.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::error::ApiError;

/// Schlüssel, die die Oberfläche setzen darf, mit ihrem Typ.
///
/// Eine feste Liste statt „schreib, was du willst": `system_config` wird auch
/// vom Ingest und von der Anreicherung gelesen, und ein Tippfehler im
/// Schlüssel wäre dort eine stumme Fehlfunktion statt eines Fehlers.
const ALLOWED: &[(&str, Kind)] = &[
    ("wan_ips", Kind::Text),
    ("gateway_ips", Kind::Text),
    ("rdns_enabled", Kind::Bool),
    ("abuseipdb_api_key", Kind::Secret),
    ("geoip_dir", Kind::Text),
    ("pihole_url", Kind::Text),
    ("pihole_password", Kind::Secret),
    ("pihole_enabled", Kind::Bool),
    ("unifi_url", Kind::Text),
    ("unifi_api_key", Kind::Secret),
    ("unifi_site", Kind::Text),
    ("unifi_enabled", Kind::Bool),
    ("retention_days", Kind::Number),
    ("retention_days_dns", Kind::Number),
];

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Bool,
    Number,
    /// Wird nie im Klartext zurückgegeben — nur ob gesetzt.
    Secret,
}

fn kind_of(key: &str) -> Option<Kind> {
    ALLOWED.iter().find(|(k, _)| *k == key).map(|(_, t)| *t)
}

/// Alle Einstellungen. Geheimnisse erscheinen als `true`/`false` unter
/// `<key>_set`, nie als Wert — wer sie auslesen könnte, bräuchte sie nicht.
pub async fn get_settings(State(pool): State<PgPool>) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query_as::<_, (String, Value)>("SELECT key, value FROM system_config")
        .fetch_all(&pool)
        .await?;

    let mut out = serde_json::Map::new();
    for (key, value) in rows {
        match kind_of(&key) {
            Some(Kind::Secret) => {
                let set = value.as_str().map(|s| !s.is_empty()).unwrap_or(false);
                out.insert(format!("{key}_set"), Value::Bool(set));
            }
            Some(_) => {
                out.insert(key, value);
            }
            // Unbekannte Schlüssel (etwa das Kontingent von AbuseIPDB, das
            // der Worker selbst pflegt) bleiben außen vor.
            None => {}
        }
    }
    Ok(Json(Value::Object(out)))
}

#[derive(Deserialize)]
pub struct SettingsPatch(pub serde_json::Map<String, Value>);

/// Setzt einzelne Schlüssel. Was nicht in der Liste steht, wird abgelehnt —
/// mit Nennung des Schlüssels, damit ein Tippfehler sichtbar wird.
pub async fn put_settings(
    State(pool): State<PgPool>,
    Json(patch): Json<SettingsPatch>,
) -> Result<Json<Value>, ApiError> {
    let mut written = Vec::new();
    let mut rejected = Vec::new();

    for (key, value) in patch.0 {
        let Some(kind) = kind_of(&key) else {
            rejected.push(key);
            continue;
        };
        let ok = match kind {
            Kind::Bool => value.is_boolean(),
            Kind::Number => value.is_number(),
            Kind::Text | Kind::Secret => value.is_string(),
        };
        if !ok {
            rejected.push(key);
            continue;
        }
        // Ein geleertes Geheimnis heißt "abschalten", nicht "unverändert".
        sqlx::query(
            "INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW())
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
        )
        .bind(&key)
        .bind(&value)
        .execute(&pool)
        .await?;
        written.push(key);
    }

    Ok(Json(json!({ "written": written, "rejected": rejected })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get_json(app: &axum::Router, uri: &str) -> serde_json::Value {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "bei {uri}");
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap()
    }

    async fn put_json(app: &axum::Router, body: serde_json::Value) -> serde_json::Value {
        let res = app
            .clone()
            .oneshot(
                Request::put("/api/settings")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn writes_and_reads_back(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let r = put_json(&app, serde_json::json!({ "pihole_url": "http://pi.hole", "rdns_enabled": false })).await;
        assert_eq!(r["rejected"].as_array().map(|a| a.len()), Some(0));

        let s = get_json(&app, "/api/settings").await;
        assert_eq!(s["pihole_url"].as_str(), Some("http://pi.hole"));
        assert_eq!(s["rdns_enabled"].as_bool(), Some(false));
    }

    /// Geheimnisse dürfen nie zurückkommen — wer sie auslesen könnte,
    /// bräuchte sie nicht. Sichtbar ist nur, ob eines gesetzt ist.
    #[sqlx::test(migrations = "../../migrations")]
    async fn secrets_are_never_returned(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        put_json(&app, serde_json::json!({ "abuseipdb_api_key": "supersecret" })).await;

        let s = get_json(&app, "/api/settings").await;
        assert_eq!(s["abuseipdb_api_key_set"].as_bool(), Some(true));
        assert!(s.get("abuseipdb_api_key").is_none(), "der Schlüssel selbst darf nicht erscheinen");
        assert!(!s.to_string().contains("supersecret"));
    }

    /// Ein Tippfehler im Schlüssel muss auffallen: `system_config` wird auch
    /// vom Ingest gelesen, dort wäre er eine stumme Fehlfunktion.
    #[sqlx::test(migrations = "../../migrations")]
    async fn unknown_keys_and_wrong_types_are_refused(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let r = put_json(
            &app,
            serde_json::json!({ "pihole_urlx": "x", "rdns_enabled": "ja", "pihole_url": "http://ok" }),
        )
        .await;
        let rejected: Vec<&str> = r["rejected"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(rejected.contains(&"pihole_urlx"), "unbekannter Schlüssel");
        assert!(rejected.contains(&"rdns_enabled"), "falscher Typ");
        assert_eq!(r["written"].as_array().unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_empty_database_yields_an_object_not_null(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        assert!(get_json(&app, "/api/settings").await.is_object());
    }
}

/// Prüft die hinterlegte Pi-hole-Verbindung, ohne das Passwort preiszugeben.
///
/// Eigener Endpunkt statt eines Feldes in `GET /api/settings`: ein Abruf über
/// das Netz gehört nicht in das Lesen einer Konfiguration, und wer die
/// Einstellungen nur öffnet, soll nicht jedes Mal einen Anmeldeversuch
/// auslösen.
pub async fn test_pihole(State(pool): State<PgPool>) -> Result<Json<Value>, ApiError> {
    let get = |key: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Value>("SELECT value FROM system_config WHERE key = $1")
                .bind(key)
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default()
        }
    };
    let url = get("pihole_url").await;
    let password = get("pihole_password").await;

    if url.is_empty() {
        return Ok(Json(json!({ "ok": false, "reason": "no_url" })));
    }
    let client = uip_enrich::pihole::Pihole::new(url, password);
    Ok(Json(match client.test().await {
        uip_enrich::pihole::TestOutcome::Ok { version } => json!({ "ok": true, "version": version }),
        uip_enrich::pihole::TestOutcome::BadCredentials => json!({ "ok": false, "reason": "bad_credentials" }),
        uip_enrich::pihole::TestOutcome::Unreachable(e) => json!({ "ok": false, "reason": "unreachable", "detail": e }),
    }))
}

/// Prüft die UniFi-Verbindung und meldet, wie viel der Controller kennt.
pub async fn test_unifi(State(pool): State<PgPool>) -> Result<Json<Value>, ApiError> {
    let read = |key: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Value>("SELECT value FROM system_config WHERE key = $1")
                .bind(key)
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default()
        }
    };
    let url = read("unifi_url").await;
    if url.is_empty() {
        return Ok(Json(json!({ "ok": false, "reason": "no_url" })));
    }
    let client = uip_enrich::unifi::Unifi::new(url, read("unifi_api_key").await, read("unifi_site").await);
    Ok(Json(match client.test().await {
        uip_enrich::unifi::TestOutcome::Ok { clients, devices } => {
            json!({ "ok": true, "clients": clients, "devices": devices })
        }
        uip_enrich::unifi::TestOutcome::BadCredentials => json!({ "ok": false, "reason": "bad_credentials" }),
        uip_enrich::unifi::TestOutcome::Unreachable(e) => json!({ "ok": false, "reason": "unreachable", "detail": e }),
    }))
}
