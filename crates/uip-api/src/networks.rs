//! Die Beschriftung der Schnittstellen.
//!
//! Im Log steht `br15`; im Controller heißt dieses Netz „IoT". Die Zuordnung
//! kommt aus dem UniFi-Abgleich (`uip-enrich/src/unifi.rs`) und wird hier als
//! eine einzige kleine Tabelle ausgeliefert, statt sie an jede Log-Zeile
//! anzuhängen: sie ändert sich selten, gilt für alle Zeilen gleich, und zwei
//! zusätzliche Joins in der heißesten Abfrage wären ein hoher Preis für einen
//! Namen, den die Oberfläche genauso gut einmal nachschlagen kann.

use axum::extract::State;
use axum::Json;
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};

use crate::error::ApiError;

pub async fn get_networks(State(pool): State<PgPool>) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT interface, name, vlan, purpose FROM unifi_networks ORDER BY interface",
    )
    .fetch_all(&pool)
    .await?;

    let mut interfaces = Map::new();
    for r in &rows {
        interfaces.insert(
            r.get::<String, _>("interface"),
            json!({
                "name": r.get::<String, _>("name"),
                "vlan": r.get::<Option<i32>, _>("vlan"),
                "purpose": r.get::<Option<String>, _>("purpose"),
            }),
        );
    }
    Ok(Json(json!({ "interfaces": interfaces })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::Value;
    use tower::ServiceExt;

    /// Ohne UniFi-Abgleich ist die Tabelle leer — und leer heißt „benutze die
    /// rohen Namen", nicht „Fehler".
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_empty_table_is_an_empty_map(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app
            .oneshot(Request::get("/api/networks").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        )
        .unwrap();
        assert_eq!(body["interfaces"].as_object().map(|m| m.len()), Some(0));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn interfaces_carry_their_name_and_vlan(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO unifi_networks (interface, name, vlan, purpose) VALUES
             ('br15', 'IoT', 15, 'corporate'), ('eth4', 'WAN', NULL, 'wan')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app
            .oneshot(Request::get("/api/networks").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        )
        .unwrap();
        assert_eq!(body["interfaces"]["br15"]["name"], "IoT");
        assert_eq!(body["interfaces"]["br15"]["vlan"], 15);
        assert_eq!(body["interfaces"]["eth4"]["name"], "WAN");
        assert!(body["interfaces"]["eth4"]["vlan"].is_null(), "WAN hat kein VLAN");
    }
}
