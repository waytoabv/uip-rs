//! Die Namen der Firewall-Regeln.
//!
//! In der Log-Zeile steht `CUSTOM2_CUSTOM1-A-10008` und daneben eine bei 29
//! Zeichen abgeschnittene Beschreibung — mehr überträgt das Feld `DESCR` der
//! Firewall nicht. Der volle Name steht im Controller und kommt über den
//! UniFi-Abgleich (`uip-enrich/src/unifi.rs`) in die Datenbank.
//!
//! Ausgeliefert wie die Netznamen: eine kleine Tabelle, einmal geholt, statt
//! eines Joins an der heißesten Abfrage. Das deckt zugleich die Zeilen aus dem
//! Live-Strom mit ab — die laufen nie durch `/api/logs`.

use axum::extract::State;
use axum::Json;
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};

use crate::error::ApiError;

pub async fn get_firewall_rules(State(pool): State<PgPool>) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT rule_key, name, src_zone, dst_zone, predefined
           FROM unifi_firewall_policies ORDER BY rule_key",
    )
    .fetch_all(&pool)
    .await?;

    let mut rules = Map::new();
    for r in &rows {
        rules.insert(
            r.get::<String, _>("rule_key"),
            json!({
                "name": r.get::<String, _>("name"),
                "src_zone": r.get::<Option<String>, _>("src_zone"),
                "dst_zone": r.get::<Option<String>, _>("dst_zone"),
                "predefined": r.get::<bool, _>("predefined"),
            }),
        );
    }
    Ok(Json(json!({ "rules": rules })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::Value;
    use tower::ServiceExt;

    async fn get(pool: sqlx::PgPool) -> Value {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app
            .oneshot(Request::get("/api/firewall-rules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap())
            .unwrap()
    }

    /// Ohne Abgleich ist die Tabelle leer — und leer heißt „nimm, was im Log
    /// steht", nicht „Fehler".
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_empty_table_is_an_empty_map(pool: sqlx::PgPool) {
        let body = get(pool).await;
        assert_eq!(body["rules"].as_object().map(|m| m.len()), Some(0));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_rule_carries_its_name_and_zones(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO unifi_firewall_policies (rule_key, name, src_zone, dst_zone, predefined)
             VALUES ('CUSTOM2_CUSTOM1-A-10008', 'VL15 -> VL10 - Allow Pihole DNS and WebUI',
                     '#1 - Internes Netzwerk', '#0 - Servernetzwerk', false),
                    ('LOCAL_WAN-A-2147483647', 'Allow All Traffic', 'Gateway', 'External', true)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let body = get(pool).await;
        let rule = &body["rules"]["CUSTOM2_CUSTOM1-A-10008"];
        assert_eq!(rule["name"], "VL15 -> VL10 - Allow Pihole DNS and WebUI");
        assert_eq!(rule["src_zone"], "#1 - Internes Netzwerk");
        assert_eq!(rule["predefined"], false);
        assert_eq!(body["rules"]["LOCAL_WAN-A-2147483647"]["predefined"], true);
    }
}
