//! Die Gerätenamen, als eine Tabelle.
//!
//! Die Zeilenliste löst sie beim Lesen über einen Join auf. Der Live-Strom
//! kann das nicht: er reicht die Zeile weiter, sobald sie geschrieben ist, und
//! ein Join je Zeile im heißesten Pfad wäre ein hoher Preis für einen Namen,
//! der sich selten ändert. Die Folge war, dass jede gerade eintreffende Zeile
//! ihre Adresse zeigte und erst nach dem Neuladen der Seite einen Namen bekam.
//!
//! Also derselbe Weg wie bei den Netznamen: einmal geholt, gilt für alle
//! Zeilen — die Oberfläche beschriftet damit, was der Strom bringt.

use axum::extract::State;
use axum::Json;
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};

use crate::error::ApiError;

pub async fn get_devices(State(pool): State<PgPool>) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query("SELECT host(ip) AS ip, name FROM device_addresses ORDER BY ip")
        .fetch_all(&pool)
        .await?;

    let mut devices = Map::new();
    for r in &rows {
        let (Some(ip), name) = (r.get::<Option<String>, _>("ip"), r.get::<String, _>("name"))
        else {
            continue;
        };
        devices.insert(ip, Value::String(name));
    }
    Ok(Json(json!({ "devices": devices })))
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
            .oneshot(Request::get("/api/devices").body(Body::empty()).unwrap())
            .await
            .unwrap();
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap())
            .unwrap()
    }

    /// Ohne Controller ist die Tabelle leer — und leer heißt „zeig die
    /// Adresse", nicht „Fehler".
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_empty_table_is_an_empty_map(pool: sqlx::PgPool) {
        let body = get(pool).await;
        assert_eq!(body["devices"].as_object().map(|m| m.len()), Some(0));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn every_known_address_carries_its_name(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO device_addresses (ip, name, kind) VALUES
             ('10.10.15.56', 'MacBook Pro', 'client'),
             ('10.10.15.1', 'Express 7', 'gateway')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let body = get(pool).await;
        assert_eq!(body["devices"]["10.10.15.56"], "MacBook Pro");
        // Auch das Gateway: es steht in jeder VLAN-Zeile und hieß bisher
        // nirgends, weil der Controller von ihm nur die WAN-Adresse meldet.
        assert_eq!(body["devices"]["10.10.15.1"], "Express 7");
    }
}
