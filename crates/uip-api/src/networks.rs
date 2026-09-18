//! Die Beschriftung der Schnittstellen.
//!
//! Im Log steht `br15`; im Controller heißt dieses Netz „IoT". Die Zuordnung
//! kommt aus dem UniFi-Abgleich (`uip-enrich/src/unifi.rs`) und wird hier als
//! eine einzige kleine Tabelle ausgeliefert, statt sie an jede Log-Zeile
//! anzuhängen: sie ändert sich selten, gilt für alle Zeilen gleich, und zwei
//! zusätzliche Joins in der heißesten Abfrage wären ein hoher Preis für einen
//! Namen, den die Oberfläche genauso gut einmal nachschlagen kann.
//!
//! Darüber liegt der selbst vergebene Name (`interface_names`): der Controller
//! nennt ein Netz „#1 - VLAN15 - Intern", weil dort Nummer und VLAN mitgeführt
//! werden — in einer Tabelle, in der die VLAN-Nummer schon in der Spalte
//! daneben steht, will man vielleicht nur „Intern" lesen.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};

use crate::error::ApiError;

/// Länger als das ist kein Name mehr, sondern ein Satz — und die Spalte, in
/// der er steht, ist schmal.
const MAX_NAME: usize = 64;

/// Alle Schnittstellen, die irgendwo vorkommen: die Netze des Controllers, die
/// selbst benannten und alles, was je in einer Log-Zeile stand. Die letzte
/// Quelle ist der Grund, warum der Einstellungsdialog auch `ppp0` oder `tun0`
/// anbieten kann — Schnittstellen, von denen der Controller nichts weiß.
pub async fn get_networks(State(pool): State<PgPool>) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT i.interface, n.name, n.vlan, n.purpose, c.name AS custom
           FROM (SELECT name AS interface FROM interfaces
                 UNION SELECT interface FROM unifi_networks
                 UNION SELECT interface FROM interface_names) i
           LEFT JOIN unifi_networks n ON n.interface = i.interface
           LEFT JOIN interface_names c ON c.interface = i.interface
          ORDER BY i.interface",
    )
    .fetch_all(&pool)
    .await?;

    let mut interfaces = Map::new();
    for r in &rows {
        interfaces.insert(
            r.get::<String, _>("interface"),
            json!({
                "name": r.get::<Option<String>, _>("name"),
                "vlan": r.get::<Option<i32>, _>("vlan"),
                "purpose": r.get::<Option<String>, _>("purpose"),
                "custom": r.get::<Option<String>, _>("custom"),
            }),
        );
    }
    Ok(Json(json!({ "interfaces": interfaces })))
}

#[derive(Deserialize)]
pub struct NamesPatch(pub Map<String, Value>);

/// Setzt oder löscht eigene Namen: `{"br15": "Intern", "ppp0": null}`.
///
/// `null` und der leere Name heißen dasselbe — zurück zu dem, was der
/// Controller sagt. Ein eigener Name ist eine Meinung über die Anzeige, kein
/// Datum: ihn zu löschen muss so leicht sein wie ihn zu setzen.
pub async fn put_names(
    State(pool): State<PgPool>,
    Json(patch): Json<NamesPatch>,
) -> Result<Json<Value>, ApiError> {
    let mut written = Vec::new();
    let mut cleared = Vec::new();
    let mut rejected = Vec::new();

    for (iface, value) in patch.0 {
        let name = match &value {
            Value::Null => None,
            Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
            // Alles andere ist ein Fehler im Aufruf, kein leerer Name: still
            // zu löschen wäre die unfreundlichere Antwort.
            _ => {
                rejected.push(iface);
                continue;
            }
        };
        if iface.trim().is_empty() || name.as_ref().is_some_and(|n| n.chars().count() > MAX_NAME) {
            rejected.push(iface);
            continue;
        }

        match name {
            Some(name) => {
                sqlx::query(
                    "INSERT INTO interface_names (interface, name, updated_at)
                     VALUES ($1, $2, NOW())
                     ON CONFLICT (interface) DO UPDATE SET name = EXCLUDED.name, updated_at = NOW()",
                )
                .bind(&iface)
                .bind(&name)
                .execute(&pool)
                .await?;
                written.push(iface);
            }
            None => {
                sqlx::query("DELETE FROM interface_names WHERE interface = $1")
                    .bind(&iface)
                    .execute(&pool)
                    .await?;
                cleared.push(iface);
            }
        }
    }

    Ok(Json(json!({ "written": written, "cleared": cleared, "rejected": rejected })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::Value;
    use tower::ServiceExt;

    fn app(pool: sqlx::PgPool) -> axum::Router {
        crate::router(pool, tokio::sync::broadcast::channel(8).0)
    }

    async fn body_of(res: axum::response::Response) -> Value {
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap())
            .unwrap()
    }

    async fn get_networks(pool: sqlx::PgPool) -> Value {
        let res = app(pool)
            .oneshot(Request::get("/api/networks").body(Body::empty()).unwrap())
            .await
            .unwrap();
        body_of(res).await
    }

    async fn put_names(pool: sqlx::PgPool, json: &str) -> Value {
        let res = app(pool)
            .oneshot(
                Request::put("/api/networks/names")
                    .header("content-type", "application/json")
                    .body(Body::from(json.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        body_of(res).await
    }

    /// Ohne UniFi-Abgleich ist die Tabelle leer — und leer heißt „benutze die
    /// rohen Namen", nicht „Fehler".
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_empty_table_is_an_empty_map(pool: sqlx::PgPool) {
        let body = get_networks(pool).await;
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

        let body = get_networks(pool).await;
        assert_eq!(body["interfaces"]["br15"]["name"], "IoT");
        assert_eq!(body["interfaces"]["br15"]["vlan"], 15);
        assert_eq!(body["interfaces"]["eth4"]["name"], "WAN");
        assert!(body["interfaces"]["eth4"]["vlan"].is_null(), "WAN hat kein VLAN");
    }

    /// Eine Schnittstelle, die nur in Log-Zeilen vorkommt, muss trotzdem
    /// benennbar sein — sonst bleibt `ppp0` für immer `ppp0`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_interface_seen_only_in_logs_is_listed(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO interfaces (name) VALUES ('ppp0')")
            .execute(&pool)
            .await
            .unwrap();

        let body = get_networks(pool).await;
        let entry = &body["interfaces"]["ppp0"];
        assert!(entry.is_object(), "ppp0 fehlt: {body}");
        assert!(entry["name"].is_null(), "der Controller kennt ppp0 nicht");
        assert!(entry["custom"].is_null());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_custom_name_is_stored_and_can_be_cleared(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO unifi_networks (interface, name, vlan) VALUES ('br15', '#1 - VLAN15 - Intern', 15)")
            .execute(&pool)
            .await
            .unwrap();

        let res = put_names(pool.clone(), r#"{"br15": "  Intern  "}"#).await;
        assert_eq!(res["written"][0], "br15");
        let body = get_networks(pool.clone()).await;
        assert_eq!(body["interfaces"]["br15"]["custom"], "Intern", "Leerraum fällt weg");
        // Der Name des Controllers bleibt daneben stehen: der eigene ist eine
        // Anzeigeentscheidung, keine Löschung.
        assert_eq!(body["interfaces"]["br15"]["name"], "#1 - VLAN15 - Intern");

        let res = put_names(pool.clone(), r#"{"br15": null}"#).await;
        assert_eq!(res["cleared"][0], "br15");
        let body = get_networks(pool).await;
        assert!(body["interfaces"]["br15"]["custom"].is_null());
    }

    /// Der leere Name ist kein Name — er heißt „zurück zum Controller".
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_empty_name_clears_instead_of_storing_nothing(pool: sqlx::PgPool) {
        put_names(pool.clone(), r#"{"br15": "Intern"}"#).await;
        let res = put_names(pool.clone(), r#"{"br15": "   "}"#).await;
        assert_eq!(res["cleared"][0], "br15");
        let body = get_networks(pool).await;
        assert!(body["interfaces"]["br15"].is_null(), "ohne Namen bleibt nichts übrig");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_name_that_is_not_a_name_is_refused(pool: sqlx::PgPool) {
        let res = put_names(pool.clone(), r#"{"br15": 42, "br20": "x"}"#).await;
        assert_eq!(res["rejected"][0], "br15");
        assert_eq!(res["written"][0], "br20");

        let long = "n".repeat(65);
        let res = put_names(pool, &format!(r#"{{"br15": "{long}"}}"#)).await;
        assert_eq!(res["rejected"][0], "br15");
    }
}
