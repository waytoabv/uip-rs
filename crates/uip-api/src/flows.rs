//! Flow View. Verkehr als Fluss (Quelle → Dienst → Ziel) und als Zonenmatrix.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::error::ApiError;
use crate::filters::{Joins, LogFilter};

#[derive(Deserialize)]
pub struct SankeyQuery {
    pub limit: Option<i64>,
    #[serde(flatten)]
    pub filter: LogFilter,
}

/// Eine (Quelle, Ziel, Dienst)-Kombination mit ihrer Zeilenzahl.
struct FlowRow {
    src: String,
    dst: String,
    service: String,
    cnt: i64,
    blocked: i64,
}

/// Die Schlüssel, deren Summe unter den `top` Werten liegt, fallen unter
/// `__other__` — der Sammelknoten "Weitere" dieser Spalte.
fn top_keys(volume: &HashMap<String, i64>, limit: usize) -> HashSet<String> {
    let mut sorted: Vec<(&str, i64)> = volume.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    sorted.into_iter().take(limit).map(|(k, _)| k.to_string()).collect()
}

fn resolve(key: &str, top: &HashSet<String>) -> String {
    if top.contains(key) { key.to_string() } else { "__other__".to_string() }
}

/// Baut die Knoten einer Spalte: die begrenzten Schlüssel nach Volumen
/// sortiert, plus ein Sammelknoten am Ende, falls etwas kollabiert wurde.
fn column_keys(volume: &HashMap<String, i64>, top: &HashSet<String>) -> Vec<String> {
    let mut entries: Vec<(String, i64)> = top.iter().map(|k| (k.clone(), volume[k])).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut keys: Vec<String> = entries.into_iter().map(|(k, _)| k).collect();
    if volume.len() > top.len() {
        keys.push("__other__".to_string());
    }
    keys
}

/// Fügt eine Spalte in die globale Knotenliste ein und liefert eine
/// Schlüssel→Index-Abbildung für diese Spalte.
fn push_column(nodes: &mut Vec<Value>, kind: &str, keys: &[String]) -> HashMap<String, usize> {
    let mut index = HashMap::with_capacity(keys.len());
    for key in keys {
        index.insert(key.clone(), nodes.len());
        let (id, label) = if key == "__other__" {
            (format!("{kind}:__other__"), "Weitere".to_string())
        } else {
            (format!("{kind}:{key}"), key.clone())
        };
        nodes.push(json!({ "id": id, "label": label, "kind": kind }));
    }
    index
}

/// Verkehr als Fluss über drei Spalten: Quelladresse → Dienst (Port/Protokoll)
/// → Zieladresse. Nur Firewall-Zeilen mit beiden Adressen zählen — eine
/// DNS- oder DHCP-Zeile hat kein Ziel, das man sinnvoll einzeichnen könnte.
pub async fn get_sankey(
    State(pool): State<PgPool>,
    Query(q): Query<SankeyQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(12).clamp(1, 50) as usize;

    let mut qb = sqlx::QueryBuilder::new(
        "SELECT host(l.src_ip) AS src_ip, host(l.dst_ip) AS dst_ip, l.dst_port, pr.name AS protocol,
                COUNT(*) AS cnt, COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked_cnt
         FROM logs l ",
    );
    q.filter.push_joins(&mut qb, Joins::NONE.protocols());
    q.filter.push_where(&mut qb);
    qb.push(" AND l.log_type_id = 1 AND l.src_ip IS NOT NULL AND l.dst_ip IS NOT NULL");
    qb.push(" GROUP BY l.src_ip, l.dst_ip, l.dst_port, pr.name");

    let rows = qb.build().fetch_all(&pool).await?;

    let data: Vec<FlowRow> = rows
        .iter()
        .filter_map(|r| {
            let src: Option<String> = r.get("src_ip");
            let dst: Option<String> = r.get("dst_ip");
            let (Some(src), Some(dst)) = (src, dst) else { return None };
            let port: Option<i32> = r.get("dst_port");
            let proto: Option<String> = r.get("protocol");
            let service = format!(
                "{}/{}",
                port.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                proto.unwrap_or_else(|| "?".into()),
            );
            Some(FlowRow { src, dst, service, cnt: r.get("cnt"), blocked: r.get("blocked_cnt") })
        })
        .collect();

    // Gesamtvolumen je Knoten und Spalte, als Grundlage für die Begrenzung.
    let mut src_vol: HashMap<String, i64> = HashMap::new();
    let mut svc_vol: HashMap<String, i64> = HashMap::new();
    let mut dst_vol: HashMap<String, i64> = HashMap::new();
    for d in &data {
        *src_vol.entry(d.src.clone()).or_default() += d.cnt;
        *svc_vol.entry(d.service.clone()).or_default() += d.cnt;
        *dst_vol.entry(d.dst.clone()).or_default() += d.cnt;
    }

    let top_src = top_keys(&src_vol, limit);
    let top_svc = top_keys(&svc_vol, limit);
    let top_dst = top_keys(&dst_vol, limit);

    let mut nodes: Vec<Value> = Vec::new();
    let idx_src = push_column(&mut nodes, "source", &column_keys(&src_vol, &top_src));
    let idx_svc = push_column(&mut nodes, "service", &column_keys(&svc_vol, &top_svc));
    let idx_dst = push_column(&mut nodes, "destination", &column_keys(&dst_vol, &top_dst));

    // Zeilen, die auf denselben (ggf. kollabierten) Knotenpaaren landen,
    // summieren sich zu einem Link je Sprung.
    let mut hop1: HashMap<(String, String), (i64, i64)> = HashMap::new();
    let mut hop2: HashMap<(String, String), (i64, i64)> = HashMap::new();
    for d in &data {
        let sk = resolve(&d.src, &top_src);
        let vk = resolve(&d.service, &top_svc);
        let dk = resolve(&d.dst, &top_dst);
        let e1 = hop1.entry((sk, vk.clone())).or_insert((0, 0));
        e1.0 += d.cnt;
        e1.1 += d.blocked;
        let e2 = hop2.entry((vk, dk)).or_insert((0, 0));
        e2.0 += d.cnt;
        e2.1 += d.blocked;
    }

    let mut links: Vec<Value> = Vec::with_capacity(hop1.len() + hop2.len());
    for ((sk, vk), (cnt, blocked)) in &hop1 {
        links.push(json!({
            "source": idx_src[sk], "target": idx_svc[vk], "value": cnt, "blocked": blocked,
        }));
    }
    for ((vk, dk), (cnt, blocked)) in &hop2 {
        links.push(json!({
            "source": idx_svc[vk], "target": idx_dst[dk], "value": cnt, "blocked": blocked,
        }));
    }

    Ok(Json(json!({ "nodes": nodes, "links": links })))
}

/// Die Zonenmatrix: Schnittstelle zu Schnittstelle. Zählt nur Zeilen, die
/// beide Schnittstellen kennen — eine Zeile mit nur einer bekannten Seite
/// sagt nichts über ein Zonenpaar aus.
pub async fn get_zones(
    State(pool): State<PgPool>,
    Query(f): Query<LogFilter>,
) -> Result<Json<Value>, ApiError> {
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT ii.name AS iface_in, io.name AS iface_out,
                COUNT(*) FILTER (WHERE l.rule_action_id = 1) AS allowed,
                COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
         FROM logs l ",
    );
    f.push_joins(&mut qb, Joins::NONE.interfaces());
    f.push_where(&mut qb);
    qb.push(" AND l.iface_in_id IS NOT NULL AND l.iface_out_id IS NOT NULL");
    qb.push(" GROUP BY ii.name, io.name");

    let rows = qb.build().fetch_all(&pool).await?;

    let mut zones: BTreeSet<String> = BTreeSet::new();
    let mut cells = Vec::with_capacity(rows.len());
    for r in &rows {
        let from: Option<String> = r.get("iface_in");
        let to: Option<String> = r.get("iface_out");
        let (Some(from), Some(to)) = (from, to) else { continue };
        let allowed: i64 = r.get("allowed");
        let blocked: i64 = r.get("blocked");
        zones.insert(from.clone());
        zones.insert(to.clone());
        cells.push(json!({ "from": from, "to": to, "allowed": allowed, "blocked": blocked }));
    }

    Ok(Json(json!({ "zones": zones.into_iter().collect::<Vec<_>>(), "cells": cells })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get_json(pool: sqlx::PgPool, uri: &str) -> Value {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "bei {uri}");
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap()).unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn empty_database_returns_empty_sankey(pool: sqlx::PgPool) {
        let body = get_json(pool, "/api/flows/sankey").await;
        assert_eq!(body["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(body["links"].as_array().unwrap().len(), 0);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn empty_database_returns_empty_zones(pool: sqlx::PgPool) {
        let body = get_json(pool, "/api/flows/zones").await;
        assert_eq!(body["zones"].as_array().unwrap().len(), 0);
        assert_eq!(body["cells"].as_array().unwrap().len(), 0);
    }

    /// Legt `n` firewall-Zeilen mit unterschiedlichen Quelladressen an, alle
    /// zum selben Ziel/Dienst, damit sich die Quellspalte isoliert prüfen lässt.
    async fn seed_many_sources(pool: &sqlx::PgPool, n: u8, first_action: i16) {
        for i in 0..n {
            let addr = format!("10.0.0.{}", i + 1);
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_ip, dst_port)
                 VALUES (NOW(), 1, $1, $2::inet, '8.8.8.8', 443)",
            )
            .bind(if i == 0 { first_action } else { 1i16 })
            .bind(addr)
            .execute(pool)
            .await
            .unwrap();
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn link_indices_are_valid_and_blocked_counts_only_blocked_rows(pool: sqlx::PgPool) {
        // 2 Zeilen derselben (Quelle, Ziel, Dienst)-Kombination, eine geblockt.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_ip, dst_port)
             VALUES (NOW(), 1, 2, '10.0.20.5', '8.8.8.8', 443)",
        ).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_ip, dst_port)
             VALUES (NOW(), 1, 1, '10.0.20.5', '8.8.8.8', 443)",
        ).execute(&pool).await.unwrap();

        let body = get_json(pool, "/api/flows/sankey").await;
        let nodes = body["nodes"].as_array().unwrap();
        let links = body["links"].as_array().unwrap();
        assert_eq!(nodes.len(), 3, "eine Quelle, ein Dienst, ein Ziel");
        assert_eq!(links.len(), 2, "ein Sprung Quelle→Dienst, einer Dienst→Ziel");

        for link in links {
            let s = link["source"].as_u64().unwrap() as usize;
            let t = link["target"].as_u64().unwrap() as usize;
            assert!(s < nodes.len(), "source-Index außerhalb von nodes");
            assert!(t < nodes.len(), "target-Index außerhalb von nodes");
        }

        // Der Sprung Quelle→Dienst zählt beide Zeilen, aber nur eine blockiert.
        let hop1 = links
            .iter()
            .find(|l| nodes[l["source"].as_u64().unwrap() as usize]["kind"] == "source")
            .unwrap();
        assert_eq!(hop1["value"], 2);
        assert_eq!(hop1["blocked"], 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_node_cap_collapses_the_remainder_into_a_single_node(pool: sqlx::PgPool) {
        seed_many_sources(&pool, 15, 2).await; // 15 Quellen, mehr als der Standard-Cap von 12
        let body = get_json(pool, "/api/flows/sankey?limit=12").await;
        let nodes = body["nodes"].as_array().unwrap();
        let links = body["links"].as_array().unwrap();

        let others: Vec<_> = nodes.iter().filter(|n| n["id"] == "source:__other__").collect();
        assert_eq!(others.len(), 1, "genau ein Sammelknoten für die Quellspalte");
        assert_eq!(others[0]["kind"], "source");
        assert_eq!(others[0]["label"], "Weitere");

        // 12 echte Quellknoten + 1 Sammelknoten
        let source_nodes: Vec<_> = nodes.iter().filter(|n| n["kind"] == "source").collect();
        assert_eq!(source_nodes.len(), 13);

        // Die Summe aller Quelle→Dienst-Sprünge bleibt trotz Kollaps bei 15 Zeilen.
        let total: i64 = links
            .iter()
            .filter(|l| nodes[l["source"].as_u64().unwrap() as usize]["kind"] == "source")
            .map(|l| l["value"].as_i64().unwrap())
            .sum();
        assert_eq!(total, 15);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn dns_rows_and_rows_without_both_addresses_are_excluded(pool: sqlx::PgPool) {
        // DNS-Zeile: kein Ziel, log_type != firewall.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, dns_query) VALUES (NOW(), 2, '10.0.0.9', 'example.com')",
        ).execute(&pool).await.unwrap();
        // Firewall-Zeile ohne Zieladresse.
        sqlx::query("INSERT INTO logs (timestamp, log_type_id, src_ip) VALUES (NOW(), 1, '10.0.0.9')")
            .execute(&pool).await.unwrap();

        let body = get_json(pool, "/api/flows/sankey").await;
        assert_eq!(body["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(body["links"].as_array().unwrap().len(), 0);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn zone_matrix_ignores_rows_missing_either_interface(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO interfaces (name) VALUES ('ppp0'), ('br20')").execute(&pool).await.unwrap();

        // Beide Schnittstellen bekannt: zählt.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, iface_in_id, iface_out_id, src_ip)
             VALUES (NOW(), 1, 1, 1, 2, '1.2.3.4')",
        ).execute(&pool).await.unwrap();
        // Nur iface_in bekannt: fällt raus.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, iface_in_id, src_ip)
             VALUES (NOW(), 1, 2, 1, '1.2.3.5')",
        ).execute(&pool).await.unwrap();
        // Nur iface_out bekannt: fällt raus.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, iface_out_id, src_ip)
             VALUES (NOW(), 1, 2, 2, '1.2.3.6')",
        ).execute(&pool).await.unwrap();

        let body = get_json(pool, "/api/flows/zones").await;
        let zones: Vec<String> =
            body["zones"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert_eq!(zones, vec!["br20", "ppp0"]);
        let cells = body["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0]["from"], "ppp0");
        assert_eq!(cells[0]["to"], "br20");
        assert_eq!(cells[0]["allowed"], 1);
        assert_eq!(cells[0]["blocked"], 0);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn zone_matrix_counts_allowed_and_blocked_separately(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO interfaces (name) VALUES ('ppp0'), ('br20')").execute(&pool).await.unwrap();
        for action in [1i16, 1, 2] {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, iface_in_id, iface_out_id, src_ip)
                 VALUES (NOW(), 1, $1, 1, 2, '1.2.3.4')",
            )
            .bind(action)
            .execute(&pool)
            .await
            .unwrap();
        }
        let body = get_json(pool, "/api/flows/zones").await;
        let cells = body["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0]["allowed"], 2);
        assert_eq!(cells[0]["blocked"], 1);
    }

    /// Der Filter gilt auch für die Aggregate: `?action=block` liefert kleinere Zahlen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_filter_applies_to_the_zone_matrix(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO interfaces (name) VALUES ('ppp0'), ('br20')").execute(&pool).await.unwrap();
        for action in [1i16, 2] {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, iface_in_id, iface_out_id, src_ip)
                 VALUES (NOW(), 1, $1, 1, 2, '1.2.3.4')",
            )
            .bind(action)
            .execute(&pool)
            .await
            .unwrap();
        }
        let body = get_json(pool, "/api/flows/zones?action=block").await;
        let cells = body["cells"].as_array().unwrap();
        assert_eq!(cells[0]["allowed"], 0);
        assert_eq!(cells[0]["blocked"], 1);
    }

    /// Eine tote Datenbank muss als Fehler ankommen, nicht als leerer Sankey.
    #[sqlx::test(migrations = "../../migrations")]
    async fn sankey_reports_a_dead_database_instead_of_hiding_it(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/flows/sankey").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Ebenso für die Zonenmatrix, nicht als leere Matrix.
    #[sqlx::test(migrations = "../../migrations")]
    async fn zones_reports_a_dead_database_instead_of_hiding_it(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/flows/zones").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
