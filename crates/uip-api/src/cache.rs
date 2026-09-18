//! Ein kurzes Gedächtnis für die Aggregate.
//!
//! Dashboard, Flow View und Threat Map stellen dieselbe Frage an dieselben
//! Millionen Zeilen, sobald jemand zwischen den Ansichten hin- und herwechselt
//! — und das Dashboard stellt beim Öffnen zehn davon auf einmal. Die Antwort
//! zwanzig Sekunden lang aufzuheben kostet ein paar Kilobyte und spart bei
//! jedem zweiten Blick den ganzen Durchgang durch die Tabelle.
//!
//! Bewusst kurz: unter der Ansicht läuft ein Live-Strom, und eine Zahl, die
//! eine halbe Minute alt ist, wäre eine andere Aussage als „jetzt". Zwanzig
//! Sekunden sind die Spanne, in der man klickt, nicht die, in der man liest.
//!
//! Als Schicht statt in jedem Endpunkt: gespeichert wird die fertige Antwort,
//! und keine Abfrage muss dafür wissen, dass es diesen Zwischenspeicher gibt.

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Wie lange eine Antwort gilt.
const TTL: Duration = Duration::from_secs(20);

/// Wie viele Antworten höchstens aufgehoben werden. Jede Filterkombination
/// bekommt einen eigenen Eintrag; ohne Obergrenze wüchse das mit jedem
/// getippten Suchbegriff.
const MAX_ENTRIES: usize = 128;

/// Größer als das wird nicht aufgehoben — der Zwischenspeicher soll Zeit
/// sparen, nicht Arbeitsspeicher kosten.
const MAX_BODY: usize = 4 << 20;

/// Die Endpunkte, deren Antworten sich lohnen: alles, was über den ganzen
/// Bestand aggregiert. Die Zeilenliste steht bewusst nicht dabei — sie ist
/// schnell, und sie soll frisch sein.
const CACHEABLE: &[&str] = &[
    "/api/stats",
    "/api/stats/series",
    "/api/stats/top",
    "/api/stats/ip-pairs",
    "/api/logs/count",
    "/api/threats/points",
    "/api/flows/sankey",
    "/api/flows/zones",
    "/api/flows/host-detail",
];

struct Entry {
    at: Instant,
    body: Bytes,
}

#[derive(Default)]
pub struct ResponseCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl ResponseCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Die Antwort auf diese Frage, sofern sie frisch genug ist.
    pub fn get(&self, key: &str) -> Option<Bytes> {
        let mut entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        if entry.at.elapsed() > TTL {
            entries.remove(key);
            return None;
        }
        Some(entry.body.clone())
    }

    pub fn put(&self, key: String, body: Bytes) {
        if body.len() > MAX_BODY {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else { return };
        // Abgelaufenes zuerst — meist ist danach wieder Platz, ohne dass etwas
        // Gültiges weichen muss.
        entries.retain(|_, e| e.at.elapsed() <= TTL);
        if entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = entries.iter().min_by_key(|(_, e)| e.at).map(|(k, _)| k.clone()) {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, Entry { at: Instant::now(), body });
    }
}

/// Der Schlüssel einer Anfrage: Pfad und roher Query-String.
///
/// Roh, nicht geparst: zwei Anfragen mit demselben Text meinen dasselbe, und
/// eine Umsortierung der Parameter kostet höchstens einen zusätzlichen
/// Eintrag. Andersherum — geparst und normalisiert — wäre jeder vergessene
/// Filter eine falsche Antwort.
fn key(path: &str, query: Option<&str>) -> String {
    format!("{path}?{}", query.unwrap_or(""))
}

pub async fn layer(State(cache): State<Arc<ResponseCache>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if req.method() != Method::GET || !CACHEABLE.contains(&path.as_str()) {
        return next.run(req).await;
    }
    let key = key(&path, req.uri().query());

    if let Some(body) = cache.get(&key) {
        return json_response(body);
    }

    let res = next.run(req).await;
    if res.status() != StatusCode::OK {
        return res;
    }
    // Die Antwort muss ohnehin ganz im Speicher stehen, um sie weiterzugeben —
    // sie dabei aufzuheben kostet nichts extra.
    let (parts, body) = res.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY).await else {
        // Zu groß zum Einsammeln: dann gibt es hier keine Antwort mehr, die
        // weitergereicht werden könnte — ein leerer Körper wäre gelogen.
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    cache.put(key, bytes.clone());
    Response::from_parts(parts, Body::from(bytes))
}

fn json_response(body: Bytes) -> Response {
    let mut res = Response::new(Body::from(body));
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_is_kept_and_found_again() {
        let cache = ResponseCache::new();
        cache.put(key("/api/stats", Some("range=24h")), Bytes::from_static(b"{\"total\":7}"));

        assert_eq!(
            cache.get(&key("/api/stats", Some("range=24h"))).as_deref(),
            Some(&b"{\"total\":7}"[..])
        );
        // Ein anderer Filter ist eine andere Frage.
        assert!(cache.get(&key("/api/stats", Some("range=1h"))).is_none());
        assert!(cache.get(&key("/api/stats/series", Some("range=24h"))).is_none());
    }

    #[test]
    fn the_oldest_answer_goes_when_it_gets_crowded() {
        let cache = ResponseCache::new();
        for i in 0..MAX_ENTRIES + 10 {
            cache.put(key("/api/stats", Some(&format!("q={i}"))), Bytes::from(i.to_string()));
        }
        let entries = cache.entries.lock().unwrap();
        assert!(entries.len() <= MAX_ENTRIES, "{} Einträge", entries.len());
    }
}
