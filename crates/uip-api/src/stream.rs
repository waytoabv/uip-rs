use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use serde::Deserialize;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

#[derive(Deserialize)]
pub struct StreamQuery {
    pub log_type: Option<String>,
}

pub fn passes_filter(json_line: &str, log_type: Option<&str>) -> bool {
    match log_type {
        None => true,
        Some(t) => json_line.contains(&format!("\"log_type\":\"{t}\"")),
    }
}

pub async fn sse_stream(
    State(events): State<tokio::sync::broadcast::Sender<String>>,
    Query(q): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(line) if passes_filter(&line, q.log_type.as_deref()) => {
            Some(Ok(Event::default().event("log").data(line)))
        }
        Ok(_) => None,
        Err(BroadcastStreamRecvError::Lagged(n)) => {
            Some(Ok(Event::default().event("lagged").data(n.to_string())))
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_filter_matches_json_line() {
        let fw = r#"{"timestamp":"t","log_type":"firewall","src_ip":"1.2.3.4"}"#;
        assert!(passes_filter(fw, Some("firewall")));
        assert!(!passes_filter(fw, Some("dns")));
        assert!(passes_filter(fw, None));
    }
}
