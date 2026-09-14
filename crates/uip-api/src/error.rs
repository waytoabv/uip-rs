use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Ein Fehler, der beim Beantworten einer Anfrage auftrat.
///
/// Wichtig ist, was hier NICHT passiert: eine fehlgeschlagene Abfrage wird
/// nicht zu einem leeren Ergebnis. Auf einem Werkzeug, das Angriffe sichtbar
/// machen soll, sähe ein Datenbankausfall sonst aus wie „nichts passiert" —
/// die beruhigendste aller Falschaussagen.
#[derive(Debug)]
pub struct ApiError(pub sqlx::Error);

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self.0, "query failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "query failed" })),
        )
            .into_response()
    }
}
