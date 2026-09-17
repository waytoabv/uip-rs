//! Die GeoLite2-Datenbanken, direkt von MaxMind geholt.
//!
//! Vorher lag das bei `geoipupdate` und einem systemd-Timer. Das hatte zwei
//! Folgen, die beide unangenehm waren: die Zugangsdaten mussten beim
//! Installieren bekannt sein — wer sie später bekam, hatte keinen Weg mehr in
//! die Anwendung hinein —, und der Termin des nächsten Laufs stand in einer
//! Datei, die die App nicht liest, also musste sie ihn nachbauen und raten.
//!
//! Jetzt macht sie es selbst: Zugangsdaten stehen in den Einstellungen wie
//! jeder andere Schlüssel auch, und der nächste Lauf ist ein beobachteter
//! Zeitpunkt statt einer Behauptung.
//!
//! Das Verfahren ist MaxMinds „direct download"
//! (<https://dev.maxmind.com/geoip/updating-databases>): Basic Auth mit
//! Account-Id und Lizenzschlüssel, ein `.tar.gz` je Ausgabe. Vor jedem Laden
//! eine HEAD-Anfrage — die verrät über `Last-Modified` den Baustand und zählt
//! ausdrücklich nicht gegen das tägliche Download-Kontingent.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::geoip::MaxmindGeo;

const BASE_URL: &str = "https://download.maxmind.com/geoip/databases";

/// Was wir holen. Die Namen sind zugleich die Dateinamen, die `geoip.rs` sucht.
pub const EDITIONS: [&str; 2] = ["GeoLite2-City", "GeoLite2-ASN"];

/// GeoLite2 erscheint zweimal pro Woche. Täglich nachsehen ist reichlich und
/// kostet dank HEAD nichts vom Download-Kontingent.
const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// Nach einem Fehlschlag früher wieder versuchen — aber nicht in einer engen
/// Schleife, sonst steht bei einem falschen Schlüssel die Sperre von MaxMind
/// als Nächstes an.
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// Solange keine Zugangsdaten hinterlegt sind, wird nur nachgesehen, ob
/// inzwischen welche da sind. Eine Minute, weil das der Weg vom Eintippen im
/// Einstellungs-Dialog bis zum ersten Download ist.
const UNCONFIGURED_POLL: Duration = Duration::from_secs(60);

/// Vorgabe wie in `uip_core::Settings` — dieselbe Zeichenkette, damit ein
/// leeres `geoip_dir` hier und dort dasselbe bedeutet.
const DEFAULT_DIR: &str = "/var/lib/uip/geoip";

pub struct Maxmind {
    account_id: String,
    license_key: String,
    dir: PathBuf,
    http: reqwest::Client,
}

/// Was ein Durchlauf ergeben hat, je Ausgabe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Heruntergeladen und ersetzt; der Baustand.
    Updated(DateTime<Utc>),
    /// Der Baustand bei MaxMind ist nicht neuer als das, was hier liegt.
    UpToDate(DateTime<Utc>),
}

impl Maxmind {
    pub fn new(account_id: String, license_key: String, dir: PathBuf) -> Self {
        Self {
            account_id,
            license_key,
            dir,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("reqwest client"),
        }
    }

    fn url(&self, edition: &str) -> String {
        format!("{BASE_URL}/{edition}/download?suffix=tar.gz")
    }

    fn target(&self, edition: &str) -> PathBuf {
        self.dir.join(format!("{edition}.mmdb"))
    }

    /// Der Baustand bei MaxMind, ohne die Datei zu holen.
    async fn build_date(&self, edition: &str) -> anyhow::Result<Option<DateTime<Utc>>> {
        let res = self
            .http
            .head(self.url(edition))
            .basic_auth(&self.account_id, Some(&self.license_key))
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("HEAD {edition}: {}", res.status());
        }
        let Some(raw) = res.headers().get(reqwest::header::LAST_MODIFIED) else {
            return Ok(None);
        };
        let parsed = DateTime::parse_from_rfc2822(raw.to_str()?)?;
        Ok(Some(parsed.with_timezone(&Utc)))
    }

    /// Der Baustand der Datei, die hier schon liegt.
    fn local_date(&self, edition: &str) -> Option<DateTime<Utc>> {
        std::fs::metadata(self.target(edition)).ok()?.modified().ok().map(Into::into)
    }

    /// Holt eine Ausgabe, wenn MaxMind eine neuere hat.
    pub async fn update(&self, edition: &str) -> anyhow::Result<Outcome> {
        let remote = self.build_date(edition).await?;
        // Ohne `Last-Modified` bleibt nur, zu laden — das ist immer noch besser
        // als eine Datenbank, die nie erneuert wird.
        if let (Some(remote), Some(local)) = (remote, self.local_date(edition)) {
            if remote <= local {
                return Ok(Outcome::UpToDate(local));
            }
        }

        let res = self
            .http
            .get(self.url(edition))
            .basic_auth(&self.account_id, Some(&self.license_key))
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("GET {edition}: {}", res.status());
        }
        let body = res.bytes().await?;

        // Auspacken und schreiben ist blockierende Arbeit — sie gehört nicht in
        // den Reaktor, sonst steht währenddessen der Rest des Dienstes.
        let target = self.target(edition);
        let dir = self.dir.clone();
        let edition = edition.to_string();
        tokio::task::spawn_blocking(move || extract_mmdb(&body, &dir, &target, &edition)).await??;

        Ok(Outcome::Updated(remote.unwrap_or_else(Utc::now)))
    }
}

/// Zieht die `.mmdb` aus dem Tarball und legt sie an ihren Platz.
///
/// Erst daneben schreiben, dann umbenennen: ein abgebrochener Download darf
/// keine halbe Datenbank hinterlassen, die der Leser beim nächsten Start
/// aufzumachen versucht. `rename` innerhalb desselben Verzeichnisses ist der
/// einzige Schritt, den das Dateisystem als Ganzes ausführt.
fn extract_mmdb(
    body: &[u8],
    dir: &Path,
    target: &Path,
    edition: &str,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(body));

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.extension().is_none_or(|e| e != "mmdb") {
            continue;
        }
        let tmp = dir.join(format!(".{edition}.mmdb.part"));
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, target)?;
        return Ok(());
    }
    anyhow::bail!("{edition}: kein .mmdb im Archiv")
}

/// Hält den Stand dort fest, wo `/api/status` ihn findet.
async fn record(
    pool: &PgPool,
    editions: &serde_json::Map<String, serde_json::Value>,
    error: Option<String>,
    next_check: DateTime<Utc>,
) {
    uip_core::settings::put_config(
        pool,
        "maxmind_status",
        serde_json::json!({
            "checked_at": Utc::now().to_rfc3339(),
            "next_check": next_check.to_rfc3339(),
            "editions": editions,
            "error": error,
        }),
    )
    .await;
}

/// Die Zugangsdaten, wie sie gerade in den Einstellungen stehen.
async fn credentials(pool: &PgPool) -> Option<(String, String, PathBuf)> {
    let text = |v: Option<serde_json::Value>| {
        v.and_then(|v| v.as_str().map(str::to_string)).filter(|s| !s.is_empty())
    };
    let account = text(uip_core::settings::get_config(pool, "maxmind_account_id").await)?;
    let key = text(uip_core::settings::get_config(pool, "maxmind_license_key").await)?;
    let dir = text(uip_core::settings::get_config(pool, "geoip_dir").await)
        .unwrap_or_else(|| DEFAULT_DIR.to_string());
    Some((account, key, PathBuf::from(dir)))
}

/// Prüft beim Start und danach täglich, ob es neue Datenbanken gibt.
///
/// Die Zugangsdaten werden bei *jedem* Durchlauf frisch gelesen, nicht einmal
/// beim Start. Das ist der Unterschied zwischen „im Dialog eintragen wirkt"
/// und „im Dialog eintragen wirkt nach einem Neustart" — und bis hierher war
/// es Letzteres: wer den Schlüssel nachträglich hinterlegte, bekam nie eine
/// Datenbank, weil die Aufgabe beim Start mangels Zugangsdaten gar nicht erst
/// angelegt wurde.
///
/// `geo` wird nach einem erfolgreichen Download neu geladen, damit die
/// Anreicherung die frischen Dateien sofort benutzt, statt bis zum nächsten
/// Neustart mit den alten weiterzuarbeiten.
pub async fn run_updater(pool: PgPool, geo: Arc<MaxmindGeo>) {
    loop {
        let Some((account, key, dir)) = credentials(&pool).await else {
            tokio::time::sleep(UNCONFIGURED_POLL).await;
            continue;
        };
        let client = Maxmind::new(account, key, dir);
        let mut editions = serde_json::Map::new();
        let mut failure: Option<String> = None;
        let mut any_new = false;

        for edition in EDITIONS {
            match client.update(edition).await {
                Ok(Outcome::Updated(built)) => {
                    any_new = true;
                    tracing::info!(edition, %built, "downloaded a fresh geolite2 database");
                    editions.insert(edition.into(), built.to_rfc3339().into());
                }
                Ok(Outcome::UpToDate(built)) => {
                    editions.insert(edition.into(), built.to_rfc3339().into());
                }
                Err(e) => {
                    tracing::warn!(edition, error = %e, "geolite2 update failed");
                    // Der erste Fehler bleibt stehen: er ist der, der die
                    // Ursache am ehesten benennt.
                    failure.get_or_insert_with(|| format!("{edition}: {e}"));
                }
            }
        }

        if any_new {
            geo.reload();
        }

        let wait = if failure.is_some() { RETRY_AFTER } else { CHECK_EVERY };
        let next = Utc::now() + ChronoDuration::from_std(wait).unwrap_or(ChronoDuration::hours(24));
        record(&pool, &editions, failure, next).await;
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use std::io::Write;

    /// Baut ein Archiv, wie MaxMind es ausliefert: ein Verzeichnis mit
    /// Datumsstempel, darin die Datenbank neben Beipackzetteln.
    fn tarball(edition: &str, contents: &[u8]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let mut add = |name: &str, data: &[u8]| {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, data).unwrap();
        };
        add(&format!("{edition}_20260917/COPYRIGHT.txt"), b"(c) MaxMind");
        add(&format!("{edition}_20260917/{edition}.mmdb"), contents);
        let inner = tar.into_inner().unwrap();

        let mut gz = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&inner).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn the_database_is_picked_out_of_the_archive() {
        let dir = std::env::temp_dir().join(format!("uip-mm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("GeoLite2-City.mmdb");

        let gz = tarball("GeoLite2-City", b"pretend this is a database");
        extract_mmdb(&gz, &dir, &target, "GeoLite2-City").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"pretend this is a database");
        // Der Beipackzettel gehört nicht dorthin, und die Teildatei ist weg.
        assert!(!dir.join("COPYRIGHT.txt").exists());
        assert!(!dir.join(".GeoLite2-City.mmdb.part").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ein Archiv ohne Datenbank darf nicht stillschweigend eine leere Datei
    /// hinterlassen — dann läge dort etwas, das der Leser für eine Datenbank
    /// hält.
    #[test]
    fn an_archive_without_a_database_is_an_error() {
        let dir = std::env::temp_dir().join(format!("uip-mm-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("GeoLite2-ASN.mmdb");

        let mut tar = tar::Builder::new(Vec::new());
        let data = b"nothing useful";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "GeoLite2-ASN_20260917/README.txt", &data[..]).unwrap();
        let mut gz = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar.into_inner().unwrap()).unwrap();

        let err = extract_mmdb(&gz.finish().unwrap(), &dir, &target, "GeoLite2-ASN").unwrap_err();
        assert!(err.to_string().contains("kein .mmdb"), "{err}");
        assert!(!target.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Der eigentliche Fehler, den das hier behebt: die Zugangsdaten kamen
    /// über den Einstellungs-Dialog, gelesen wurden sie aber nur beim Start.
    /// Wer sie nachtrug, bekam nie eine Datenbank. Also muss jeder Durchlauf
    /// sie frisch aus der Datenbank holen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn credentials_are_read_fresh_and_not_captured_at_startup(pool: sqlx::PgPool) {
        assert!(credentials(&pool).await.is_none(), "ohne Eintrag kein Abruf");

        uip_core::settings::put_config(&pool, "maxmind_account_id", "1395678".into()).await;
        assert!(credentials(&pool).await.is_none(), "die Account-Id allein genügt nicht");

        uip_core::settings::put_config(&pool, "maxmind_license_key", "secret".into()).await;
        let (account, key, dir) = credentials(&pool).await.expect("jetzt vollständig");
        assert_eq!((account.as_str(), key.as_str()), ("1395678", "secret"));
        assert_eq!(dir, PathBuf::from(DEFAULT_DIR), "ohne eigenes Verzeichnis die Vorgabe");

        // Ein leerer Schlüssel ist kein Schlüssel — sonst liefe jeder Abruf in
        // eine 401 statt einfach zu warten.
        uip_core::settings::put_config(&pool, "maxmind_license_key", "".into()).await;
        assert!(credentials(&pool).await.is_none());

        uip_core::settings::put_config(&pool, "maxmind_license_key", "secret".into()).await;
        uip_core::settings::put_config(&pool, "geoip_dir", "/srv/geo".into()).await;
        assert_eq!(credentials(&pool).await.unwrap().2, PathBuf::from("/srv/geo"));
    }

    /// Die URL ist die aus der Doku — Tippfehler darin fielen sonst erst im
    /// Betrieb auf, als 404 gegen einen echten Schlüssel.
    #[test]
    fn the_download_url_follows_the_documented_shape() {
        let m = Maxmind::new("123456".into(), "key".into(), PathBuf::from("/tmp"));
        assert_eq!(
            m.url("GeoLite2-City"),
            "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
        );
        assert_eq!(m.target("GeoLite2-ASN"), PathBuf::from("/tmp/GeoLite2-ASN.mmdb"));
    }
}
