use uip_core::remote_ip;
use crate::types::{GeoSource, IpFacts, Quota, RdnsSource, ThreatOutcome, ThreatSource};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use sqlx::{PgPool, Row};
use tokio::sync::broadcast;
use uip_core::LiveEvent;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Wie viele Zeilen ein Durchlauf höchstens anfasst.
pub const BATCH_SIZE: i64 = 200;
/// Auch ohne Signal wird regelmäßig nachgesehen (Backfill, verpasste Notifies).
const IDLE_POLL: Duration = Duration::from_secs(2);

/// Wie alt eine Bewertung werden darf, bevor sie neu erfragt wird.
///
/// AbuseIPDB bewertet die letzten 90 Tage; zwei Wochen sind kurz genug, dass
/// eine Adresse, die auffällig geworden ist, auffällt, und lang genug, dass
/// eine ruhige Adresse nicht ständig Kontingent kostet.
const REFRESH_AFTER_DAYS: i64 = 14;

/// Wie viele Auffrischungen an einem Tag höchstens.
///
/// Eine neue Adresse ist wichtiger als eine alte Bewertung: wer heute zum
/// ersten Mal anklopft, soll bewertet werden, auch wenn zehntausend
/// gespeicherte Einträge in die Jahre kommen. Deshalb ein Deckel, und ein
/// kleiner — beim kostenlosen Kontingent von tausend Abfragen am Tag ist ein
/// Fünftel für die Pflege genug.
const DEFAULT_REFRESH_PER_DAY: u32 = 200;

/// Der Tagesvorrat an Auffrischungen.
///
/// Zählt in Tagen seit der Epoche, nicht in Stunden seit dem Start: sonst
/// verschöbe jeder Neustart den Stichtag, und ein Dienst, der oft neu startet,
/// hätte jedes Mal wieder den vollen Vorrat.
#[derive(Debug)]
pub struct RefreshBudget {
    day: std::sync::atomic::AtomicI64,
    used: std::sync::atomic::AtomicU32,
    per_day: std::sync::atomic::AtomicU32,
}

impl Default for RefreshBudget {
    fn default() -> Self {
        Self {
            day: std::sync::atomic::AtomicI64::new(0),
            used: std::sync::atomic::AtomicU32::new(0),
            per_day: std::sync::atomic::AtomicU32::new(DEFAULT_REFRESH_PER_DAY),
        }
    }
}

impl RefreshBudget {
    pub fn set_per_day(&self, n: u32) {
        self.per_day.store(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// Nimmt eine Auffrischung in Anspruch — oder lehnt ab, wenn der Tag
    /// aufgebraucht ist.
    fn take(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let today = Utc::now().timestamp().div_euclid(86_400);
        if self.day.swap(today, Relaxed) != today {
            self.used.store(0, Relaxed);
        }
        let limit = self.per_day.load(Relaxed);
        if limit == 0 {
            return false;
        }
        // Kein compare_exchange nötig: der Worker ist eine einzige Aufgabe.
        let used = self.used.load(Relaxed);
        if used >= limit {
            return false;
        }
        self.used.store(used + 1, Relaxed);
        true
    }
}

pub struct Sources {
    pub geo: Arc<dyn GeoSource>,
    pub rdns: Option<Arc<dyn RdnsSource>>,
    pub threat: Arc<dyn ThreatSource>,
    /// Ob rückwärtige Namensauflösung gerade erwünscht ist.
    ///
    /// Ein Schalter statt eines `Option`, weil der Auflöser beim Start gebaut
    /// wird, die Einstellung aber jederzeit umgelegt werden kann — ohne ihn
    /// hieße Abschalten, dass das Wiedereinschalten einen Neustart braucht.
    pub rdns_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Was heute noch an Auffrischungen übrig ist.
    pub refresh: Arc<RefreshBudget>,
}

/// Adressen, die uns selbst gehören und die niemand nachschlagen muss.
#[derive(Debug, Clone, Default)]
pub struct Exclusions(pub HashSet<IpAddr>);

impl std::ops::Deref for Exclusions {
    type Target = HashSet<IpAddr>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Eine geclaimte Zeile, bevor sie angereichert ist.
struct Claimed {
    timestamp: DateTime<Utc>,
    id: i64,
    remote: Option<IpAddr>,
    wants_threat: bool,
}

/// Nach einem Absturz können Zeilen auf "in progress" hängen bleiben. Das hier
/// setzt voraus, dass genau ein Prozess schreibt — so läuft das LXC-Deployment.
pub async fn release_stale_claims(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("UPDATE logs SET enrich_status = 0 WHERE enrich_status = 3")
        .execute(pool)
        .await?;
    let n = res.rows_affected();
    if n > 0 {
        tracing::warn!(rows = n, "released claims left behind by an earlier run");
    }
    Ok(n)
}

/// Claimt bis zu `limit` Zeilen. Das UPDATE committet sofort — die langsame
/// Arbeit darf keine Transaktion offen halten.
async fn claim(pool: &PgPool, excluded: &Exclusions, limit: i64) -> Result<Vec<Claimed>, sqlx::Error> {
    let rows = sqlx::query(
        r#"UPDATE logs SET enrich_status = 3
           WHERE (timestamp, id) IN (
               SELECT timestamp, id FROM logs
               WHERE enrich_status = 0
               ORDER BY timestamp DESC
               LIMIT $1
               FOR UPDATE SKIP LOCKED
           )
           RETURNING timestamp, id, log_type_id, direction_id, rule_action_id,
                     host(src_ip) AS src_ip, host(dst_ip) AS dst_ip"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| {
            let src: Option<String> = r.get("src_ip");
            let dst: Option<String> = r.get("dst_ip");
            let log_type_id: i16 = r.get("log_type_id");
            let direction_id: Option<i16> = r.get("direction_id");
            let remote = remote_ip(
                log_type_id,
                direction_id,
                src.and_then(|s| s.parse().ok()),
                dst.and_then(|s| s.parse().ok()),
                excluded,
            );
            Claimed {
                timestamp: r.get("timestamp"),
                id: r.get("id"),
                remote,
                // AbuseIPDB nur für blockierte Firewall-Zeilen: das freie
                // Kontingent ist klein, erlaubter Traffic braucht keinen Score.
                wants_threat: log_type_id == 1 && r.get::<Option<i16>, _>("rule_action_id") == Some(2),
            }
        })
        .collect())
}

/// Liest bekannte Fakten aus dem Cache, damit wir nichts doppelt nachschlagen.
/// Bekannte Fakten — und welche Bewertungen alt genug für eine Auffrischung
/// sind. Beides aus derselben Abfrage: der Zeitpunkt steht in derselben Zeile.
async fn cached_facts(
    pool: &PgPool,
    ips: &[IpAddr],
) -> (HashMap<IpAddr, IpFacts>, HashSet<IpAddr>) {
    let nets: Vec<IpNetwork> = ips.iter().copied().map(IpNetwork::from).collect();
    let rows = sqlx::query(
        r#"SELECT host(ip) AS ip, geo_country, geo_city, geo_lat, geo_lon,
                  asn_number, asn_name, rdns, threat_score, threat_categories,
                  abuse_total_reports, abuse_last_reported, abuse_is_tor, abuse_usage_type,
                  abuse_looked_up_at
           FROM ip_enrichment WHERE ip = ANY($1)"#,
    )
    .bind(&nets)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let cutoff = Utc::now() - chrono::Duration::days(REFRESH_AFTER_DAYS);
    let mut stale: HashSet<IpAddr> = HashSet::new();

    let facts = rows
        .iter()
        .filter_map(|r| {
            let ip: String = r.get("ip");
            let ip: IpAddr = ip.parse().ok()?;
            // Veraltet ist nur, was überhaupt eine Bewertung hat: eine Zeile
            // ohne Score wird ohnehin gefragt, die braucht keinen Vorrat.
            let checked: Option<DateTime<Utc>> = r.get("abuse_looked_up_at");
            let score: Option<i32> = r.get("threat_score");
            if score.is_some() && checked.is_none_or(|t| t < cutoff) {
                stale.insert(ip);
            }
            Some((
                ip,
                IpFacts {
                    geo_country: r.get("geo_country"),
                    geo_city: r.get("geo_city"),
                    geo_lat: r.get("geo_lat"),
                    geo_lon: r.get("geo_lon"),
                    asn_number: r.get("asn_number"),
                    asn_name: r.get("asn_name"),
                    rdns: r.get("rdns"),
                    threat_score: r.get("threat_score"),
                    threat_categories: r.get("threat_categories"),
                    abuse_total_reports: r.get("abuse_total_reports"),
                    abuse_last_reported: r.get("abuse_last_reported"),
                    abuse_is_tor: r.get("abuse_is_tor"),
                    abuse_usage_type: r.get("abuse_usage_type"),
                },
            ))
        })
        .collect();
    (facts, stale)
}

/// Hält fest, dass nachgefragt wurde — auch wenn nichts dabei herauskam.
///
/// Ohne das bliebe der alte Zeitpunkt stehen, die Adresse gälte weiter als
/// veraltet, und jeder Durchlauf verbrauchte erneut einen Platz des
/// Tagesvorrats für dieselbe Adresse.
async fn touch_abuse_checked(pool: &PgPool, ip: IpAddr) {
    let res = sqlx::query("UPDATE ip_enrichment SET abuse_looked_up_at = NOW() WHERE ip = $1")
        .bind(IpNetwork::from(ip))
        .execute(pool)
        .await;
    if let Err(e) = res {
        tracing::debug!(error = %e, %ip, "could not record the refresh attempt");
    }
}

async fn store_facts(pool: &PgPool, ip: IpAddr, f: &IpFacts) {
    let res = sqlx::query(
        r#"INSERT INTO ip_enrichment (ip, geo_country, geo_city, geo_lat, geo_lon,
              asn_number, asn_name, rdns, threat_score, threat_categories,
              abuse_total_reports, abuse_last_reported, abuse_is_tor, abuse_usage_type,
              geo_looked_up_at, rdns_looked_up_at, abuse_looked_up_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
              CASE WHEN $2 IS NULL THEN NULL ELSE NOW() END,
              CASE WHEN $8 IS NULL THEN NULL ELSE NOW() END,
              CASE WHEN $9 IS NULL THEN NULL ELSE NOW() END)
           ON CONFLICT (ip) DO UPDATE SET
              geo_country = COALESCE(EXCLUDED.geo_country, ip_enrichment.geo_country),
              geo_city = COALESCE(EXCLUDED.geo_city, ip_enrichment.geo_city),
              geo_lat = COALESCE(EXCLUDED.geo_lat, ip_enrichment.geo_lat),
              geo_lon = COALESCE(EXCLUDED.geo_lon, ip_enrichment.geo_lon),
              asn_number = COALESCE(EXCLUDED.asn_number, ip_enrichment.asn_number),
              asn_name = COALESCE(EXCLUDED.asn_name, ip_enrichment.asn_name),
              rdns = COALESCE(EXCLUDED.rdns, ip_enrichment.rdns),
              threat_score = COALESCE(EXCLUDED.threat_score, ip_enrichment.threat_score),
              threat_categories = COALESCE(EXCLUDED.threat_categories, ip_enrichment.threat_categories),
              abuse_total_reports = COALESCE(EXCLUDED.abuse_total_reports, ip_enrichment.abuse_total_reports),
              abuse_last_reported = COALESCE(EXCLUDED.abuse_last_reported, ip_enrichment.abuse_last_reported),
              abuse_is_tor = COALESCE(EXCLUDED.abuse_is_tor, ip_enrichment.abuse_is_tor),
              abuse_usage_type = COALESCE(EXCLUDED.abuse_usage_type, ip_enrichment.abuse_usage_type),
              geo_looked_up_at = COALESCE(EXCLUDED.geo_looked_up_at, ip_enrichment.geo_looked_up_at),
              rdns_looked_up_at = COALESCE(EXCLUDED.rdns_looked_up_at, ip_enrichment.rdns_looked_up_at),
              abuse_looked_up_at = COALESCE(EXCLUDED.abuse_looked_up_at, ip_enrichment.abuse_looked_up_at)"#,
    )
    .bind(IpNetwork::from(ip))
    .bind(&f.geo_country).bind(&f.geo_city).bind(f.geo_lat).bind(f.geo_lon)
    .bind(f.asn_number).bind(&f.asn_name).bind(&f.rdns)
    .bind(f.threat_score).bind(&f.threat_categories)
    .bind(f.abuse_total_reports).bind(f.abuse_last_reported)
    .bind(f.abuse_is_tor).bind(&f.abuse_usage_type)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, %ip, "could not cache ip facts");
    }
}

/// Ein Durchlauf: claimen, anreichern, zurückschreiben. Gibt zurück, wie viele
/// Zeilen angefasst wurden — 0 heißt, die Queue ist leer.
pub async fn run_once(
    pool: &PgPool,
    sources: &Sources,
    excluded: &Exclusions,
    limit: i64,
    events: Option<&broadcast::Sender<LiveEvent>>,
) -> Result<usize, sqlx::Error> {
    let claimed = claim(pool, excluded, limit).await?;
    if claimed.is_empty() {
        return Ok(0);
    }

    // Eine Adresse, ein Lookup — auch wenn sie in zweihundert Zeilen steht.
    let distinct: Vec<IpAddr> = claimed
        .iter()
        .filter_map(|c| c.remote)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let wants_threat: HashSet<IpAddr> = claimed
        .iter()
        .filter(|c| c.wants_threat)
        .filter_map(|c| c.remote)
        .collect();

    let (mut facts, stale) = cached_facts(pool, &distinct).await;
    let mut quota_ran_out = false;

    for ip in &distinct {
        let known = facts.entry(*ip).or_default();
        if known.geo_country.is_none() && known.asn_number.is_none() {
            known.merge(sources.geo.lookup(*ip));
        }
        if known.rdns.is_none() && sources.rdns_enabled.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(rdns) = &sources.rdns {
                known.rdns = rdns.lookup(*ip).await;
            }
        }
        // Eine Auffrischung nur, wenn die Adresse ohnehin gerade auftaucht,
        // ihre Bewertung alt ist und der Tagesvorrat noch reicht. `take()` hat
        // eine Wirkung, steht deshalb hinter allen anderen Bedingungen.
        let refreshing = wants_threat.contains(ip)
            && known.threat_score.is_some()
            && stale.contains(ip)
            && sources.refresh.take();

        if wants_threat.contains(ip) && (known.threat_score.is_none() || refreshing) {
            match sources.threat.lookup(*ip).await {
                // Bei einer Auffrischung ersetzen, nicht ergänzen: `merge`
                // füllt nur Leerstellen, und die Bewertung ist gerade keine —
                // der neue Wert käme sonst nie an.
                ThreatOutcome::Found(t) if refreshing => {
                    tracing::debug!(%ip, from = known.threat_score, to = t.threat_score, "refreshed");
                    known.threat_score = t.threat_score;
                    known.threat_categories = t.threat_categories;
                    known.abuse_total_reports = t.abuse_total_reports;
                    known.abuse_last_reported = t.abuse_last_reported;
                    known.abuse_is_tor = t.abuse_is_tor;
                    known.abuse_usage_type = t.abuse_usage_type;
                }
                ThreatOutcome::Found(t) => known.merge(t),
                ThreatOutcome::QuotaExhausted => quota_ran_out = true,
                ThreatOutcome::NotFound | ThreatOutcome::Disabled => {
                    if refreshing {
                        touch_abuse_checked(pool, *ip).await;
                    }
                }
            }
        }
        if !known.is_empty() {
            let snapshot = known.clone();
            store_facts(pool, *ip, &snapshot).await;
        }
    }

    write_back(pool, &claimed, &facts, quota_ran_out, &wants_threat).await?;
    announce(events, &facts);
    Ok(claimed.len())
}

/// Reicht nach, was gerade herausgefunden wurde.
///
/// Die Zeile ging an offene Ströme, bevor es diese Angaben gab — wer zusieht,
/// hat sie mit leerem Land und leerer ASN vor sich und bekäme sie nie gefüllt.
/// Bezug ist die Adresse, nicht die Zeile: dieselbe Auskunft gilt für jede
/// Zeile, in der sie vorkommt, und spart je Durchlauf hunderte Ereignisse.
fn announce(events: Option<&broadcast::Sender<LiveEvent>>, facts: &HashMap<IpAddr, IpFacts>) {
    let Some(events) = events else { return };
    for (ip, f) in facts {
        if f.is_empty() {
            continue;
        }
        let _ = events.send(LiveEvent::Enriched(Arc::new(uip_core::Enrichment {
            ip: *ip,
            geo_country: f.geo_country.clone(),
            geo_city: f.geo_city.clone(),
            geo_lat: f.geo_lat,
            geo_lon: f.geo_lon,
            asn_number: f.asn_number,
            asn_name: f.asn_name.clone(),
            rdns: f.rdns.clone(),
            threat_score: f.threat_score,
            threat_categories: f.threat_categories.clone(),
            abuse_is_tor: f.abuse_is_tor,
        })));
    }
}

/// Schreibt die Ergebnisse in einem einzigen UPDATE zurück.
///
/// `threat_categories` fährt separat: es ist die einzige Spalte, die ein
/// `TEXT[]` je Zeile trägt, und PostgreSQL kennt keine gezackten
/// mehrdimensionalen Arrays. Ein `$n::text[][]`-Bind über Zeilen mit
/// unterschiedlich langen Kategorie-Listen schlägt zur Laufzeit fehl
/// ("multidimensional arrays must have array expressions with matching
/// dimensions"), sobald zwei Zeilen unterschiedlich viele Kategorien haben.
/// Deshalb: erst das Haupt-UPDATE ohne `cats`, danach für die wenigen Zeilen,
/// die tatsächlich Kategorien haben, je ein eigenes UPDATE — jede Liste geht
/// einzeln als gewöhnliches `text[]` durch, kein `[][]` nötig. Das sind pro
/// Batch nur die geblockten, tatsächlich als Bedrohung erkannten Zeilen, also
/// wenige — eine Schleife statt eines Bulk-UNNESTs kostet hier nichts.
async fn write_back(
    pool: &PgPool,
    claimed: &[Claimed],
    facts: &HashMap<IpAddr, IpFacts>,
    quota_ran_out: bool,
    wants_threat: &HashSet<IpAddr>,
) -> Result<(), sqlx::Error> {
    let empty = IpFacts::default();
    let mut ts = Vec::with_capacity(claimed.len());
    let mut ids = Vec::with_capacity(claimed.len());
    let mut status = Vec::with_capacity(claimed.len());
    let (mut country, mut city, mut lat, mut lon) = (vec![], vec![], vec![], vec![]);
    let (mut asn_n, mut asn_name, mut rdns, mut score) = (vec![], vec![], vec![], vec![]);
    let (mut reports, mut last_rep, mut tor, mut usage) = (vec![], vec![], vec![], vec![]);
    // Getrennt: nur Zeilen mit Kategorien, je eine (timestamp, id, categories).
    let mut with_categories: Vec<(DateTime<Utc>, i64, Vec<String>)> = Vec::new();

    for c in claimed {
        let f = c.remote.and_then(|ip| facts.get(&ip)).unwrap_or(&empty);
        // Kontingent alle? Dann bleibt genau diese Zeile in der Queue, damit
        // der Score nachgereicht werden kann.
        let pending_again = quota_ran_out
            && c.wants_threat
            && c.remote.map(|ip| wants_threat.contains(&ip)).unwrap_or(false)
            && f.threat_score.is_none();
        ts.push(c.timestamp);
        ids.push(c.id);
        status.push(if pending_again { 0i16 } else { 1i16 });
        country.push(f.geo_country.clone());
        city.push(f.geo_city.clone());
        lat.push(f.geo_lat);
        lon.push(f.geo_lon);
        asn_n.push(f.asn_number);
        asn_name.push(f.asn_name.clone());
        rdns.push(f.rdns.clone());
        score.push(f.threat_score);
        reports.push(f.abuse_total_reports);
        last_rep.push(f.abuse_last_reported);
        tor.push(f.abuse_is_tor);
        usage.push(f.abuse_usage_type.clone());

        if let Some(cats) = &f.threat_categories {
            if !cats.is_empty() {
                with_categories.push((c.timestamp, c.id, cats.clone()));
            }
        }
    }

    sqlx::query(
        r#"UPDATE logs l SET
             enrich_status = u.status,
             geo_country = u.country,
             geo_city = u.city,
             geo_lat = u.lat::numeric,
             geo_lon = u.lon::numeric,
             asn_number = u.asn_number,
             asn_name = u.asn_name,
             rdns = u.rdns,
             threat_score = u.score,
             abuse_total_reports = u.reports,
             abuse_last_reported = u.last_rep,
             abuse_is_tor = u.tor,
             abuse_usage_type = u.usage
           FROM UNNEST($1::timestamptz[], $2::bigint[], $3::smallint[], $4::text[],
                       $5::text[], $6::float8[], $7::float8[], $8::int[], $9::text[],
                       $10::text[], $11::int[], $12::int[],
                       $13::timestamptz[], $14::bool[], $15::text[])
             AS u(ts, id, status, country, city, lat, lon, asn_number, asn_name,
                  rdns, score, reports, last_rep, tor, usage)
           WHERE l.timestamp = u.ts AND l.id = u.id"#,
    )
    .bind(&ts).bind(&ids).bind(&status).bind(&country)
    .bind(&city).bind(&lat).bind(&lon).bind(&asn_n).bind(&asn_name)
    .bind(&rdns).bind(&score).bind(&reports)
    .bind(&last_rep).bind(&tor).bind(&usage)
    .execute(pool)
    .await?;

    for (timestamp, id, cats) in &with_categories {
        sqlx::query(
            "UPDATE logs SET threat_categories = $3 WHERE timestamp = $1 AND id = $2",
        )
        .bind(timestamp)
        .bind(id)
        .bind(cats)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Dauerläufer: arbeitet die Queue leer, wartet dann auf ein Signal vom
/// Writer oder auf den Timer.
/// Übernimmt, was im Einstellungs-Dialog steht — bei jedem Durchlauf.
///
/// Zwei Werte betreffen die Anreicherung unmittelbar: der AbuseIPDB-Schlüssel
/// und der Schalter für die rückwärtige Namensauflösung. Beide sind billig zu
/// lesen, und die Alternative wäre, den Dienst neu starten zu lassen.
async fn apply_settings(pool: &PgPool, sources: &Sources) {
    let text = |v: Option<serde_json::Value>| {
        v.and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
    };
    sources
        .threat
        .set_api_key(&text(uip_core::settings::get_config(pool, "abuseipdb_api_key").await));

    // Fehlt der Eintrag, gilt dieselbe Vorgabe wie in `uip_core::Settings`.
    let enabled = uip_core::settings::get_config(pool, "rdns_enabled")
        .await
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    sources.rdns_enabled.store(enabled, std::sync::atomic::Ordering::Relaxed);

    // 0 schaltet die Auffrischung ab, ohne dass jemand Code ändern muss.
    let per_day = uip_core::settings::get_config(pool, "abuseipdb_refresh_per_day")
        .await
        .and_then(|v| v.as_i64())
        .filter(|n| (0..=100_000).contains(n))
        .map(|n| n as u32)
        .unwrap_or(DEFAULT_REFRESH_PER_DAY);
    sources.refresh.set_per_day(per_day);
}

/// Hält den Kontingentstand dort fest, wo die API ihn findet.
///
/// `system_config` ist der Kanal, den Ingest, Anreicherung und API sich ohnehin
/// teilen; ein eigener Zustand im Router hieße, ihn durch jeden Konstruktor zu
/// fädeln.
async fn persist_quota(pool: &PgPool, q: Quota) {
    // -1 und 0 heißen „nicht bekannt" und dürfen nicht als Zahl durchgereicht
    // werden: die Leiste soll „987" zeigen können, ohne „von -1" daneben.
    let opt = |n: i64, unknown: i64| (n != unknown).then_some(n);
    uip_core::settings::put_config(
        pool,
        "abuseipdb_quota",
        serde_json::json!({
            "remaining": q.remaining,
            "limit": opt(q.limit, -1),
            "reset_at": opt(q.reset_at, 0).map(unix_to_rfc3339),
            "paused_until": opt(q.paused_until, 0).map(unix_to_rfc3339),
            "checked_at": Utc::now().to_rfc3339(),
        }),
    )
    .await;
}

/// Unix-Sekunden als RFC-3339 — die API reicht Zeitpunkte nirgends als Zahl
/// heraus, und die Oberfläche soll sie nicht selbst umrechnen müssen.
fn unix_to_rfc3339(secs: i64) -> String {
    DateTime::from_timestamp(secs, 0).unwrap_or_else(Utc::now).to_rfc3339()
}

pub async fn run_worker(
    pool: PgPool,
    sources: Sources,
    excluded: Exclusions,
    wake: Arc<tokio::sync::Notify>,
    events: Option<broadcast::Sender<LiveEvent>>,
) {
    if let Err(e) = release_stale_claims(&pool).await {
        tracing::error!(error = %e, "could not release stale claims at startup");
    }
    // Das zuletzt in `system_config` geschriebene Kontingent. Die Oberfläche
    // liest es von dort, weil sie an die Quelle selbst nicht herankommt — und
    // geschrieben wird nur, wenn sich der Wert ändert: sonst wäre es ein
    // Schreibvorgang je Durchlauf für eine Zahl, die sich selten bewegt.
    let mut last_quota: Option<Quota> = None;
    loop {
        // Die Einstellungen können sich jederzeit ändern; sie nur beim Start zu
        // lesen hieße, dass ein im Dialog eingetragener Schlüssel erst nach
        // einem Neustart wirkt.
        apply_settings(&pool, &sources).await;
        if let Some(q) = sources.threat.quota() {
            if last_quota != Some(q) {
                persist_quota(&pool, q).await;
                last_quota = Some(q);
            }
        }
        match run_once(&pool, &sources, &excluded, BATCH_SIZE, events.as_ref()).await {
            Ok(0) => {
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(IDLE_POLL) => {}
                }
            }
            Ok(n) => tracing::debug!(rows = n, "enriched batch"),
            Err(e) => {
                tracing::error!(error = %e, "enrichment run failed");
                tokio::time::sleep(IDLE_POLL).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GeoSource, IpFacts, RdnsSource, ThreatOutcome, ThreatSource};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct FakeGeo { calls: AtomicUsize }
    #[async_trait::async_trait]
    impl GeoSource for FakeGeo {
        fn lookup(&self, _ip: IpAddr) -> IpFacts {
            self.calls.fetch_add(1, Ordering::SeqCst);
            IpFacts { geo_country: Some("US".into()), asn_number: Some(15169), ..Default::default() }
        }
    }

    struct FakeRdns;
    #[async_trait::async_trait]
    impl RdnsSource for FakeRdns {
        async fn lookup(&self, _ip: IpAddr) -> Option<String> { Some("dns.example.".into()) }
    }

    struct FakeThreat { outcome: ThreatOutcome }
    #[async_trait::async_trait]
    impl ThreatSource for FakeThreat {
        async fn lookup(&self, _ip: IpAddr) -> ThreatOutcome { self.outcome.clone() }
    }

    fn sources(threat: ThreatOutcome) -> (Arc<FakeGeo>, Sources) {
        let geo = Arc::new(FakeGeo { calls: AtomicUsize::new(0) });
        let s = Sources {
            geo: geo.clone(),
            rdns: Some(Arc::new(FakeRdns)),
            threat: Arc::new(FakeThreat { outcome: threat }),
            rdns_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            refresh: Arc::new(RefreshBudget::default()),
        };
        (geo, s)
    }

    async fn insert_row(pool: &sqlx::PgPool, log_type: i16, direction: Option<i16>, action: Option<i16>, src: &str) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, direction_id, rule_action_id, src_ip, dst_ip)
             VALUES (NOW(), $1, $2, $3, $4::text::inet, '10.0.0.5')",
        ).bind(log_type).bind(direction).bind(action).bind(src)
        .execute(pool).await.unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn enriches_a_pending_row(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        let (_, s) = sources(ThreatOutcome::Found(IpFacts { threat_score: Some(77), ..Default::default() }));

        let n = run_once(&pool, &s, &Default::default(), 100, None).await.unwrap();
        assert_eq!(n, 1);

        let (status, country, rdns, score): (i16, Option<String>, Option<String>, Option<i32>) =
            sqlx::query_as("SELECT enrich_status, geo_country, rdns, threat_score FROM logs LIMIT 1")
                .fetch_one(&pool).await.unwrap();
        assert_eq!(status, 1);
        assert_eq!(country.as_deref(), Some("US"));
        assert_eq!(rdns.as_deref(), Some("dns.example."));
        assert_eq!(score, Some(77));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rows_without_a_remote_address_are_done_immediately(pool: sqlx::PgPool) {
        insert_row(&pool, 3, None, None, "192.168.1.50").await; // dhcp
        let (geo, s) = sources(ThreatOutcome::NotFound);

        let n = run_once(&pool, &s, &Default::default(), 100, None).await.unwrap();
        assert_eq!(n, 1);

        let status: i16 = sqlx::query_scalar("SELECT enrich_status FROM logs LIMIT 1")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(status, 1);
        assert_eq!(geo.calls.load(Ordering::SeqCst), 0, "keine Quelle darf befragt worden sein");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_lookup_per_distinct_address(pool: sqlx::PgPool) {
        for _ in 0..5 { insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await; }
        insert_row(&pool, 1, Some(1), Some(2), "1.1.1.1").await;
        let (geo, s) = sources(ThreatOutcome::NotFound);

        let n = run_once(&pool, &s, &Default::default(), 100, None).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(geo.calls.load(Ordering::SeqCst), 2, "zwei verschiedene Adressen, zwei Lookups");
    }

    /// Die Zeile ging an offene Ströme, bevor Land und ASN feststanden. Ohne
    /// Nachtrag bliebe sie dort für immer leer — angereichert wird sie ja nur
    /// in der Datenbank, nicht auf dem Schirm.
    #[sqlx::test(migrations = "../../migrations")]
    async fn enrichment_is_announced_for_the_address(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        let (_geo, sources) = sources(ThreatOutcome::NotFound);
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);

        run_once(&pool, &sources, &Exclusions::default(), 100, Some(&tx)).await.unwrap();

        let LiveEvent::Enriched(facts) = rx.try_recv().expect("ein Nachtrag") else {
            panic!("ein Nachtrag, keine Zeile");
        };
        assert_eq!(facts.ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(facts.geo_country.as_deref(), Some("US"));
        assert_eq!(facts.asn_number, Some(15169));
    }

    /// Eine Adresse, über die nichts herauskam, wird nicht angekündigt — sonst
    /// liefe bei rein internem Verkehr ein leeres Ereignis je Zeile mit.
    #[sqlx::test(migrations = "../../migrations")]
    async fn nothing_learned_means_nothing_announced(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(4), Some(1), "10.0.0.5").await;
        let (_geo, sources) = sources(ThreatOutcome::NotFound);
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);

        run_once(&pool, &sources, &Exclusions::default(), 100, Some(&tx)).await.unwrap();
        assert!(rx.try_recv().is_err(), "keine Gegenstelle, kein Nachtrag");
    }

    /// Eine gespeicherte Bewertung altert. Taucht die Adresse wieder auf und
    /// ist ihr Eintrag alt genug, wird neu gefragt — und der neue Wert muss
    /// den alten *ersetzen*, nicht bloß Lücken füllen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_old_score_is_asked_again_and_replaced(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO ip_enrichment (ip, threat_score, abuse_looked_up_at)
             VALUES ('8.8.8.8', 12, NOW() - INTERVAL '30 days')",
        ).execute(&pool).await.unwrap();
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;

        let (_geo, sources) = sources(ThreatOutcome::Found(IpFacts {
            threat_score: Some(93),
            ..Default::default()
        }));
        run_once(&pool, &sources, &Exclusions::default(), 100, None).await.unwrap();

        let (score, checked): (Option<i32>, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT threat_score, abuse_looked_up_at FROM ip_enrichment WHERE ip = '8.8.8.8'",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(score, Some(93), "der neue Wert, nicht der alte");
        assert!(checked.unwrap() > Utc::now() - chrono::Duration::minutes(1));
    }

    /// Eine frische Bewertung wird nicht angefasst — sonst kostete jede
    /// wiederkehrende Adresse bei jedem Durchlauf eine Abfrage.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_recent_score_is_left_alone(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO ip_enrichment (ip, threat_score, abuse_looked_up_at)
             VALUES ('8.8.8.8', 12, NOW() - INTERVAL '2 days')",
        ).execute(&pool).await.unwrap();
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;

        let (_geo, sources) = sources(ThreatOutcome::Found(IpFacts {
            threat_score: Some(93),
            ..Default::default()
        }));
        run_once(&pool, &sources, &Exclusions::default(), 100, None).await.unwrap();

        let score: Option<i32> = sqlx::query_scalar(
            "SELECT threat_score FROM ip_enrichment WHERE ip = '8.8.8.8'",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(score, Some(12), "zwei Tage alt ist nicht alt");
    }

    /// Der Tagesvorrat ist der Schutz des Kontingents: zweiundvierzigtausend
    /// alte Einträge dürfen die tausend Abfragen des Tages nicht aufbrauchen,
    /// die eine neue Adresse braucht.
    #[test]
    fn the_daily_budget_runs_out_and_returns_the_next_day() {
        let budget = RefreshBudget::default();
        budget.set_per_day(2);
        assert!(budget.take());
        assert!(budget.take());
        assert!(!budget.take(), "mehr gibt es heute nicht");

        // Ein neuer Tag füllt ihn wieder auf.
        budget.day.store(0, std::sync::atomic::Ordering::Relaxed);
        assert!(budget.take());

        // Und 0 schaltet die Auffrischung ganz ab.
        budget.set_per_day(0);
        assert!(!budget.take());
    }

    /// Der Punkt der ganzen Übung: was im Einstellungs-Dialog steht, wirkt im
    /// laufenden Dienst. Vorher wurden diese Werte einmal beim Start gelesen,
    /// und eine Änderung blieb bis zum Neustart folgenlos.
    #[sqlx::test(migrations = "../../migrations")]
    async fn settings_reach_the_running_worker(pool: sqlx::PgPool) {
        let (_geo, sources) = sources(ThreatOutcome::NotFound);
        let threat = Arc::new(crate::abuseipdb::AbuseIpDb::new(String::new()));
        let sources = Sources { threat: threat.clone(), ..sources };

        assert!(!threat.enabled(), "ohne Eintrag abgeschaltet");
        uip_core::settings::put_config(&pool, "abuseipdb_api_key", "secret".into()).await;
        uip_core::settings::put_config(&pool, "rdns_enabled", false.into()).await;

        apply_settings(&pool, &sources).await;

        assert!(threat.enabled(), "der Schlüssel kam im Betrieb an");
        assert!(!sources.rdns_enabled.load(std::sync::atomic::Ordering::Relaxed));

        // Und wieder zurück, ohne Neustart.
        uip_core::settings::put_config(&pool, "abuseipdb_api_key", "".into()).await;
        uip_core::settings::put_config(&pool, "rdns_enabled", true.into()).await;
        apply_settings(&pool, &sources).await;
        assert!(!threat.enabled());
        assert!(sources.rdns_enabled.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn threat_lookups_only_for_blocked_firewall_rows(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(1), "8.8.8.8").await; // allow
        let (_, s) = sources(ThreatOutcome::Found(IpFacts { threat_score: Some(99), ..Default::default() }));

        run_once(&pool, &s, &Default::default(), 100, None).await.unwrap();

        let score: Option<i32> = sqlx::query_scalar("SELECT threat_score FROM logs LIMIT 1")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(score, None, "erlaubter Traffic kostet kein Kontingent");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn exhausted_quota_leaves_the_row_pending(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        let (_, s) = sources(ThreatOutcome::QuotaExhausted);

        run_once(&pool, &s, &Default::default(), 100, None).await.unwrap();

        let (status, country): (i16, Option<String>) =
            sqlx::query_as("SELECT enrich_status, geo_country FROM logs LIMIT 1")
                .fetch_one(&pool).await.unwrap();
        assert_eq!(status, 0, "zurück in die Queue, damit der Score nachgereicht wird");
        assert_eq!(country.as_deref(), Some("US"), "das Übrige wird trotzdem geschrieben");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn startup_releases_stale_claims(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        sqlx::query("UPDATE logs SET enrich_status = 3").execute(&pool).await.unwrap();

        release_stale_claims(&pool).await.unwrap();

        let status: i16 = sqlx::query_scalar("SELECT enrich_status FROM logs LIMIT 1")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(status, 0);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn facts_land_in_the_ip_cache(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        let (_, s) = sources(ThreatOutcome::NotFound);

        run_once(&pool, &s, &Default::default(), 100, None).await.unwrap();

        let country: Option<String> = sqlx::query_scalar(
            "SELECT geo_country FROM ip_enrichment WHERE ip = '8.8.8.8'",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(country.as_deref(), Some("US"));
    }

    /// Regressionstest für das ragged-array-Problem: zwei Zeilen mit
    /// unterschiedlich vielen Kategorien in einem Batch. Ein naives
    /// `text[][]`-Bind über beide Listen scheitert an Postgres' Verbot
    /// gezackter mehrdimensionaler Arrays — dieser Test bleibt rot, falls
    /// die Sonderbehandlung in `write_back` je wieder verschwindet.
    #[sqlx::test(migrations = "../../migrations")]
    async fn category_lists_of_different_lengths_both_land(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        insert_row(&pool, 1, Some(1), Some(2), "1.1.1.1").await;

        struct MultiThreat;
        #[async_trait::async_trait]
        impl ThreatSource for MultiThreat {
            async fn lookup(&self, ip: IpAddr) -> ThreatOutcome {
                let cats = if ip == "8.8.8.8".parse::<IpAddr>().unwrap() {
                    vec!["scanner".to_string()]
                } else {
                    vec!["scanner".to_string(), "spam".to_string(), "brute-force".to_string()]
                };
                ThreatOutcome::Found(IpFacts { threat_score: Some(50), threat_categories: Some(cats), ..Default::default() })
            }
        }

        let geo = Arc::new(FakeGeo { calls: AtomicUsize::new(0) });
        let s = Sources {
            geo,
            rdns: Some(Arc::new(FakeRdns)),
            threat: Arc::new(MultiThreat),
            rdns_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            refresh: Arc::new(RefreshBudget::default()),
        };

        let n = run_once(&pool, &s, &Default::default(), 100, None).await.unwrap();
        assert_eq!(n, 2);

        let mut rows: Vec<(String, Option<Vec<String>>)> = sqlx::query_as(
            "SELECT host(src_ip), threat_categories FROM logs ORDER BY host(src_ip)",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        rows.sort_by(|a, b| a.0.cmp(&b.0));

        let short = rows.iter().find(|(ip, _)| ip == "8.8.8.8").unwrap();
        let long = rows.iter().find(|(ip, _)| ip == "1.1.1.1").unwrap();
        assert_eq!(short.1, Some(vec!["scanner".to_string()]));
        assert_eq!(
            long.1,
            Some(vec!["scanner".to_string(), "spam".to_string(), "brute-force".to_string()])
        );
    }
}
