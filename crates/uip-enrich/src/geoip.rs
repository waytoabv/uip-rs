use crate::types::{GeoSource, IpFacts};
use arc_swap::ArcSwap;
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Wie oft nachgesehen wird, ob geoipupdate neue Dateien hingelegt hat.
const RELOAD_CHECK: Duration = Duration::from_secs(300);

struct Databases {
    city: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

pub struct MaxmindGeo {
    dbs: ArcSwap<Databases>,
    city_path: Option<PathBuf>,
    asn_path: Option<PathBuf>,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok()?.modified().ok()
}

impl MaxmindGeo {
    /// Fehlende oder kaputte Dateien sind kein Fehler: dann gibt es eben
    /// kein GeoIP, und alles andere reichert weiter an.
    pub fn load(city: Option<&Path>, asn: Option<&Path>) -> anyhow::Result<Self> {
        let open = |p: Option<&Path>| -> Option<Reader<Vec<u8>>> {
            let p = p?;
            match Reader::open_readfile(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "could not open mmdb");
                    None
                }
            }
        };
        Ok(Self {
            dbs: ArcSwap::from_pointee(Databases { city: open(city), asn: open(asn) }),
            city_path: city.map(Path::to_path_buf),
            asn_path: asn.map(Path::to_path_buf),
        })
    }

    /// Aus einem Verzeichnis mit den üblichen GeoLite2-Dateinamen.
    pub fn from_dir(dir: &Path) -> anyhow::Result<Self> {
        let city = dir.join("GeoLite2-City.mmdb");
        let asn = dir.join("GeoLite2-ASN.mmdb");
        Self::load(
            city.exists().then_some(city.as_path()),
            asn.exists().then_some(asn.as_path()),
        )
    }

    fn reload(&self) {
        let open = |p: &Option<PathBuf>| -> Option<Reader<Vec<u8>>> {
            Reader::open_readfile(p.as_ref()?).ok()
        };
        self.dbs.store(Arc::new(Databases {
            city: open(&self.city_path),
            asn: open(&self.asn_path),
        }));
        tracing::info!("reloaded geoip databases");
    }
}

impl GeoSource for MaxmindGeo {
    fn lookup(&self, ip: IpAddr) -> IpFacts {
        let dbs = self.dbs.load();
        let mut f = IpFacts::default();

        if let Some(reader) = &dbs.city {
            if let Ok(Some(city)) = reader.lookup::<geoip2::City>(ip) {
                f.geo_country = city.country.as_ref().and_then(|c| c.iso_code).map(str::to_string);
                f.geo_city = city
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string());
                if let Some(loc) = &city.location {
                    f.geo_lat = loc.latitude;
                    f.geo_lon = loc.longitude;
                }
            }
        }

        if let Some(reader) = &dbs.asn {
            if let Ok(Some(asn)) = reader.lookup::<geoip2::Asn>(ip) {
                f.asn_number = asn.autonomous_system_number.map(|n| n as i32);
                f.asn_name = asn.autonomous_system_organization.map(str::to_string);
            }
        }
        f
    }
}

/// Wacht über die mtime der Dateien. Der Fork brauchte dafür SIGUSR1 zwischen
/// Update-Skript und Prozess; das hier funktioniert auch, wenn jemand die
/// Dateien von Hand tauscht.
pub async fn watch_for_updates(geo: Arc<MaxmindGeo>) {
    let mut seen = (
        geo.city_path.as_deref().and_then(mtime),
        geo.asn_path.as_deref().and_then(mtime),
    );
    loop {
        tokio::time::sleep(RELOAD_CHECK).await;
        let now = (
            geo.city_path.as_deref().and_then(mtime),
            geo.asn_path.as_deref().and_then(mtime),
        );
        if now != seen {
            seen = now;
            geo.reload();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn data_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
    }

    /// Die Testdatenbanken sind optional — ohne sie kann dieser Test nichts
    /// aussagen, aber er darf deshalb nicht die Suite rot machen.
    fn test_dbs() -> Option<MaxmindGeo> {
        let city = data_dir().join("GeoIP2-City-Test.mmdb");
        let asn = data_dir().join("GeoLite2-ASN-Test.mmdb");
        if !city.exists() || !asn.exists() { return None; }
        MaxmindGeo::load(Some(&city), Some(&asn)).ok()
    }

    #[test]
    fn reads_country_and_city_from_the_test_database() {
        let Some(geo) = test_dbs() else { eprintln!("skipped: no test mmdb"); return };
        // 2.125.160.216 liegt in MaxMinds Testdaten in GB.
        let f = geo.lookup("2.125.160.216".parse().unwrap());
        assert_eq!(f.geo_country.as_deref(), Some("GB"));
        assert!(f.geo_lat.is_some() && f.geo_lon.is_some());
    }

    /// Stadt und AS kommen aus zwei getrennten Dateien, und eine Adresse kann
    /// in der einen stehen und in der anderen fehlen — 2.125.160.216 etwa hat
    /// in den Testdaten eine Stadt, aber kein AS. Ohne eigenen Test bliebe der
    /// ASN-Zweig deshalb unbemerkt tot.
    #[test]
    fn reads_the_autonomous_system_from_its_own_database() {
        let Some(geo) = test_dbs() else { eprintln!("skipped: no test mmdb"); return };
        let f = geo.lookup("1.128.0.1".parse().unwrap());
        assert_eq!(f.asn_number, Some(1221));
        assert_eq!(f.asn_name.as_deref(), Some("Telstra Pty Ltd"));
    }

    #[test]
    fn unknown_addresses_yield_nothing_rather_than_an_error() {
        let Some(geo) = test_dbs() else { eprintln!("skipped: no test mmdb"); return };
        assert!(geo.lookup("10.0.0.1".parse().unwrap()).is_empty());
    }

    #[test]
    fn a_missing_database_is_not_a_failure() {
        let geo = MaxmindGeo::load(None, None).unwrap();
        assert!(geo.lookup("8.8.8.8".parse().unwrap()).is_empty());
    }
}
