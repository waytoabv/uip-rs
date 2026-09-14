use crate::types::RdnsSource;
use hickory_resolver::{Resolver, TokioResolver};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// PTR-Lookups sind langsam und oft erfolglos — beides wird gemerkt.
pub struct RdnsCache {
    ttl: Duration,
    entries: Mutex<HashMap<IpAddr, (Instant, Option<String>)>>,
}

impl RdnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, entries: Mutex::new(HashMap::new()) }
    }

    pub fn get(&self, ip: &IpAddr) -> Option<Option<String>> {
        let mut map = self.entries.lock().unwrap();
        match map.get(ip) {
            Some((at, value)) if at.elapsed() < self.ttl => Some(value.clone()),
            Some(_) => { map.remove(ip); None }
            None => None,
        }
    }

    pub fn put(&self, ip: IpAddr, value: Option<String>) {
        let mut map = self.entries.lock().unwrap();
        if map.len() > 10_000 {
            let ttl = self.ttl;
            map.retain(|_, (at, _)| at.elapsed() < ttl);
        }
        map.insert(ip, (Instant::now(), value));
    }
}

pub struct Rdns {
    resolver: TokioResolver,
    cache: RdnsCache,
    timeout: Duration,
}

impl Rdns {
    pub fn from_system() -> anyhow::Result<Self> {
        let resolver = Resolver::builder_tokio()?.build();
        Ok(Self {
            resolver,
            cache: RdnsCache::new(Duration::from_secs(24 * 3600)),
            timeout: Duration::from_secs(2),
        })
    }
}

#[async_trait::async_trait]
impl RdnsSource for Rdns {
    async fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let Some(hit) = self.cache.get(&ip) {
            return hit;
        }
        let found = match tokio::time::timeout(self.timeout, self.resolver.reverse_lookup(ip)).await {
            Ok(Ok(answer)) => answer.iter().next().map(|n| n.to_string()),
            _ => None, // Timeout, NXDOMAIN, Netzfehler — alles dasselbe: kein rDNS
        };
        self.cache.put(ip, found.clone());
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn caches_hits_and_misses_alike() {
        let cache = RdnsCache::new(Duration::from_secs(60));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(cache.get(&ip).is_none());

        cache.put(ip, Some("dns.google.".into()));
        assert_eq!(cache.get(&ip), Some(Some("dns.google.".into())));

        let other: IpAddr = "1.1.1.1".parse().unwrap();
        // Auch ein Fehlschlag wird gemerkt, sonst fragen wir ihn ewig neu.
        cache.put(other, None);
        assert_eq!(cache.get(&other), Some(None));
    }

    #[tokio::test]
    async fn entries_expire() {
        let cache = RdnsCache::new(Duration::from_millis(30));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        cache.put(ip, Some("dns.google.".into()));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(cache.get(&ip).is_none());
    }
}
