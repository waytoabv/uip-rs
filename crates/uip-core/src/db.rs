use sqlx::PgPool;
use std::collections::HashMap;
use tokio::sync::RwLock;

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}

#[derive(Default)]
pub struct LookupCache {
    interfaces: RwLock<HashMap<String, i16>>,
    protocols: RwLock<HashMap<String, i16>>,
    device_names: RwLock<HashMap<String, i16>>,
    rules: RwLock<HashMap<(String, String), i16>>,
}

impl LookupCache {
    pub fn new() -> Self {
        Self::default()
    }

    async fn simple_id(
        map: &RwLock<HashMap<String, i16>>,
        pool: &PgPool,
        table: &str,
        value: &str,
    ) -> Result<i16, sqlx::Error> {
        let key = value.to_lowercase();
        if let Some(&id) = map.read().await.get(&key) {
            return Ok(id);
        }
        // Nur whitelisted Tabellennamen landen im SQL-String.
        let insert = format!("INSERT INTO {table} (name) VALUES ($1) ON CONFLICT DO NOTHING");
        sqlx::query(&insert).bind(value).execute(pool).await?;
        let select = format!("SELECT id FROM {table} WHERE lower(name) = $1");
        let id: i16 = sqlx::query_scalar(&select).bind(&key).fetch_one(pool).await?;
        map.write().await.insert(key, id);
        Ok(id)
    }

    pub async fn interface_id(&self, pool: &PgPool, name: &str) -> Result<i16, sqlx::Error> {
        Self::simple_id(&self.interfaces, pool, "interfaces", name).await
    }
    pub async fn protocol_id(&self, pool: &PgPool, name: &str) -> Result<i16, sqlx::Error> {
        Self::simple_id(&self.protocols, pool, "protocols", name).await
    }
    pub async fn device_name_id(&self, pool: &PgPool, name: &str) -> Result<i16, sqlx::Error> {
        Self::simple_id(&self.device_names, pool, "device_names", name).await
    }

    pub async fn rule_id(
        &self,
        pool: &PgPool,
        name: Option<&str>,
        descr: Option<&str>,
    ) -> Result<i16, sqlx::Error> {
        let key = (
            name.unwrap_or("").to_lowercase(),
            descr.unwrap_or("").to_lowercase(),
        );
        if let Some(&id) = self.rules.read().await.get(&key) {
            return Ok(id);
        }
        sqlx::query("INSERT INTO rules (name, descr) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(name)
            .bind(descr)
            .execute(pool)
            .await?;
        let id: i16 = sqlx::query_scalar(
            "SELECT id FROM rules WHERE COALESCE(lower(name), '') = $1 AND COALESCE(lower(descr), '') = $2",
        )
        .bind(&key.0)
        .bind(&key.1)
        .fetch_one(pool)
        .await?;
        self.rules.write().await.insert(key, id);
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn lookup_ids_are_stable_and_case_insensitive(pool: sqlx::PgPool) {
        let cache = LookupCache::new();
        let a = cache.interface_id(&pool, "ppp0").await.unwrap();
        let b = cache.interface_id(&pool, "PPP0").await.unwrap();
        assert_eq!(a, b);
        let c = cache.interface_id(&pool, "br20").await.unwrap();
        assert_ne!(a, c);
        let p = cache.protocol_id(&pool, "tcp").await.unwrap();
        assert!(p >= 1);
        let r1 = cache.rule_id(&pool, Some("WAN_IN-D"), Some("Block x")).await.unwrap();
        let r2 = cache.rule_id(&pool, Some("wan_in-d"), Some("block x")).await.unwrap();
        assert_eq!(r1, r2);
        let h = cache.device_name_id(&pool, "myhost").await.unwrap();
        assert!(h >= 1);
    }
}
