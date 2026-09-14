-- IP-Fakten als Cache und Wahrheit. logs behält seine denormalisierten
-- Spalten: das Land, das zum Zeitpunkt des Logs galt, bleibt historisch
-- korrekt, auch wenn die Adresse später jemand anderem gehört.
CREATE TABLE ip_enrichment (
    ip                   INET PRIMARY KEY,
    geo_country          VARCHAR(2),
    geo_city             VARCHAR(100),
    geo_lat              DOUBLE PRECISION,
    geo_lon              DOUBLE PRECISION,
    asn_number           INTEGER,
    asn_name             VARCHAR(255),
    rdns                 VARCHAR(255),
    threat_score         INTEGER,
    threat_categories    TEXT[],
    abuse_total_reports  INTEGER,
    abuse_last_reported  TIMESTAMPTZ,
    abuse_is_tor         BOOLEAN,
    abuse_usage_type     TEXT,
    geo_looked_up_at     TIMESTAMPTZ,
    rdns_looked_up_at    TIMESTAMPTZ,
    abuse_looked_up_at   TIMESTAMPTZ
);

-- Kandidaten für eine Auffrischung: alles, was älter als vier Tage ist.
CREATE INDEX idx_ip_enrichment_abuse_age ON ip_enrichment (abuse_looked_up_at)
    WHERE threat_score IS NOT NULL;

-- Die in Phase 1 noch fehlenden AbuseIPDB-Spalten.
ALTER TABLE logs
    ADD COLUMN threat_categories   TEXT[],
    ADD COLUMN abuse_total_reports INTEGER,
    ADD COLUMN abuse_last_reported TIMESTAMPTZ,
    ADD COLUMN abuse_is_tor        BOOLEAN,
    ADD COLUMN abuse_usage_type    TEXT;

CREATE INDEX idx_logs_threat_score ON logs (threat_score, timestamp DESC)
    WHERE threat_score IS NOT NULL;
