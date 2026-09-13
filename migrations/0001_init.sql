CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Lookup-Tabellen: offene Wertemengen aus dem Netz, je einmal gespeichert.
CREATE TABLE rules (
    id    SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name  VARCHAR(100),
    descr VARCHAR(255)
);
CREATE UNIQUE INDEX idx_rules_key ON rules (COALESCE(lower(name), ''), COALESCE(lower(descr), ''));

CREATE TABLE interfaces (
    id   SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(20) NOT NULL
);
CREATE UNIQUE INDEX idx_interfaces_key ON interfaces (lower(name));

CREATE TABLE protocols (
    id   SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(10) NOT NULL
);
CREATE UNIQUE INDEX idx_protocols_key ON protocols (lower(name));

CREATE TABLE device_names (
    id   SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_device_names_key ON device_names (lower(name));

-- Logs: Hypertable, partitioniert nach timestamp. id ist NICHT global eindeutig
-- sortierbar ohne timestamp — Cursor ist immer (timestamp, id).
CREATE TABLE logs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY,
    timestamp           TIMESTAMPTZ NOT NULL,
    src_port            INTEGER,
    dst_port            INTEGER,
    asn_number          INTEGER,
    threat_score        INTEGER,
    log_type_id         SMALLINT NOT NULL,
    direction_id        SMALLINT,
    rule_id             SMALLINT,
    rule_action_id      SMALLINT,
    protocol_id         SMALLINT,
    iface_in_id         SMALLINT,
    iface_out_id        SMALLINT,
    hostname_id         SMALLINT,
    enrich_status       SMALLINT NOT NULL DEFAULT 0,  -- 0=pending 1=done 2=failed
    src_ip              INET,
    dst_ip              INET,
    mac_address         MACADDR,
    geo_country         VARCHAR(2),
    geo_city            VARCHAR(100),
    geo_lat             DECIMAL(9,6),
    geo_lon             DECIMAL(9,6),
    asn_name            VARCHAR(255),
    rdns                VARCHAR(255),
    dns_query           VARCHAR(255),
    dns_type            VARCHAR(10),
    dns_answer          VARCHAR(255),
    dhcp_event          VARCHAR(20),
    wifi_event          VARCHAR(50),
    raw_log             TEXT,
    PRIMARY KEY (timestamp, id)
);

SELECT create_hypertable('logs', 'timestamp', chunk_time_interval => INTERVAL '1 day');

CREATE INDEX idx_logs_type_time ON logs (log_type_id, timestamp DESC, id DESC);
CREATE INDEX idx_logs_src_ip ON logs (src_ip, timestamp DESC);
CREATE INDEX idx_logs_dst_ip ON logs (dst_ip, timestamp DESC);
-- Die Enrichment-Queue: Worker (Phase 2) holt pending-Zeilen. Partial → winzig.
CREATE INDEX idx_logs_enrich_pending ON logs (timestamp, id) WHERE enrich_status = 0;

-- Kompression + Retention über Timescale statt eigenem Cron.
ALTER TABLE logs SET (
    timescaledb.compress,
    timescaledb.compress_orderby = 'timestamp DESC, id DESC',
    timescaledb.compress_segmentby = 'log_type_id'
);
SELECT add_compression_policy('logs', INTERVAL '7 days');
SELECT add_retention_policy('logs', INTERVAL '60 days');

-- Dynamische Konfiguration (Setup, Labels, Retention-Overrides …)
CREATE TABLE system_config (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
