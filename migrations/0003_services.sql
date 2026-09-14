-- IANA service name lookup: resolves (dst_port, protocol) to a human name
-- for the log table's SERVICE column. Seeded at start-up from the bundled
-- CSV (see crates/uip-api/src/services.rs) when this table is empty.
CREATE TABLE services (
    port  INTEGER NOT NULL,
    proto VARCHAR(10) NOT NULL,
    name  TEXT NOT NULL,
    PRIMARY KEY (port, proto)
);
