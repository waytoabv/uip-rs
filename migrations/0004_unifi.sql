-- Geräte aus dem UniFi-Controller.
--
-- Bewusst getrennt von `device_names`: dort landen Namen, die aus den Logs
-- selbst stammen (DHCP-Hostnamen). Hier stehen die Namen, die jemand im
-- Controller vergeben hat — sie sind verlässlicher und ändern sich, ohne dass
-- ein Log dazu geschrieben wird.
CREATE TABLE unifi_clients (
    mac          MACADDR PRIMARY KEY,
    ip           INET,
    name         TEXT,
    hostname     TEXT,
    oui          TEXT,
    network      TEXT,
    is_wired     BOOLEAN,
    last_seen    TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Die Auflösung geschieht beim Lesen über die Adresse, nicht über die MAC:
-- in einer Log-Zeile steht die Adresse.
CREATE INDEX idx_unifi_clients_ip ON unifi_clients (ip) WHERE ip IS NOT NULL;

CREATE TABLE unifi_devices (
    mac          MACADDR PRIMARY KEY,
    ip           INET,
    name         TEXT,
    model        TEXT,
    device_type  TEXT,
    firmware     TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_unifi_devices_ip ON unifi_devices (ip) WHERE ip IS NOT NULL;
