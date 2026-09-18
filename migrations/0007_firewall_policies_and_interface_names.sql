-- Die Firewall-Regeln, wie sie im Controller heißen.
--
-- Im Log steht `CUSTOM2_CUSTOM1-A-10008`, daneben eine bei 29 Zeichen
-- abgeschnittene Beschreibung. Der Controller kennt den ganzen Namen
-- („VL15 -> VL10 - Allow Pihole DNS and WebUI"). Der Schlüssel ist der
-- Regelname selbst: er ist aus Quellzone, Zielzone, Aktion und Index gebaut,
-- und dieses Tripel ist über alle Regeln hinweg eindeutig.
CREATE TABLE unifi_firewall_policies (
    rule_key   TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    -- Klartext, absichtlich in der Zeile statt in einer eigenen Zonentabelle:
    -- die vordefinierten Regeln heißen alle „Allow All Traffic", erst die
    -- Zonen sagen, welche gemeint ist. Ein Join dafür wäre ein hoher Preis.
    src_zone   TEXT,
    dst_zone   TEXT,
    predefined BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Eigene Namen für die Schnittstellen.
--
-- Getrennt von `unifi_networks`: dort räumt der Abgleich alles weg, was der
-- Controller nicht mehr kennt, und ein selbst vergebener Name verschwände mit
-- dem ersten Umbau. Außerdem soll man benennen können, was der Controller gar
-- nicht kennt — `ppp0`, `tun0`, die Schnittstelle einer VPN-Instanz.
CREATE TABLE interface_names (
    interface  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
