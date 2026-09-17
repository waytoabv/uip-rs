-- Die Netze, wie sie im Controller heißen.
--
-- In einer Log-Zeile steht `br15`. Dass das „IoT" ist, weiß der Controller;
-- niemand sollte die VLAN-Nummern auswendig können müssen. Wie bei den
-- Gerätenamen wird auch das beim Lesen aufgelöst und nicht in die Zeilen
-- geschrieben: eine Umbenennung im Controller gilt dann rückwirkend.
CREATE TABLE unifi_networks (
    -- Der Name der Schnittstelle, wie er im Log steht: br0, br15, eth4, ppp0.
    interface  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    -- NULL bei WAN-Schnittstellen — die haben kein VLAN.
    vlan       INTEGER,
    purpose    TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
