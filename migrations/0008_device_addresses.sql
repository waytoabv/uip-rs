-- Adresse → Gerätename, an einer Stelle.
--
-- Die Namen kommen aus drei Quellen, die bisher getrennt abgefragt wurden:
-- den Clients des Controllers (`unifi_clients`), seinen eigenen Geräten
-- (`unifi_devices`) und — neu — den Gateway-Adressen der Netze, die in keiner
-- der beiden Tabellen stehen: das Gateway meldet unter `stat/device` nur seine
-- WAN-Adresse, seine Adresse in jedem VLAN steht in der Netz-Konfiguration.
--
-- Zusammengeführt, weil dieselbe Frage sonst an zwei Stellen unterschiedlich
-- beantwortet wird: die Zeilenliste löste über vier Joins auf, der Live-Strom
-- gar nicht. Eine Tabelle, die beide lesen, kann nicht auseinanderlaufen — und
-- die Zeilenliste braucht zwei Joins statt vier.
CREATE TABLE device_addresses (
    ip         INET PRIMARY KEY,
    name       TEXT NOT NULL,
    -- 'device' (Gerät des Controllers), 'gateway' (Adresse des Gateways in
    -- einem Netz), 'client'. Die Reihenfolge ist auch die Rangfolge: kennen
    -- zwei Quellen dieselbe Adresse, gewinnt die verlässlichere.
    kind       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
