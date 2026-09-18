# Regelnamen aus dem Controller, eigene Namen für die Schnittstellen (Design)

**Datum:** 2026-09-18
**Status:** Angenommen

## Warum

Zwei Namen in der Log-Tabelle sind heute schlechter, als sie sein müssten.

**Der Regelname.** Die Firewall schreibt in jede Zeile ihren Regelnamen
(`CUSTOM2_CUSTOM1-A-10008`) und, wenn Platz ist, eine Beschreibung. Der Platz
ist knapp: das Feld `DESCR` bricht nach 29 Zeichen ab, aus
`VL15 -> VL10 - Allow Pihole DNS and WebUI` wird
`VL15 -> VL10 - Allow Pihole D`. Fehlt die Beschreibung ganz — bei den
vordefinierten Regeln steht dort nur `[LOCAL_WAN]Allow All Traffic` —, zeigt
die Tabelle den rohen Namen. Der Controller kennt beides vollständig.

**Der Name der Schnittstelle.** `br15` heißt im Controller „#1 - VLAN15 -
Intern". Das ist der Name, den der Controller kennt, nicht zwangsläufig der,
den man in einer Log-Tabelle lesen will: die Nummerierung und die VLAN-Nummer
stehen schon in der Zeile daneben. Wer „Intern" schreiben will, soll das tun
können, ohne sein Netz im Controller umzubenennen.

## 1. Regelnamen

### Die Zuordnung

Der Regelname im Log ist keine willkürliche Zeichenkette, sondern gebaut:

```
{Quellzone}_{Zielzone}-{A|D|R}-{index}
```

Die Zonen-Kürzel kommen aus der Zonen-Liste des Controllers
(`v2/api/site/{site}/firewall/zone`): `zone_key` `internal` → `LAN`,
`external` → `WAN`, `gateway` → `LOCAL`, alle übrigen Vorgabezonen tragen ihr
`zone_key` in Großbuchstaben (`DMZ`, `VPN`, `HOTSPOT`). Selbst angelegte Zonen
haben kein `zone_key`; sie heißen `CUSTOM1`, `CUSTOM2`, … in der Reihenfolge
ihrer Erstellung — also nach `_id` sortiert, denn die MongoDB-Kennung trägt den
Zeitstempel in sich.

Der Buchstabe ist die Aktion der Regel (`ALLOW` → `A`, `BLOCK`/`REJECT`/`DROP`
→ `D`, sonst `R`), der Index ihr Feld `index`. Der Index ist nur innerhalb
eines Zonenpaars eindeutig — 37 Regeln tragen die 10000 —, zusammen mit den
Zonen und der Aktion ist er es ganz: über die 215 Regeln der Testanlage gibt es
keine einzige Kollision, und alle 16 in den Logs vorkommenden Regelnamen
treffen genau eine Regel.

### Ablage und Abgleich

Neue Tabelle, geschrieben vom bestehenden UniFi-Abgleich (alle fünf Minuten,
`uip-enrich/src/unifi.rs`):

```sql
CREATE TABLE unifi_firewall_policies (
    rule_key   TEXT PRIMARY KEY,   -- exakt der Regelname aus dem Log
    name       TEXT NOT NULL,
    src_zone   TEXT,               -- Klartext: "Gateway", "#1 - Internes Netzwerk"
    dst_zone   TEXT,
    predefined BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Denormalisiert, mit den Zonennamen in der Zeile: eine eigene Zonen-Tabelle
hätte einen Join gekostet und keine Frage beantwortet, die nicht schon hier
steht. Gelöschte Regeln werden wie die Netze nach dem Abgleich weggeräumt.

Die Endpunkte sind die der v2-API (`{base}/proxy/network/v2/api/site/{site}/…`,
Rückfall auf `{base}/v2/api/site/{site}/…`) und antworten mit einem nackten
Array statt mit `{"data": […]}` wie die alte. Fehlen sie — ein Controller ohne
Zonen-Firewall —, bleibt die Tabelle leer und die Anzeige bei dem, was sie
heute zeigt. Die alte `rest/firewallrule` wird nicht ausgewertet: auf der
Testanlage ist sie leer, und ein Mapping, das man nicht gegen echte Daten
prüfen kann, ist geraten.

### Anzeige

Ein neuer Endpunkt `/api/firewall-rules` liefert die Tabelle als eine Map,
genau wie `/api/networks` — einmal geholt, gilt sie für alle Zeilen. Das hält
den Join aus der heißesten Abfrage heraus und deckt die Zeilen aus dem
Live-Stream mit ab, die nie durch `/api/logs` laufen.

Die Spalte RULE/INFO zeigt dann in dieser Reihenfolge: den Namen aus dem
Controller, sonst die Beschreibung aus dem Log, sonst den rohen Regelnamen. Die
vordefinierten Regeln heißen alle gleich (38 mal „Block All Traffic"), deshalb
stehen bei ihnen die Zonen davor: `Gateway → External · Allow All Traffic`. Der
rohe Regelname bleibt im Tooltip erreichbar.

## 2. Eigene Namen für die Schnittstellen

Eigene Tabelle, nicht eine Spalte an `unifi_networks`:

```sql
CREATE TABLE interface_names (
    interface  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Der Abgleich löscht in `unifi_networks` alles, was der Controller nicht mehr
kennt — ein eigener Name dort verschwände mit dem ersten Umbau im Controller.
Und benennen können soll man auch, was der Controller gar nicht kennt: `ppp0`,
`tun0`, die Schnittstelle einer VPN-Instanz.

`/api/networks` liefert je Schnittstelle zusätzlich `custom` und listet nicht
mehr nur die Netze des Controllers, sondern alles je Gesehene
(`unifi_networks ∪ interfaces`) — sonst kann der Dialog keine Zeile für `ppp0`
anbieten. `PUT /api/networks/names` nimmt `{"br15": "Intern", "ppp0": null}`;
`null` oder leer heißt „zurück zum Namen des Controllers".

In der Oberfläche eine eigene Abteilung „Interfaces" in den Einstellungen: eine
Zeile je Schnittstelle, der Controller-Name als Platzhalter im Eingabefeld, das
VLAN daneben. Gespeichert wird mit demselben Knopf wie der Rest.

`interfaceLabels.ts` löst danach in der Reihenfolge eigener Name → Controller →
roher Name auf. Damit gilt die Umbenennung überall, wo heute schon der
Controller-Name steht: Log-Tabelle, Flow View, Dashboard.

## Was nicht dazugehört

- Der CSV-Export schreibt weiter den rohen Regelnamen. Er liest aus der
  Datenbank, nicht aus der Map der Oberfläche; ihn nachzuziehen wäre ein
  eigener Join für einen Weg, den niemand beim Lesen nimmt.
- Die Zonen-Kürzel im Regelnamen werden nicht zusätzlich übersetzt. Der Name
  aus dem Controller sagt bereits, worum es geht.
