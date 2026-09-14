# Phase 3b–3d — Aggregate und Visualisierungen (Design)

**Datum:** 2026-09-14
**Status:** Entwurf
**Vorgänger:** [3a](2026-09-14-phase3a-filters-search-export-design.md) — Filter, Suche, Export

Drei Ansichten auf dieselben Daten, die sich eine Grundlage teilen: den
`LogFilter` aus 3a. Was in der Log-Tabelle gefiltert ist, gilt auch für
Dashboard, Karte und Flussdiagramm — man filtert einmal und sieht dieselbe
Auswahl aus vier Blickwinkeln.

- **3b:** Dashboard — Kennzahlen, Zeitreihe, Top-Listen.
- **3c:** Threat Map — wo blockierter Verkehr herkommt.
- **3d:** Flow View — wie Verkehr zwischen Zonen und Diensten fließt.

## Gemeinsame Entscheidungen

### Der Filter ist geteilt, die Abfragen sind es nicht

Jede Ansicht bekommt eigene Endpunkte, die `LogFilter::push_joins` und
`push_where` wiederverwenden. Kein gemeinsames „Alles-Aggregat", aus dem sich
jede Ansicht ihr Stück schneidet — das wäre eine Abfrage, die nichts gut kann.

### Aggregate laufen nebenläufig

Ein Dashboard besteht aus sechs bis acht unabhängigen Aggregaten. Nacheinander
ausgeführt addieren sich ihre Laufzeiten; über denselben Pool nebenläufig
ausgeführt nicht. Der Fork hat genau das nachträglich umbauen müssen
(*„unpick the view joins and run the aggregates concurrently"*) — wir fangen
damit an. `tokio::try_join!` über einen Pool mit zehn Verbindungen.

Ebenso: keine Sicht (`VIEW`), die alle Lookups joint und aus der dann
aggregiert wird. Jede Aggregatabfrage joint nur die Tabellen, die sie
tatsächlich braucht. Die meisten brauchen gar keine.

### Zeitreihen über `time_bucket`

TimescaleDB liefert `time_bucket('5 minutes', timestamp)` — genau dafür ist
die Erweiterung da. Die Bucket-Breite folgt dem Zeitfenster, damit eine Kurve
immer ungefähr gleich viele Punkte hat:

| Fenster | Bucket |
|---|---|
| ≤ 1 h | 1 min |
| ≤ 6 h | 5 min |
| ≤ 24 h | 15 min |
| ≤ 7 d | 1 h |
| darüber | 6 h |

Continuous Aggregates wären der nächste Schritt, wenn das zu langsam wird. Für
ein Heimnetz mit einer Handvoll Ereignissen pro Sekunde sind sie verfrüht —
und sie kosten Speicher und Komplexität, die man erst ausgeben sollte, wenn
eine Messung sie rechtfertigt.

### Keine Karten-Kacheln von fremden Servern

Die Threat Map zeichnet die Welt aus einer **mitgelieferten** TopoJSON-Datei
mit `d3-geo`, nicht aus Kacheln eines Kartendienstes. Eine Kachelkarte würde
bei jedem Schwenk verraten, welche Weltgegend man sich gerade ansieht — für
ein Werkzeug, dessen Zweck die Auswertung des eigenen Netzverkehrs ist, wäre
das ein Widerspruch. Die Datei ist Teil des Bundles; im Betrieb geht keine
einzige Anfrage nach außen.

Das ist zugleich die einfachere Lösung: kein Kachel-Cache, keine Attribution
fremder Dienste, keine kaputte Karte, wenn der LXC kein Internet hat.

## 3b — Dashboard

### Endpunkte

`GET /api/stats` — alles, was die Kennzahlenreihe braucht, in einer Antwort
(nebenläufig ermittelt):

```json
{
  "total": 18422, "blocked": 1204, "allowed": 17218,
  "by_type": {"firewall": 17800, "dns": 600, "dhcp": 22},
  "unique_sources": 143, "threats": 38
}
```

`GET /api/stats/series` — eine Zeitreihe je Aktion:

```json
{"bucket": "15 minutes",
 "points": [{"t": "2026-09-14T10:00:00Z", "allowed": 120, "blocked": 8}, …]}
```

`GET /api/stats/top?what=<dimension>&limit=10` — eine Top-Liste. Dimensionen:
`countries`, `sources`, `destinations`, `ports`, `rules`, `interfaces`,
`asns`, `threats`. Antwort ist immer dieselbe Form:

```json
{"rows": [{"key": "CN", "label": "China", "count": 812, "extra": {"blocked": 800}}]}
```

Eine Form für alle Dimensionen, weil die Oberfläche sie alle gleich darstellt
— eine Liste mit Balken. Unterschiedliche Formen je Dimension hieße
unterschiedlicher Code je Liste, ohne dass es etwas brächte.

### Oberfläche

Kennzahlen als Kacheln, darunter die Zeitreihe als gestapelte Fläche
(erlaubt/blockiert), darunter die Top-Listen als Raster. Jede Zeile einer
Top-Liste ist anklickbar und setzt den entsprechenden Filter — von „China, 812"
zur Liste dieser 812 Zeilen ist es ein Klick.

Die Zeitreihe wird als SVG selbst gezeichnet, ohne Chart-Bibliothek: zwei
gestapelte Flächen, eine Achse, ein Tooltip. Eine Bibliothek für zwei Pfade zu
laden lohnt nicht.

## 3c — Threat Map

### Endpunkt

`GET /api/threats/points` — blockierter Verkehr, gruppiert nach Ort:

```json
{"points": [{"lat": 39.9, "lon": 116.4, "country": "CN", "city": "Beijing",
             "count": 812, "max_threat": 100, "sample_ip": "1.2.3.4"}]}
```

Gruppiert wird auf eine Nachkommastelle gerundet (~11 km) — feiner ist bei
GeoIP-Genauigkeit Fiktion, und es hält die Punktzahl im Hunderterbereich statt
im Zehntausenderbereich.

### Oberfläche

Natural-Earth-Projektion, Länder aus der mitgelieferten TopoJSON, Punkte nach
Anzahl skaliert und nach höchstem Threat-Score eingefärbt. Klick auf einen
Punkt filtert die Log-Ansicht auf dieses Land. Ohne GeoIP-Datenbanken ist die
Karte leer und sagt das auch — nicht kaputt, nur uninformiert.

## 3d — Flow View

### Endpunkte

`GET /api/flows/sankey?limit=…` — Verkehr als Fluss über drei Spalten
(Quelle → Dienst → Ziel):

```json
{"nodes": [{"id": "src:10.0.20.5", "label": "10.0.20.5", "kind": "source"}, …],
 "links": [{"source": 0, "target": 4, "value": 231, "blocked": 12}]}
```

Knoten werden begrenzt (Standard: 12 je Spalte), der Rest fällt in einen
Sammelknoten „Weitere". Ein Sankey mit zweihundert Knoten ist ein Knäuel, kein
Diagramm.

`GET /api/flows/zones` — die Zonenmatrix, Schnittstelle zu Schnittstelle:

```json
{"zones": ["ppp0", "br20", "br30"],
 "cells": [{"from": "ppp0", "to": "br20", "allowed": 1200, "blocked": 44}]}
```

### Oberfläche

Sankey links, Matrix rechts (auf schmalen Schirmen untereinander). Das Layout
rechnet `d3-sankey`, gezeichnet wird als SVG. Ein Klick auf einen Knoten oder
eine Zelle setzt den passenden Filter.

## Tests

Für alle drei gilt dasselbe Muster wie in 3a: **gegen eine echte Wegwerf-DB,
geprüft wird das Ergebnis, nicht das SQL.** Bekannte Zeilen einfügen, Endpunkt
aufrufen, erwartete Zahlen vergleichen.

Wichtig sind dabei die Fälle, die man sonst übersieht:

- Leere Datenbank: jedes Aggregat liefert Nullen und eine leere Liste, keinen
  Fehler und kein `null`.
- Der Filter wirkt auch auf Aggregate — dieselbe Abfrage mit
  `?action=block` muss kleinere Zahlen liefern.
- Zeilen ohne Anreicherung (kein Land, keine Koordinaten) fallen aus Karte und
  Länderliste heraus, ohne die Gesamtzahlen zu verfälschen.
- Die Zonenmatrix zählt nur Zeilen, die beide Schnittstellen kennen.

## Bewusst nicht in 3b–3d

Gespeicherte Ansichten, Drilldown-Seitenpanel je Host, Continuous Aggregates,
Export der Aggregate, UniFi- und Pi-hole-Integration, MCP.
