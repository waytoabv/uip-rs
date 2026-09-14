# Phase 3a — Filter, Suche und Export (Design)

**Datum:** 2026-09-14
**Status:** Entwurf
**Vorgänger:** [Phase 1](2026-09-13-uip-rs-rewrite-design.md), [Phase 2](2026-09-14-phase2-enrichment-design.md)

## Warum Phase 3 geteilt wird

Die Roadmap führt Phase 3 als „UI-Parität" mit Filtern, Suche, Dashboard,
Threat Map, Flow View, Theming und CSV-Export. Das sind vier unabhängige
Teilsysteme; in einen Spec-Zyklus gepresst würde keines davon sauber
durchdacht. Deshalb:

- **3a (dieses Dokument):** Die Log-Ansicht wird benutzbar — Filter, typisierte
  Suche, gefilterter Live-Stream, CSV-Export, Theming.
- **3b:** Dashboard-Aggregate (Verkehrsaufteilung, Top-Listen, Zeitreihen).
- **3c:** Threat Map und Flow View — die beiden schweren Visualisierungen.

Nach 3a ist das Werkzeug für den Alltag tauglich: man kann eine Frage an die
Logs stellen und bekommt Antwort. Das ist der Punkt, an dem sich der Rewrite
zum ersten Mal wie das fertige Produkt anfühlt.

## 1. Die Suche

Ein Feld nimmt, was man weiß — Adresse, Port, Gerätename — und findet selbst
heraus, was es ist.

Das ist nicht kosmetisch. Der Fork hat es zuerst als Textvergleich gebaut und
zwei Dinge gelernt, die wir übernehmen statt sie zu wiederholen: eine Suche
nach `10.10.10.10` fand auch `10.10.10.100`, und der Textvergleich stellte die
Adressspalten außerhalb der Reichweite ihres Index — ein Begriff mit drei
Treffern musste das ganze Zeitfenster scannen. Erkennt man die Adresse als
Adresse, wird daraus ein exakter, indizierter Vergleich.

### Grammatik

```
query   := term*
term    := ('!' | '-')? (field ':')? value
value   := '"' … '"' | bare
field   := src | dst | ip | port | sport | dport | rule | country
         | asn | proto | iface | host | action | type
```

Mehrere Begriffe, durch Leerzeichen getrennt, müssen **alle** zutreffen — das
Feld ist damit zugleich ein Weg, Filter zu stapeln:

```
10.10.30.0/24 443 !tcp        dieses Subnetz, Port 443, nicht TCP
src:10.0.0.5 rule:"LAN to"    je auf ein Feld beschränkt
nas denied                    beide Wörter, irgendwo
```

### Typerkennung

| Eingabe | erkannt als | Vergleich |
|---|---|---|
| `10.0.0.5` | Adresse | `=`, indiziert |
| `10.10.30.0/24` | Netz | `<<=`, indiziert |
| `10.10.30.` / `10.10.30.*` / `10.10.30` | Netz (/24) | `<<=` |
| `aa:bb:cc:dd:ee:ff` | MAC | `=` |
| `443` | Port | `=` auf Quell- **oder** Zielport |
| alles andere | Text | `ILIKE`, `*` wird zu `%` |

Ein einzelnes Oktett ohne Punkt oder Stern ist eine Zahl, kein Netz: `10` ist
Port 10, nicht `10.0.0.0/8`.

Der Parser wirft nie. Eine unbalancierte Anführung ist kein Fehler, sondern
jemand, der noch tippt — dann wird an Leerzeichen getrennt und weitergearbeitet.

### Textsuche

Textbegriffe treffen auf Regelname, Regelbeschreibung, Schnittstellen,
Hostname, DNS-Abfrage, rDNS, AS-Name und Land. Das ist eine Reihe von
`ILIKE`-Vergleichen über die ohnehin gejointen Lookup-Tabellen — für die
Datenmengen eines Heimnetzes in Ordnung. Wird es eng, ist ein
Trigram-Index der nächste Schritt, nicht eine andere Architektur.

## 2. Filter

Alles, was die Suche kann, geht auch als expliziter Parameter — die Filterleiste
schreibt sie, die Suche ist der schnellere Weg für Geübte.

| Parameter | Werte |
|---|---|
| `log_type` | `firewall,dns,dhcp,wifi,system` (mehrfach) |
| `action` | `allow,block,redirect` |
| `direction` | `inbound,outbound,local,inter_vlan,vpn,nat` |
| `iface` | Schnittstellenname (mehrfach) |
| `proto` | `tcp,udp,icmp,…` |
| `country` | ISO-Code (mehrfach) |
| `port` | Zahl, trifft Quell- oder Zielport |
| `threat_min` | Zahl 0–100 |
| `from` / `to` | RFC3339 |
| `range` | `1h,6h,24h,7d,30d` — Kurzform für `from` |
| `q` | Suchausdruck (siehe oben) |

Alle Filter verknüpfen mit UND. Mehrfachwerte innerhalb eines Parameters mit
ODER. Die Cursor-Navigation aus Phase 1 bleibt unverändert gültig: der Cursor
ist weiterhin `(timestamp, id)`, die Filter sind nur zusätzliche Bedingungen.

## 3. Der Live-Stream folgt dem Filter

Bisher filtert SSE nur nach Log-Typ, und zwar mit einem Textvergleich auf dem
fertigen JSON. Das reicht nicht mehr: wer auf „blockiert, eingehend" filtert,
darf nicht plötzlich unbeteiligte Zeilen oben einfließen sehen.

Dafür ändert sich, was der Writer sendet — statt eines fertigen JSON-Strings
ein typisierter Datensatz (`Arc<LiveRow>`). Der SSE-Endpunkt wertet denselben
Filter gegen dieses Objekt aus und serialisiert erst danach, pro Verbindung.
Die Serialisierung wandert damit von einmal pro Zeile zu einmal pro Zeile und
Zuschauer — bei einer Handvoll offener Tabs ist das nichts, und es ist der
Preis dafür, dass Filter und Stream dieselbe Wahrheit benutzen.

**Was der Stream nicht kann:** Filter auf angereicherte Felder (Land,
Threat-Score). Eine frisch geschriebene Zeile ist noch nicht angereichert; sie
jetzt nach Land zu filtern hieße, sie immer zu verwerfen. Ist ein solcher
Filter aktiv, pausiert der Stream sichtbar mit einem Hinweis, statt still zu
lügen — beim nächsten Nachladen sind die Zeilen dann da.

## 4. CSV-Export

`GET /api/export` mit denselben Filtern, Obergrenze 100 000 Zeilen. Die Antwort
wird **gestreamt**, nicht gesammelt: 100 000 Zeilen im Speicher aufzubauen,
bevor das erste Byte rausgeht, ist bei 2 GB RAM im LXC eine schlechte Idee.
Der Export nimmt die aufgelösten Namen, nicht die Lookup-Ids — eine Tabelle,
die man in Excel öffnet, soll `ppp0` zeigen, nicht `7`.

## 5. Theming

Hell/dunkel, umschaltbar, Auswahl im `localStorage`. Kein Framework, nur
CSS-Custom-Properties auf `:root` und ein `data-theme`-Attribut. Ohne
getroffene Wahl gilt `prefers-color-scheme`.

## 6. Tests

- Der Suchparser bekommt eine Tabelle aus Eingabe und erwarteten Begriffen,
  einschließlich der Fälle, die den Fork gelehrt haben, worauf es ankommt:
  `10.10.10.10` darf `10.10.10.100` nicht treffen, `10` ist ein Port, `10.10.30.`
  ist ein Netz, eine offene Anführung bricht nichts.
- Der Filteraufbau wird gegen eine echte Wegwerf-DB geprüft, nicht gegen
  erwartete SQL-Strings: eingefügte Zeilen, gefilterte Abfrage, erwartete
  Treffermenge. Was zählt, ist welche Zeilen zurückkommen.
- Der Export wird auf Kopfzeile, Zeilenanzahl und Maskierung geprüft
  (ein Regelname mit Komma darf die Spalten nicht verschieben).
- Der Stream-Filter bekommt Tests für „passt", „passt nicht" und
  „angereichertes Feld gefiltert → pausiert".

## 7. Bewusst nicht in 3a

Dashboard-Aggregate, Threat Map, Flow View (3b/3c), gespeicherte Ansichten,
Volltextindex, UniFi- und Pi-hole-Integration, MCP.
