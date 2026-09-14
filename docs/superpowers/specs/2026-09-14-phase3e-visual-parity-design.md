# Phase 3e — Visuelle Parität zum Original (Design)

**Datum:** 2026-09-14
**Status:** Entwurf

## Ziel

Die Oberfläche soll aussehen wie das Original — dieselbe Anordnung, dieselben
Farben, dieselben Abzeichen und anklickbaren Flächen — umgesetzt mit unseren
Komponenten (SolidJS, kein React).

Das Original liegt vollständig vor und ist die verbindliche Vorlage:

| Was | Wo |
|---|---|
| Screenshots | `/Users/lukas/Documents/dev/UniFi-Insights-Plus/docs/screenshots/` |
| Komponenten | `/Users/lukas/Documents/dev/UniFi-Insights-Plus/ui/src/components/` |
| Eigene Stile | `/Users/lukas/Documents/dev/UniFi-Insights-Plus/ui/src/index.css` |
| Tailwind-Konfiguration | `/Users/lukas/Documents/dev/UniFi-Insights-Plus/ui/tailwind.config.js` |

**Vorlage lesen, nicht kopieren.** Der Originalcode steht unter BSL 1.1. Wir
übernehmen das *Erscheinungsbild* — Abstände, Farbwerte, Abzeichenformen,
Spaltenreihenfolge —, schreiben den Code aber neu für Solid. Klassennamen von
Tailwind sind dabei keine Schöpfungshöhe, sondern die Beschreibung eines
Aussehens; die Komponentenlogik ist neu.

## 1. Tailwind als Grundlage

Das Original gestaltet über Tailwind-Utility-Klassen, kaum über eigenes CSS.
Ohne Tailwind müssten wir jede Klasse von Hand in CSS übersetzen — hunderte
Male, jedes Mal eine Gelegenheit, einen Wert falsch abzuschreiben. Mit
Tailwind bleibt das Aussehen im Markup ablesbar und vergleichbar.

Wir übernehmen die Konfiguration des Originals: Standardpalette, `gray-950`
auf `#000000` gesetzt, Sans- und Mono-Stack wie dort.

**Die Schrift nicht.** Das Original bindet `UI Sans` ein, die Hausschrift von
Ubiquiti. Eine fremde Markenschrift in ein eigenes Projekt zu kopieren ist
eine Lizenzfrage, die niemand nebenbei entscheiden sollte. Der Stack lautet
deshalb `['UI Sans', 'Inter', 'system-ui', 'sans-serif']`: wer die Dateien
rechtmäßig hat, legt sie unter `ui/public/fonts/` ab und bekommt das Original;
alle anderen sehen Inter, das sehr nah dran ist. Ausgeliefert wird nur Inter.

## 2. Die dunkle Variante ist die Hauptvariante

Das Original ist dunkel (`body { background-color: #000 }`) und schaltet über
`[data-theme="light"]` auf hell. Unsere bisherige Reihenfolge ist umgekehrt.
Wir drehen sie: dunkel ist der Normalfall, hell die Ausnahme — sonst stimmen
die Farbwerte an keiner Stelle mit der Vorlage überein.

## 3. Die Bestandteile

### Kopfzeile

Links das Zeichen (Kreis mit „U") und der Name, daneben die Reiter — der
aktive als gefüllte Pille, die übrigen flach. Rechts die Statusleiste:
AbuseIPDB-Kontingent, MaxMind-Stand, nächster Abruf, Zahl der Logs, ein
grüner Punkt für „lebt", Mond für das Design, Regler für die Einstellungen.
Alles durch dünne senkrechte Striche getrennt.

Was wir nicht haben, zeigen wir als `—` statt es wegzulassen: eine Leerstelle
an erwarteter Stelle sagt „noch nichts", eine fehlende Spalte sagt „gibt es
nicht".

### Log Stream

Zwei Filterzeilen über der Tabelle:

1. Pillen für Log-Typ (aktiv blau), Trennstrich, Pillen für Aktion (ALLOW
   grün, BLOCK rot, REDIRECT gelb), Trennstrich, Pillen für Richtung mit
   Pfeilzeichen, dann die Zeitraumknöpfe (1h 6h 24h 7d 30d 60d 90d, Custom).
2. Textfelder nebeneinander: IP, Regelname, Schnittstelle, Quellport,
   Zielport, Protokoll, Dienst, Ländercode, ASN, Freitext — und rechts
   „Reset".

Darunter eine schmale Zeile: grüner Punkt, „Live", Zeitstempel der letzten
Aktualisierung; rechts „Columns", „↻ Refresh", „↓ Export CSV".

Die Tabelle: ZEIT, TYP, AKTION, QUELLE, (Richtungspfeil), ZIEL, LAND,
NETZWERK, PROTO, DIENST, REGEL/INFO, ABUSEIPDB, KATEGORIEN. Quelle und Ziel
zweizeilig — Gerätename oben, Adresse mit Port darunter in Grau. Land als
Flagge. Zeilen mit hohem Threat-Score bekommen einen roten Schimmer.

Fußzeile: „1–50 von N" links, Blätterpfeile rechts.

### Dashboard

Karten mit kleiner, gesperrter Überschrift in Großbuchstaben:

- **Traffic Overview:** große Gesamtzahl, darunter Pillen ALLOWED/BLOCKED/
  THREATS, darunter die Richtungen als Pillen mit Zeichen.
- **Log Types:** eine Pille je Typ in der Farbe des Typs.
- **Traffic over Time:** Flächendiagramm, blauer Verlauf.
- **Traffic by Action:** übereinandergelegte Flächen grün/rot/gelb mit
  Legendenpunkten oben rechts.
- **Top-Listen:** Adresse mit Flagge, ASN darunter grau, Kategorien blau,
  rechts Anzahl und Anteil; bei den blockierten Adressen ein Balken unter
  jeder Zeile.

### Flow View und Threat Map

Anordnung und Farbgebung wie in den Screenshots
(`flow-view.png`, `flow-view-zone-matrix.png`, `threat-map-heatmap.png`,
`threat-map-clusters.png`).

**Eine bewusste Abweichung:** Die Karte des Originals lädt Kacheln von einem
Kartendienst. Wir zeichnen weiter aus mitgelieferter Geometrie. Eine
Kachelkarte verrät bei jedem Schwenk an einen Dritten, welche Weltgegend man
sich ansieht — bei einem Werkzeug zur Auswertung des eigenen Netzverkehrs ist
das ein Widerspruch, und ohne Internet im LXC bliebe die Karte leer. Aussehen
und Bedienung gleichen wir an, die Herkunft der Geometrie nicht.

## 4. Was geprüft wird

Aussehen lässt sich nicht sinnvoll per Zusicherung testen, und niemand sollte
so tun. Geprüft wird deshalb:

- `npm run build` und `npm test` bleiben grün, `tsc` meldet nichts.
- Jede Ansicht rendert mit leeren Daten, ohne zu werfen — der Sankey-Absturz
  kam genau daher.
- Reine Hilfsfunktionen (Farbe je Aktion, Formatierung großer Zahlen,
  Flaggenzeichen aus Ländercode) bekommen Vitest-Tests.
- Die Beurteilung des Aussehens macht ein Mensch im Browser, nebeneinander
  mit dem Screenshot.

## 5. Nicht in dieser Phase

Einstellungen, Setup-Assistent, Firewall-Matrix, Login — die gehören zu
Phase 4 und werden dann im hier festgelegten Stil gebaut.
