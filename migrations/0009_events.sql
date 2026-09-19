-- Was eine Zeile über sich selbst sagt, jenseits von Adressen und Ports.
--
-- Drei Dinge fehlten, und alle drei betreffen die Zeilen, die bisher nur als
-- Rohtext dastanden:
--
--   * der Schweregrad — er steckt im Syslog-Kopf (`<30>` = Facility 3,
--     Severity 6) und wurde bisher beim Zerlegen weggeworfen. Ohne ihn sind
--     siebenundzwanzigtausend System-Zeilen am Tag nicht nach „wichtig" zu
--     sortieren;
--   * das Programm, das die Zeile geschrieben hat (`systemd`, `mca-ctrl`,
--     `dbus-daemon`) — als Nachschlagetabelle wie Protokolle und
--     Schnittstellen, weil es wenige sind und sie sich ständig wiederholen;
--   * die Felder strukturierter Ereignisse. Das Gateway schickt seine
--     Ereignisse im CEF-Format über dasselbe Syslog: WLAN-Verbindungen mit
--     Access Point, SSID, Kanal und Signalstärke, Firewall-Blockaden mit
--     Zieldomain und Anwendung, Änderungen an der Konfiguration mit dem
--     Namen der Einstellung. Für jedes dieser Felder eine Spalte anzulegen
--     hieße, das Schema jedem neuen Ereignistyp des Herstellers
--     hinterherzuschieben — `details` nimmt sie als JSON, und die Detailzeile
--     der Oberfläche zeigt, was da ist.
CREATE TABLE programs (
    id   SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(64) NOT NULL
);
CREATE UNIQUE INDEX idx_programs_key ON programs (lower(name));

ALTER TABLE logs
    ADD COLUMN severity   SMALLINT,
    ADD COLUMN program_id SMALLINT,
    ADD COLUMN details    JSONB;
