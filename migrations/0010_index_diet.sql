-- Zwei Indexe, die mehr kosten als sie tragen.
--
-- `idx_logs_type_time` war in der Entwicklungsdatenbank das größte Objekt
-- überhaupt: 54 MB gegen 58 MB Heap — und 67 Scans, bei 948.000 auf dem
-- Primärschlüssel. Die führende Spalte ist `log_type_id`, und die trägt für
-- 99 % der Zeilen denselben Wert (Firewall). Ein Index, dessen erste Spalte
-- fast konstant ist, kann nichts einschränken; schlimmer, er zerlegt die
-- Sortierung, die den Rest billig macht. Dass er ungenutzt bleibt, ist kein
-- Zufall der Testdaten: jede Stelle, die überhaupt nach der Art fragt, fragt
-- nach genau diesem einen Wert (`threats.rs`, `flows.rs`, `collector.rs`).
--
-- Für die seltenen Arten — DNS, DHCP, WLAN, System — bleibt ein partieller
-- Index, der die Firewall-Zeilen ausspart: dieselbe Auskunft für die Fälle,
-- in denen sie hilft, zu einem Prozent der Größe.
--
-- `logs_timestamp_idx` hat `create_hypertable` selbst angelegt. Der
-- Primärschlüssel ist (timestamp, id) und deckt ihn als Präfix vollständig
-- ab; die Zeilenliste sortiert nach genau diesem Paar. Künftige Hypertables
-- sollten ihn gar nicht erst bekommen (`create_default_indexes => FALSE`).
DROP INDEX IF EXISTS idx_logs_type_time;
DROP INDEX IF EXISTS logs_timestamp_idx;

CREATE INDEX IF NOT EXISTS idx_logs_type_time_rare ON logs (log_type_id, timestamp DESC, id DESC)
    WHERE log_type_id <> 1;

-- Luft auf der Seite, damit ein Update die Zeile am selben Ort ersetzen kann,
-- statt in jedem Index einen neuen Eintrag zu hinterlassen (HOT). In der
-- Entwicklungsdatenbank waren 0,27 % der Updates HOT und die Blattdichte der
-- Indexe bei 33–41 % statt der 90 %, die reines Anhängen erreicht.
--
-- Das hilft nur den Updates, die keine indizierte Spalte anfassen — solange
-- `enrich_status` und `threat_score` beim Anreichern gesetzt werden, bleibt
-- der Rest nicht-HOT. Die eigentliche Antwort darauf ist, die Zeile fertig zu
-- schreiben statt sie nachzubessern; das hier ist die Hälfte, die ohne
-- Umbau zu haben ist. Gilt für neue Chunks, nicht rückwirkend.
ALTER TABLE logs SET (fillfactor = 85);
