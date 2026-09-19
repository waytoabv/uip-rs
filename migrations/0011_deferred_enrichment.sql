-- Ein eigener Zustand für „wartet auf Kontingent".
--
-- Bisher kannte `enrich_status` nur 0=offen, 1=fertig, 2=fehlgeschlagen,
-- 3=in Arbeit. War das AbuseIPDB-Kontingent alle, schrieb der Worker die
-- Zeile auf 0 zurück, damit der Score später nachgereicht werden kann.
--
-- Das war eine Schleife. `claim` holt sich die offenen Zeilen, also sofort
-- wieder dieselben; das Kontingent ist immer noch alle; sie gehen wieder auf
-- 0. Und weil `run_worker` nur dann schläft, wenn ein Durchlauf nichts
-- gefunden hat, lief das ohne Pause durch. In der Produktionsdatenbank standen
-- dadurch 1,4 Milliarden Updates gegen 10 Millionen Inserts — 139 je Zeile.
-- Jedes davon war nicht-HOT, weil `enrich_status` indiziert ist, also ein
-- neuer Eintrag in jedem der sieben Indexe. Das ist der Grund, warum die
-- Indexe dort 71 % der Datenbank ausmachten und ihre Blattdichte bei einem
-- Drittel lag.
--
-- 4 heißt jetzt „zurückgestellt". `claim` nimmt nur 0, die Zeile liegt also
-- still. `reopen_deferred` öffnet sie wieder — einmal je Kontingentfenster,
-- nicht einmal je Durchlauf.
COMMENT ON COLUMN logs.enrich_status IS
    '0=offen 1=fertig 2=fehlgeschlagen 3=in Arbeit 4=zurückgestellt (Kontingent)';

-- Damit das Wiederöffnen ein Indexscan bleibt und kein Durchlauf über die
-- Hypertable. Partiell, also so klein wie die Zahl der wartenden Zeilen —
-- und deckungsgleich mit `idx_logs_enrich_pending`, nur für den anderen Wert.
CREATE INDEX IF NOT EXISTS idx_logs_enrich_deferred ON logs (timestamp, id)
    WHERE enrich_status = 4;
