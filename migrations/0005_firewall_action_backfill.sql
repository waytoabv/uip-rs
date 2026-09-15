-- Bestehende Firewall-Zeilen tragen die falsche Aktion.
--
-- `derive_action` (crates/uip-ingest/src/firewall.rs) las den Aktionsbuchstaben
-- nur aus dem LETZTEN Segment des Regelnamens. Die zonenbasierte Firewall hängt
-- dort aber ihren Index an (`DMZ_LOCAL-D-10002`), sodass der Buchstabe nie
-- gefunden wurde und der Rückfall aus jeder geblockten Zeile eine erlaubte
-- machte. Der Parser ist repariert; das hier holt die Historie nach.
--
-- Dieselbe Ableitung wie im Parser, in derselben Reihenfolge: der von rechts
-- gesehen erste Buchstabe im Namen gewinnt, sonst der Hinweis in der
-- Beschreibung (hinter einem `[ZONE]`-Präfix). Der Rest bleibt, wie er ist —
-- `rule_action_id IS NULL` heißt „keine Regel", nicht „unbekannte Aktion".
UPDATE logs l
SET rule_action_id = d.action_id
FROM (
    SELECT
        r.id,
        COALESCE(
            CASE (
                SELECT seg
                FROM unnest(string_to_array(r.name, '-')) WITH ORDINALITY AS t(seg, ord)
                WHERE seg IN ('A', 'D', 'R')
                ORDER BY t.ord DESC
                LIMIT 1
            )
                WHEN 'A' THEN 1 WHEN 'D' THEN 2 WHEN 'R' THEN 3
            END,
            CASE
                WHEN regexp_replace(lower(r.descr), '^[^]]*\]\s*', '') LIKE ANY (ARRAY['block%', 'deny%', 'drop%']) THEN 2
                WHEN regexp_replace(lower(r.descr), '^[^]]*\]\s*', '') LIKE ANY (ARRAY['allow%', 'accept%']) THEN 1
            END
        )::smallint AS action_id
    FROM rules r
    WHERE r.name IS NOT NULL
) d
WHERE l.rule_id = d.id
  AND d.action_id IS NOT NULL
  AND l.rule_action_id IS DISTINCT FROM d.action_id;
