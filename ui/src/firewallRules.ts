/**
 * Die Namen der Firewall-Regeln, wie sie im Controller stehen.
 *
 * Im Log steht `CUSTOM2_CUSTOM1-A-10008` und daneben eine Beschreibung, die
 * die Firewall bei 29 Zeichen abschneidet — aus „VL15 -> VL10 - Allow Pihole
 * DNS and WebUI" wird „VL15 -> VL10 - Allow Pihole D". `/api/firewall-rules`
 * liefert den vollen Namen, einmal beim Start geholt.
 *
 * Gleiche Bauweise wie `interfaceLabels.ts` und aus demselben Grund getrennt
 * von `LogHelpers.ts`: dort ist kein Solid erlaubt, hier braucht es ein
 * Signal, damit sich die Tabelle neu zeichnet, wenn die Antwort eintrifft.
 */
import { createSignal } from 'solid-js';

export interface FirewallRule {
  name: string;
  src_zone: string | null;
  dst_zone: string | null;
  /** Die Vorgaberegeln am Ende jeder Kette; sie heißen alle gleich. */
  predefined: boolean;
}

const [rules, setRules] = createSignal<Record<string, FirewallRule>>({});

/** Holt die Namen. Scheitert es, bleibt es bei dem, was im Log steht. */
export async function loadFirewallRules(): Promise<void> {
  try {
    const res = await fetch('/api/firewall-rules');
    if (!res.ok) return;
    const body = (await res.json()) as { rules?: Record<string, FirewallRule> };
    setRules(body.rules ?? {});
  } catch {
    // Ohne Controller oder ohne Netz zeigt die Tabelle weiter die Beschreibung
    // aus der Log-Zeile — kürzer, aber richtig.
  }
}

/**
 * Der lesbare Name einer Regel.
 *
 * Die vordefinierten Regeln heißen im Controller alle „Allow All Traffic" oder
 * „Block All Traffic" — achtunddreißig Regeln mit demselben Namen sagen nichts
 * über die Zeile, in der sie stehen. Bei ihnen stehen deshalb die Zonen davor:
 * „Gateway → External · Allow All Traffic". Bei selbst angelegten Regeln nicht
 * — deren Name nennt die Richtung ohnehin meist selbst („VL15 -> VL10 - …"),
 * und zweimal dasselbe ist keine Erklärung, sondern Länge.
 */
export function describeRule(rule: FirewallRule | null | undefined): string | null {
  if (!rule) return null;
  if (!rule.predefined) return rule.name;
  const zones = [rule.src_zone, rule.dst_zone];
  if (zones.every(Boolean)) return `${zones[0]} → ${zones[1]} · ${rule.name}`;
  return rule.name;
}

/** Der Name aus dem Controller zu einem Regelnamen aus dem Log, falls bekannt. */
export function ruleLabel(ruleName: string | null | undefined): string | null {
  if (!ruleName) return null;
  return describeRule(rules()[ruleName]);
}
