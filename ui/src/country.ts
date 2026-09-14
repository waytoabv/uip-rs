/**
 * ISO-3166-Alpha-2-Code zu Ländername.
 *
 * Bewusst im Browser statt als Tabelle in der Datenbank: `Intl.DisplayNames`
 * bringt die Namen in der Sprache des Betrachters mit, kostet kein einziges
 * Byte im Bundle und veraltet nicht, wenn sich ein Land umbenennt. Eine
 * gepflegte Tabelle wäre eine Kopie derselben Daten, die irgendwann
 * auseinanderläuft.
 *
 * Der Code bleibt trotzdem sichtbar, wo Platz ist: er ist die Kennung, nach
 * der man filtert und sucht, und er ist eindeutig, wo Namen es nicht sind.
 */

const display = (() => {
  try {
    return new Intl.DisplayNames(undefined, { type: 'region' });
  } catch {
    return null; // sehr alte Umgebung — dann bleibt es beim Code
  }
})();

/** "CN" → "China". Unbekanntes oder Fehlendes gibt den Code zurück. */
export function countryName(code: string | null | undefined): string {
  if (!code) return '';
  const upper = code.toUpperCase();
  // Intl kennt nur zweibuchstabige Regionen und dreistellige UN-Codes;
  // alles andere gibt es unverändert zurück.
  if (!/^[A-Z]{2}$/.test(upper)) return upper;
  try {
    return display?.of(upper) ?? upper;
  } catch {
    return upper;
  }
}

/** "CN" → "China (CN)", für Listen, in denen man auch filtern will. */
export function countryLabel(code: string | null | undefined): string {
  if (!code) return '';
  const name = countryName(code);
  const upper = code.toUpperCase();
  return name === upper ? upper : `${name} (${upper})`;
}
