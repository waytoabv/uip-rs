// Reine Geometrie fürs handgezeichnete Flächendiagramm — kein Solid-Import,
// damit Skalierung und Pfadaufbau ohne DOM testbar sind (DashChartMath.test.ts).
// Eine Bibliothek für zwei Flächenpfade lohnt nicht (siehe Vorgabe); die
// Rechnung dahinter verdient trotzdem eigene Tests statt in der Komponente
// mitzulaufen.

/** Lineare Skala von [0, domainMax] auf [rangeMax, rangeMin] — gespiegelt,
 * weil SVG-y nach unten wächst. `domainMax <= 0` (keine Daten oder alles
 * Null) ergibt eine flache Linie am oberen Rand statt einer Division durch
 * 0. */
export function yScale(domainMax: number, rangeMin: number, rangeMax: number): (v: number) => number {
  const max = domainMax > 0 ? domainMax : 1;
  return (v: number) => rangeMax - (Math.max(0, v) / max) * (rangeMax - rangeMin);
}

/** x-Position des i-ten von `n` Punkten, gleichmäßig über [left, right]
 * verteilt. Ein einzelner Punkt landet in der Mitte statt am linken Rand. */
export function xScale(n: number, left: number, right: number): (i: number) => number {
  if (n <= 1) return () => (left + right) / 2;
  return (i: number) => left + (i / (n - 1)) * (right - left);
}

/** SVG-Pfad einer gefüllten Fläche zwischen zwei Höhenverläufen: vorwärts
 * über die Oberkante, zurück über die Unterkante, geschlossen. Leere Eingabe
 * ergibt einen leeren Pfad statt zu werfen — wichtig, wenn ein Endpunkt (noch)
 * nichts liefert. */
export function areaPath(xs: number[], tops: number[], bottoms: number[]): string {
  const n = xs.length;
  if (n === 0) return '';
  const forward = xs.map((x, i) => `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${tops[i].toFixed(1)}`);
  const backward = [...xs.keys()].reverse().map((i) => `L ${xs[i].toFixed(1)} ${bottoms[i].toFixed(1)}`);
  return [...forward, ...backward, 'Z'].join(' ');
}

/** Bis zu `count` gleichmäßig verteilte, deduplizierte Indizes von `0` bis
 * `n - 1` — für Achsenbeschriftungen, die nicht an jedem Punkt kleben
 * sollen. Ist `n` selbst schon klein, kommt jeder Index einmal zurück. */
export function tickIndices(n: number, count: number): number[] {
  if (n <= 0) return [];
  if (n <= count || count <= 1) return [...Array(n).keys()];
  const idx = new Set<number>();
  for (let i = 0; i < count; i++) {
    idx.add(Math.round((i / (count - 1)) * (n - 1)));
  }
  return [...idx].sort((a, b) => a - b);
}
