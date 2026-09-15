// Reine Geometrie fürs handgezeichnete Flächendiagramm — kein Solid-Import,
// damit Skalierung und Pfadaufbau ohne DOM testbar sind (DashChartMath.test.ts).
// Für die eigentliche Kurve genügt `d3-shape` (schon eine Abhängigkeit des
// Projekts) — die Rechnung dahinter verdient trotzdem eigene Tests statt in
// der Komponente mitzulaufen.

import { area as d3Area, curveMonotoneX } from 'd3-shape';

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

/** Dieselbe gefüllte Fläche wie `areaPath`, nur mit weich geschwungener
 * Ober- und Unterkante statt gerader Linien zwischen den Punkten — wie im
 * Original. `curveMonotoneX` statt z. B. `curveNatural`, weil es zwischen
 * zwei Punkten nie über deren Werte hinausschießt: eine Kurve, die von 0 auf
 * einen hohen Wert steigt, taucht unterwegs nie unter 0. Weniger als zwei
 * Punkte ergeben keine sinnvolle Kurve — dann zurück auf die gerade Fläche. */
export function curvedAreaPath(xs: number[], tops: number[], bottoms: number[]): string {
  const n = xs.length;
  if (n < 2) return areaPath(xs, tops, bottoms);
  const gen = d3Area<number>()
    .x((_, i) => xs[i])
    .y1((_, i) => tops[i])
    .y0((_, i) => bottoms[i])
    .curve(curveMonotoneX);
  return gen(xs) ?? '';
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

/**
 * Rundet auf einen "schönen" Wert: 1, 2, 2.5, 5 oder 10 mal eine Zehnerpotenz.
 */
function niceNum(range: number, round: boolean): number {
  const exp = Math.floor(Math.log10(range));
  const f = range / 10 ** exp;
  let nf: number;
  if (round) {
    nf = f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10;
  } else {
    nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  }
  return nf * 10 ** exp;
}

/**
 * Obergrenze und Teilstriche einer Achse.
 *
 * Das rohe Maximum als Obergrenze zu nehmen ergibt Beschriftungen wie
 * "1183204" und lässt die Fläche oben am Rand kleben. Der Fork rundet auf
 * glatte Schritte (0, 300k, 600k, 900k, 1200k) — das ist der sichtbare
 * Unterschied in der Skalierung, nicht bloß Kosmetik: an krummen Zahlen
 * lässt sich nichts ablesen.
 */
export function niceAxis(max: number, tickCount = 4): { max: number; ticks: number[] } {
  if (!Number.isFinite(max) || max <= 0) {
    return { max: 1, ticks: [0, 1] };
  }
  const step = niceNum(niceNum(max, false) / tickCount, true);
  const top = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let v = 0; v <= top + step / 2; v += step) {
    // Gleitkomma-Reste wegputzen: 0.1+0.2 soll 0.3 heißen, nicht 0.30000000004.
    ticks.push(Number(v.toFixed(10)));
  }
  return { max: top, ticks };
}
