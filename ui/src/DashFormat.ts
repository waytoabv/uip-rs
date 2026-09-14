// Reine Formatierungs- und Farb-Helfer fürs Dashboard — ohne Solid-Import,
// damit sie sich ohne DOM in Vitest testen lassen (siehe DashFormat.test.ts).

/** "2148180" → "2,148,180". Fest auf `en-US`, damit das Ergebnis unabhängig
 * von der Locale der Testumgebung ist — im Browser sieht es dank derselben
 * Ziffern- und Trennzeichenkonvention genauso aus. */
export function formatNumber(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return '—';
  return n.toLocaleString('en-US');
}

/** Große Zahl für Achsenbeschriftungen: "300000" → "300k", "1200000" →
 * "1.2M". Rein kosmetisch, deshalb keine Rundungsgarantie über eine
 * Nachkommastelle hinaus. */
export function formatCompactNumber(n: number): string {
  const v = Math.max(0, n);
  if (v >= 1_000_000) {
    const m = v / 1_000_000;
    return `${m % 1 === 0 ? m.toFixed(0) : m.toFixed(1)}M`;
  }
  if (v >= 1_000) return `${Math.round(v / 1000)}k`;
  return `${Math.round(v)}`;
}

/** Anteil von `part` an `total`, als gerundete Prozentzahl. `<1%` statt
 * `0%`, wenn tatsächlich etwas da ist — sonst sähe ein winziger, aber realer
 * Anteil aus wie gar keiner. Ein leerer oder negativer Nenner ergibt `0%`
 * statt einer Division durch 0. */
export function formatShare(part: number, total: number): string {
  if (!total || total <= 0 || part <= 0) return '0%';
  const pct = (part / total) * 100;
  if (pct < 1) return '<1%';
  return `${Math.round(pct)}%`;
}

/** Reihenfolge, in der Log-Typ-Pillen erscheinen — unbekannte Typen fallen
 * ans Ende statt die Liste durcheinanderzuwürfeln. */
const LOG_TYPE_ORDER = ['firewall', 'dns', 'dhcp', 'wifi', 'system'];

export function sortLogTypeEntries(entries: [string, number][]): [string, number][] {
  return [...entries].sort(([a], [b]) => {
    const ia = LOG_TYPE_ORDER.indexOf(a);
    const ib = LOG_TYPE_ORDER.indexOf(b);
    return (ia === -1 ? LOG_TYPE_ORDER.length : ia) - (ib === -1 ? LOG_TYPE_ORDER.length : ib);
  });
}

// Farbklassen je Log-Typ, an die Original-Palette angelehnt (gelesen aus
// deren utils.js für Farbwerte, nicht für Code). Helle Klassen zuerst als
// Tailwind-Basis, `dark:` überschreibt für das dunkle Standarddesign
// (index.css macht Dunkel zum Normalfall, solange kein `data-theme="light"`
// gesetzt ist).
const LOG_TYPE_CLASSES: Record<string, string> = {
  firewall:
    'bg-blue-500/10 text-blue-700 border-blue-500/30 dark:bg-blue-500/15 dark:text-blue-400 dark:border-blue-500/30',
  dns: 'bg-violet-500/10 text-violet-700 border-violet-500/30 dark:bg-violet-500/15 dark:text-violet-400 dark:border-violet-500/30',
  dhcp: 'bg-cyan-500/10 text-cyan-700 border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-400 dark:border-cyan-500/30',
  wifi: 'bg-amber-500/10 text-amber-700 border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/30',
  system:
    'bg-gray-500/10 text-gray-700 border-gray-500/30 dark:bg-gray-500/15 dark:text-gray-300 dark:border-gray-500/30',
};
const DEFAULT_LOG_TYPE_CLASS = LOG_TYPE_CLASSES.system;

export function logTypeClass(type: string): string {
  return LOG_TYPE_CLASSES[type] ?? DEFAULT_LOG_TYPE_CLASS;
}

export const ALLOWED_PILL_CLASS =
  'bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-400 dark:border-emerald-500/30';
export const BLOCKED_PILL_CLASS =
  'bg-red-500/10 text-red-700 border-red-500/40 dark:bg-red-500/20 dark:text-red-400 dark:border-red-500/40';
export const THREATS_PILL_CLASS =
  'bg-orange-500/10 text-orange-700 border-orange-500/30 dark:bg-orange-500/15 dark:text-orange-400 dark:border-orange-500/30';
