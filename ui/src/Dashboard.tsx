import { createEffect, createMemo, createSignal, For, Show } from 'solid-js';
import { countryName } from './country';
import CountryFlag from './CountryFlag';
import {
  ALLOWED_PILL_CLASS,
  BLOCKED_PILL_CLASS,
  formatNumber,
  formatShare,
  logTypeClass,
  sortLogTypeEntries,
  THREATS_PILL_CLASS,
} from './DashFormat';
import { TrafficByActionChart, TrafficOverTimeChart, type SeriesPoint } from './DashCharts';

interface Stats {
  total: number;
  blocked: number;
  allowed: number;
  by_type: Record<string, number>;
  by_direction: Record<string, number>;
  unique_sources: number;
  threats: number;
}

interface Series {
  bucket: string;
  points: SeriesPoint[];
}

interface TopRow {
  key: string;
  label: string;
  count: number;
  extra: Record<string, unknown> | null;
}

type Dimension =
  | 'countries'
  | 'sources'
  | 'destinations'
  | 'ports'
  | 'rules'
  | 'interfaces'
  | 'asns'
  | 'threats';

// Titel bewusst auf Englisch, wie im geklonten Original — anders als der
// Rest der Oberfläche, die deutschsprachig ist. Diese Ansicht wird Pixel für
// Pixel mit den Referenz-Screenshots verglichen, und `by_type` liefert seine
// Schlüssel (firewall, dhcp, …) ohnehin schon englisch.
const DIMENSIONS: { id: Dimension; title: string }[] = [
  { id: 'countries', title: 'Countries' },
  { id: 'sources', title: 'Sources' },
  { id: 'destinations', title: 'Destinations' },
  { id: 'ports', title: 'Ports' },
  { id: 'rules', title: 'Rules' },
  { id: 'interfaces', title: 'Interfaces' },
  { id: 'asns', title: 'ASNs' },
  { id: 'threats', title: 'Threat IPs' },
];

// Werte aus dem Fork (ui/src/utils.js): Zeichen und Farbe je Richtung.
const DIRECTION_ICONS: Record<string, string> = {
  inbound: '↓', outbound: '↑', inter_vlan: '⇔', nat: '⤴', local: '⟳', vpn: '⛨',
};
const DIRECTION_COLORS: Record<string, string> = {
  inbound: 'text-red-400', outbound: 'text-blue-400', inter_vlan: 'text-gray-300',
  nat: 'text-yellow-400', local: 'text-gray-400', vpn: 'text-teal-400',
};

const EMPTY_STATS: Stats = { total: 0, blocked: 0, allowed: 0, by_type: {}, by_direction: {}, unique_sources: 0, threats: 0 };

function buildUrl(path: string, query: string, extra?: Record<string, string>): string {
  const params = new URLSearchParams(query);
  if (extra) for (const [k, v] of Object.entries(extra)) params.set(k, v);
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  return (await res.json()) as T;
}

/** Der Filter, den ein Klick auf eine Top-Zeile dieser Dimension setzt. */
function filterFor(dim: Dimension, row: TopRow): Record<string, string> {
  switch (dim) {
    case 'countries':
      return { country: row.key };
    case 'sources':
      return { q: `src:${row.key}` };
    case 'destinations':
      return { q: `dst:${row.key}` };
    case 'ports':
      return { port: row.key };
    case 'rules':
      return { q: `rule:"${row.label}"` };
    case 'interfaces':
      return { iface: row.key };
    case 'asns':
      return { q: `asn:${row.label || row.key}` };
    case 'threats':
      return { q: row.key, threat_min: '50' };
  }
}

function extraNumber(row: TopRow, key: string): number | null {
  const v = row.extra?.[key];
  return typeof v === 'number' ? v : null;
}

function extraString(row: TopRow, key: string): string | null {
  const v = row.extra?.[key];
  return typeof v === 'string' && v !== '' ? v : null;
}

/** Ländercode für die Flagge vor der Zeile — nur wo die Zeile wirklich einen
 * mitbringt, statt für alle Dimensionen einen zu erfinden. */
function flagCodeFor(dim: Dimension, row: TopRow): string | null {
  if (dim === 'countries') return row.key || null;
  if (dim === 'threats') return extraString(row, 'country');
  return null;
}

/** Was in der Zeile steht. Länder tragen ihren Code nur noch im Tooltip —
 * der Name sagt mehr, und gefiltert wird ohnehin über `row.key`. */
function rowLabel(dim: Dimension, row: TopRow): string {
  return dim === 'countries' ? countryName(row.key) || row.key : row.label;
}

/** Kleine Zusatzinfo unter dem Zeilennamen — je Dimension etwas anderes. Der
 * Blockiert-Anteil steht separat rechts in der Zeile, taucht hier also nicht
 * noch einmal auf. */
function subline(dim: Dimension, row: TopRow): string {
  switch (dim) {
    case 'sources':
    case 'destinations':
      return extraString(row, 'asn') ?? '';
    case 'rules':
      return extraString(row, 'descr') ?? '';
    case 'threats': {
      const score = extraNumber(row, 'max_threat');
      return score != null ? `Score ${score}` : '';
    }
    default:
      return '';
  }
}

const CARD = 'rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4';
const CARD_TITLE = 'text-xs font-medium uppercase tracking-wider text-[var(--muted)]';
const PILL = 'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold uppercase border';

/** Kennzahlen, Zeitreihe und Top-Listen — alle drei teilen sich `props.query`
 * und laden neu, sobald sich der Filter ändert. */
export default function Dashboard(props: { query: string; onFilter: (patch: Record<string, string>) => void }) {
  const [stats, setStats] = createSignal<Stats>(EMPTY_STATS);
  const [series, setSeries] = createSignal<Series>({ bucket: '', points: [] });
  const [tops, setTops] = createSignal<Partial<Record<Dimension, TopRow[]>>>({});

  createEffect(() => {
    const q = props.query;
    let cancelled = false;

    fetchJson<Stats>(buildUrl('/api/stats', q)).then((s) => {
      if (!cancelled) setStats(s);
    });
    fetchJson<Series>(buildUrl('/api/stats/series', q)).then((s) => {
      if (!cancelled) setSeries(s);
    });
    setTops({});
    for (const dim of DIMENSIONS) {
      fetchJson<{ rows: TopRow[] }>(buildUrl('/api/stats/top', q, { what: dim.id, limit: '8' })).then((res) => {
        if (!cancelled) setTops((prev) => ({ ...prev, [dim.id]: res.rows ?? [] }));
      });
    }

    return () => {
      cancelled = true;
    };
  });

  const points = createMemo(() => series().points ?? []);
  const byTypeEntries = createMemo(() => sortLogTypeEntries(Object.entries(stats().by_type ?? {})));

  // Richtungen absteigend nach Menge — die Vorlage zeigt die stärkste zuerst.
  const byDirectionEntries = createMemo(() =>
    Object.entries(stats().by_direction ?? {}).sort((a, b) => b[1] - a[1]),
  );

  return (
    <div class="flex flex-col gap-4">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Traffic Overview: Gesamtzahl, Aktions-Pillen, Richtungs-Pillen. */}
        <div class={CARD}>
          <div class={`${CARD_TITLE} mb-3`}>Traffic Overview</div>
          <div class="flex items-baseline gap-2 mb-3">
            <span class="text-2xl font-semibold text-[var(--fg)]">{formatNumber(stats().total)}</span>
            <span class="text-xs text-[var(--muted)]">total logs</span>
          </div>
          <div class="flex flex-wrap items-center gap-1.5">
            <span class={`${PILL} ${ALLOWED_PILL_CLASS}`}>Allowed {formatNumber(stats().allowed)}</span>
            <span class={`${PILL} ${BLOCKED_PILL_CLASS}`}>Blocked {formatNumber(stats().blocked)}</span>
            <span class={`${PILL} ${THREATS_PILL_CLASS}`}>Threats {formatNumber(stats().threats)}</span>
          </div>
          <Show when={byDirectionEntries().length > 0}>
            <div class="mt-3 flex flex-wrap items-center gap-1.5 border-t border-[var(--border)] pt-3">
              <For each={byDirectionEntries()}>
                {([dir, n]) => (
                  <button
                    type="button"
                    onClick={() => props.onFilter({ direction: dir })}
                    class={`${PILL} border-transparent bg-[var(--surface)] hover:bg-[var(--surface-hover)]`}
                  >
                    <span class={DIRECTION_COLORS[dir] ?? 'text-gray-400'}>
                      {DIRECTION_ICONS[dir] ?? ''}
                    </span>{' '}
                    <span class="uppercase text-[var(--muted)]">
                      {dir === 'inter_vlan' ? 'vlan' : dir}
                    </span>{' '}
                    <span class="text-[var(--fg)]">{formatNumber(n)}</span>
                  </button>
                )}
              </For>
            </div>
          </Show>
        </div>

        <div class={CARD}>
          <div class={`${CARD_TITLE} mb-3`}>Log Types</div>
          <div class="flex flex-wrap gap-1.5">
            <For each={byTypeEntries()}>
              {([type, n]) => <span class={`${PILL} ${logTypeClass(type)}`}>{type} {formatNumber(n)}</span>}
            </For>
            <Show when={byTypeEntries().length === 0}>
              <span class="text-xs text-[var(--muted)]">No data</span>
            </Show>
          </div>
        </div>
      </div>

      <div class={CARD}>
        <div class={`${CARD_TITLE} mb-3`}>Traffic Over Time</div>
        <TrafficOverTimeChart points={points()} bucket={series().bucket} />
      </div>

      <div class={CARD}>
        <div class="flex items-center justify-between mb-3">
          <div class={CARD_TITLE}>Traffic by Action</div>
          <div class="flex items-center gap-4">
            <span class="flex items-center gap-1 text-xs text-emerald-700 dark:text-emerald-400">
              <span class="w-2 h-2 rounded-full bg-emerald-500" /> Allowed
            </span>
            <span class="flex items-center gap-1 text-xs text-red-700 dark:text-red-400">
              <span class="w-2 h-2 rounded-full bg-red-500" /> Blocked
            </span>
          </div>
        </div>
        <TrafficByActionChart points={points()} bucket={series().bucket} />
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <For each={DIMENSIONS}>
          {(dim) => {
            const rows = createMemo(() => tops()[dim.id] ?? []);
            const max = createMemo(() => Math.max(1, ...rows().map((r) => r.count)));
            return (
              <div class={`${CARD} flex flex-col`}>
                <div class={`${CARD_TITLE} mb-3`}>{dim.title}</div>
                <Show when={rows().length === 0}>
                  <div class="flex-1 flex items-center justify-center text-sm text-[var(--muted)] py-4">No data</div>
                </Show>
                <div class="flex flex-col">
                  <For each={rows()}>
                    {(row) => {
                      const blocked = createMemo(() => extraNumber(row, 'blocked'));
                      const flagCode = flagCodeFor(dim.id, row);
                      const sub = subline(dim.id, row);
                      return (
                        <button
                          type="button"
                          class="w-full text-left py-1.5 px-1 -mx-1 rounded hover:bg-[var(--surface-hover)]"
                          onClick={() => props.onFilter(filterFor(dim.id, row))}
                          title={`${row.label} (${row.key})`}
                        >
                          <div class="flex items-center justify-between gap-2 text-sm">
                            <span class="flex items-center gap-1.5 min-w-0">
                              <Show when={flagCode}>
                                <CountryFlag code={flagCode} />
                              </Show>
                              <span class="truncate text-[var(--fg)]">{rowLabel(dim.id, row)}</span>
                            </span>
                            <span class="shrink-0 flex items-baseline gap-2">
                              <span class="text-[var(--fg)]">{formatNumber(row.count)}</span>
                              <Show when={blocked() != null && blocked()! > 0}>
                                <span class="text-[var(--danger-fg)] text-xs">{formatShare(blocked()!, row.count)}</span>
                              </Show>
                            </span>
                          </div>
                          <Show when={sub}>
                            <div class="text-xs text-[var(--muted)] truncate">{sub}</div>
                          </Show>
                          {/* Balken unter der Zeile — der rote Abschnitt zeigt
                              den blockierten Teil, wo die API ihn mitliefert.
                              Bei Bedrohungen bleibt er weg: dort ist jede
                              Zeile per Definition (Score ≥ 50) schon auffällig,
                              ein Balken würde nur das Ranking wiederholen. */}
                          <Show when={dim.id !== 'threats'}>
                            <div class="h-1 rounded-full bg-[var(--border)] mt-1 overflow-hidden">
                              <div
                                class="h-full rounded-full relative bg-[var(--accent)]"
                                style={{ width: `${(row.count / max()) * 100}%` }}
                              >
                                <Show when={blocked() != null && blocked()! > 0}>
                                  <div
                                    class="h-full absolute inset-y-0 left-0 rounded-full bg-[var(--danger-fg)]"
                                    style={{ width: `${(blocked()! / row.count) * 100}%` }}
                                  />
                                </Show>
                              </div>
                            </div>
                          </Show>
                        </button>
                      );
                    }}
                  </For>
                </div>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
