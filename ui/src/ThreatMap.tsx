import { createEffect, createMemo, createSignal, For, Show, type JSX } from 'solid-js';
import { countryName } from './country';
import CountryFlag from './CountryFlag';
import { fetchLogs, type LogRow } from './api';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import { scaleLinear, scaleSqrt } from 'd3-scale';
import { feature } from 'topojson-client';
import type { Topology } from 'topojson-specification';
import type { Feature, FeatureCollection, GeoJsonProperties, GeometryObject } from 'geojson';
import { useIsDark } from './VizTheme';
// Mitgelieferte TopoJSON, Teil des Bundles — im Betrieb geht dafür keine
// einzige Anfrage nach außen ("Keine Karten-Kacheln von fremden Servern").
import worldTopology from 'world-atlas/countries-110m.json';

interface ThreatPoint {
  lat: number;
  lon: number;
  country: string | null;
  city: string | null;
  count: number;
  max_threat: number | null;
  sample_ip: string | null;
}

interface PointsResponse {
  points: ThreatPoint[];
  blocked_total: number;
}

interface Projected {
  p: ThreatPoint;
  x: number;
  y: number;
}

interface SelectedLocation {
  country: string | null;
  city: string | null;
  count: number;
  maxThreat: number | null;
}

const WIDTH = 960;
const HEIGHT = 500;

type ViewMode = 'heatmap' | 'clusters';
const VIEWS: { id: ViewMode; label: string }[] = [
  { id: 'heatmap', label: 'Heatmap' },
  { id: 'clusters', label: 'Cluster' },
];

// Fünf Stufen, absteigend nach Schwelle sortiert — passend zu einem
// AbuseIPDB-artigen Confidence-Wert (0–100). Farben wie im Original:
// Kritisch/Hoch/Mittel/Niedrig/Sauber. `text`/`dot` sind Tailwind-Klassen mit
// `dark:`-Gegenstück (kippen von selbst mit dem Theme); `hex` speist die
// SVG-Kreisfüllung direkt und braucht deshalb — kein CSS greift auf ein
// Attribut — zwei feste Werte, siehe `levelHex`.
const THREAT_LEVELS = [
  {
    min: 75,
    label: 'Kritisch',
    text: 'text-red-600 dark:text-red-400',
    dot: 'bg-red-600 dark:bg-red-400',
    hex: { light: '#dc2626', dark: '#f87171' },
  },
  {
    min: 50,
    label: 'Hoch',
    text: 'text-orange-600 dark:text-orange-400',
    dot: 'bg-orange-600 dark:bg-orange-400',
    hex: { light: '#ea580c', dark: '#fb923c' },
  },
  {
    min: 25,
    label: 'Mittel',
    text: 'text-yellow-700 dark:text-yellow-400',
    dot: 'bg-yellow-600 dark:bg-yellow-400',
    hex: { light: '#ca8a04', dark: '#facc15' },
  },
  {
    min: 1,
    label: 'Niedrig',
    text: 'text-blue-600 dark:text-blue-400',
    dot: 'bg-blue-600 dark:bg-blue-400',
    hex: { light: '#2563eb', dark: '#60a5fa' },
  },
  {
    min: 0,
    label: 'Sauber',
    text: 'text-emerald-600 dark:text-emerald-400',
    dot: 'bg-emerald-600 dark:bg-emerald-400',
    hex: { light: '#059669', dark: '#34d399' },
  },
];

function levelFor(score: number | null | undefined): (typeof THREAT_LEVELS)[number] | null {
  if (score == null || Number.isNaN(score)) return null;
  return THREAT_LEVELS.find((t) => score >= t.min) ?? THREAT_LEVELS[THREAT_LEVELS.length - 1];
}

function levelHex(level: (typeof THREAT_LEVELS)[number] | null, dark: boolean): string | null {
  if (!level) return null;
  return dark ? level.hex.dark : level.hex.light;
}

const ACTION_TEXT: Record<string, string> = {
  block: 'text-red-600 dark:text-red-400',
  allow: 'text-emerald-600 dark:text-emerald-400',
  redirect: 'text-yellow-700 dark:text-yellow-400',
};

// Länder und Projektion sind pro Ladevorgang konstant — einmal auf
// Modulebene aufgebaut statt bei jedem Render neu berechnet.
const topology = worldTopology as unknown as Topology;
const worldCountries = feature(
  topology,
  topology.objects.countries as Parameters<typeof feature>[1],
) as FeatureCollection<GeometryObject, GeoJsonProperties>;

const projection = geoNaturalEarth1().fitSize([WIDTH, HEIGHT], worldCountries);
const pathGen = geoPath(projection);

const countryShapes: { id: string; d: string }[] = worldCountries.features
  .map((f: Feature<GeometryObject, GeoJsonProperties>) => ({ id: String(f.id ?? ''), d: pathGen(f) }))
  .filter((c: { id: string; d: string | null }): c is { id: string; d: string } => c.d !== null);

// Warme Rampe für die Heatmap-Ansicht — dieselben Farbstufen wie im Original
// (gelb → orange → dunkelrot), hier über den normierten Anteil an der
// größten Punktgröße statt über eine echte Dichteschätzung. Zwei Rampen: die
// helle liegt auf einer fast weißen Fläche (Ozean = `var(--bg)`) und braucht
// dafür kräftigere, weniger transparente Stufen als die dunkle, sonst
// verschwinden gerade die unteren Stufen.
const HEAT_DOMAIN = [0, 0.05, 0.25, 0.5, 0.75, 1];
const heatColorDark = scaleLinear<string>()
  .domain(HEAT_DOMAIN)
  .range(['rgba(250,204,21,0.15)', 'rgba(250,204,21,0.5)', '#f59e0b', '#ef4444', '#dc2626', '#991b1b'])
  .clamp(true);
const heatColorLight = scaleLinear<string>()
  .domain(HEAT_DOMAIN)
  .range(['rgba(202,138,4,0.25)', 'rgba(202,138,4,0.6)', '#ea580c', '#dc2626', '#b91c1c', '#7f1d1d'])
  .clamp(true);
const heatGradientCss = {
  dark: 'linear-gradient(to right, rgba(250,204,21,0.3), #facc15, #f59e0b, #ef4444, #991b1b)',
  light: 'linear-gradient(to right, rgba(202,138,4,0.35), #ca8a04, #ea580c, #dc2626, #7f1d1d)',
};

async function fetchPoints(query: string): Promise<PointsResponse> {
  const res = await fetch(`/api/threats/points${query ? `?${query}` : ''}`);
  return (await res.json()) as PointsResponse;
}

function mergeQuery(base: string, patch: Record<string, string>): string {
  const params = new URLSearchParams(base);
  for (const [k, v] of Object.entries(patch)) params.set(k, v);
  return params.toString();
}

function Row(props: { label: string; value: JSX.Element | string | null | undefined }) {
  return (
    <Show when={props.value}>
      <div class="flex items-baseline justify-between gap-2 py-0.5">
        <span class="shrink-0 text-xs text-gray-500">{props.label}</span>
        <span class="truncate text-right text-xs text-gray-700 dark:text-gray-300 dark:text-gray-200">{props.value}</span>
      </div>
    </Show>
  );
}

function Section(props: { title: string; children: JSX.Element }) {
  return (
    <div class="border-t border-gray-200/70 px-3 py-2 dark:border-gray-800/50">
      <div class="mb-1 text-xs uppercase tracking-wider text-gray-600 dark:text-gray-400">{props.title}</div>
      {props.children}
    </div>
  );
}

/** Detailansicht eines einzelnen Log-Eintrags in der Seitenleiste. */
function LogDetail(props: { log: LogRow; onBack: () => void }) {
  const log = () => props.log;
  return (
    <div class="flex min-h-0 flex-1 flex-col overflow-y-auto">
      <button
        type="button"
        onClick={props.onBack}
        class="flex shrink-0 items-center gap-1 border-b border-gray-200/70 px-3 py-1.5 text-xs text-gray-600 dark:text-gray-400 hover:text-gray-700 dark:border-gray-800/50 dark:hover:text-gray-200"
      >
        ← Zurück zur Liste
      </button>
      <div class="px-3 py-2 text-xs text-gray-500">{new Date(log().timestamp).toLocaleString('en-GB')}</div>
      <div class="px-3 pb-2">
        <Row
          label="Risiko"
          value={log().threat_score != null ? <span class={levelFor(log().threat_score)?.text}>{log().threat_score}</span> : null}
        />
        <Row
          label="Aktion"
          value={<span class={ACTION_TEXT[log().rule_action ?? ''] ?? 'text-gray-500'}>{log().rule_action ?? '—'}</span>}
        />
        <Row label="Direction" value={log().direction} />
      </div>
      <Section title="Quelle">
        <Row label="IP-Adresse" value={log().src_ip} />
        <Show when={log().src_port != null}>
          <Row label="Port" value={String(log().src_port)} />
        </Show>
      </Section>
      <Section title="Ziel">
        <Row label="IP-Adresse" value={log().dst_ip} />
        <Show when={log().dst_port != null}>
          <Row label="Port" value={String(log().dst_port)} />
        </Show>
        <Show when={log().geo_country}>
          <Row
            label="Region"
            value={
              <span class="inline-flex items-center gap-1">
                <CountryFlag code={log().geo_country} />
                {[log().geo_city, countryName(log().geo_country)].filter(Boolean).join(', ')}
              </span>
            }
          />
        </Show>
      </Section>
      <Section title="Verkehr">
        <Show when={log().protocol}>
          <Row label="Protokoll" value={log().protocol?.toUpperCase()} />
        </Show>
        <Show when={log().iface_in}>
          <Row label="Interface (ein)" value={log().iface_in} />
        </Show>
        <Show when={log().iface_out}>
          <Row label="Interface (aus)" value={log().iface_out} />
        </Show>
        <Show when={log().rule_name}>
          <Row label="Regel" value={log().rule_name} />
        </Show>
        <Show when={log().asn_name}>
          <Row label="ASN" value={log().asn_name} />
        </Show>
        <Show when={log().rdns}>
          <Row label="rDNS" value={log().rdns} />
        </Show>
      </Section>
    </div>
  );
}

/** Threat Map: woher blockierter Verkehr kommt, aus der mitgelieferten TopoJSON gezeichnet. */
export default function ThreatMap(props: { query: string; onFilter: (patch: Record<string, string>) => void }) {
  const [points, setPoints] = createSignal<ThreatPoint[]>([]);
  const [blockedTotal, setBlockedTotal] = createSignal(0);
  const [loaded, setLoaded] = createSignal(false);
  const [viewMode, setViewMode] = createSignal<ViewMode>('heatmap');
  const [selected, setSelected] = createSignal<SelectedLocation | null>(null);
  const [sidebarLogs, setSidebarLogs] = createSignal<LogRow[]>([]);
  const [sidebarLoading, setSidebarLoading] = createSignal(false);
  const [selectedLogId, setSelectedLogId] = createSignal<number | null>(null);
  const isDark = useIsDark();

  // Ändert sich der geteilte Filter, lädt die Karte neu.
  createEffect(() => {
    const q = props.query;
    let cancelled = false;
    setLoaded(false);
    setSelected(null);
    fetchPoints(q).then((body) => {
      if (cancelled) return;
      setPoints(body.points ?? []);
      setBlockedTotal(body.blocked_total ?? 0);
      setLoaded(true);
    });
    return () => {
      cancelled = true;
    };
  });

  // Ein Klick auf einen Punkt holt die dazu passenden Log-Zeilen — dieselbe
  // Filterauswahl, plus das angeklickte Land, plus block-Aktion (die Karte
  // zeigt ausschließlich blockierten/bewerteten Verkehr).
  createEffect(() => {
    const loc = selected();
    setSelectedLogId(null);
    if (!loc?.country) {
      setSidebarLogs([]);
      return;
    }
    let cancelled = false;
    setSidebarLoading(true);
    const q = mergeQuery(props.query, { country: loc.country, action: 'block' });
    fetchLogs(q)
      .then((rows) => {
        if (!cancelled) setSidebarLogs(rows);
      })
      .catch(() => {
        if (!cancelled) setSidebarLogs([]);
      })
      .finally(() => {
        if (!cancelled) setSidebarLoading(false);
      });
    return () => {
      cancelled = true;
    };
  });

  const maxCount = createMemo(() => points().reduce((m, p) => Math.max(m, p.count), 1));
  const totalEvents = createMemo(() => points().reduce((sum, p) => sum + p.count, 0));

  // Sqrt-Skala: die Fläche, nicht der Radius, trägt die Anzahl. Die
  // Heatmap-Ansicht bekommt größere, weichere Kreise, die Cluster-Ansicht
  // kompaktere mit Zahl darin — wie die zwei Ansichten des Originals.
  const clusterRadius = createMemo(() => scaleSqrt().domain([1, maxCount()]).range([5, 26]).clamp(true));
  const heatRadius = createMemo(() => scaleSqrt().domain([1, maxCount()]).range([12, 48]).clamp(true));
  const radius = () => (viewMode() === 'heatmap' ? heatRadius() : clusterRadius());

  const projected = createMemo<Projected[]>(() =>
    points()
      .map((p) => {
        const xy = projection([p.lon, p.lat]);
        return xy ? { p, x: xy[0], y: xy[1] } : null;
      })
      .filter((v): v is Projected => v !== null),
  );

  const selectedLog = createMemo(() => {
    const id = selectedLogId();
    return id == null ? null : (sidebarLogs().find((l) => l.id === id) ?? null);
  });

  const isSelectedPoint = (p: ThreatPoint) => {
    const loc = selected();
    return !!loc && loc.country === p.country && loc.city === p.city;
  };

  const pointColor = (p: ThreatPoint) => {
    if (viewMode() === 'heatmap') return (isDark() ? heatColorDark : heatColorLight)(p.count / maxCount());
    const level = levelFor(p.max_threat);
    return levelHex(level, isDark()) ?? (isDark() ? '#6b7280' : '#9ca3af');
  };

  const tooltip = (p: ThreatPoint) => {
    const land = countryName(p.country) || 'unbekannt';
    const where = p.city ? `${p.city}, ${land}` : land;
    const lines = [where, `${p.count.toLocaleString('en-GB')} blocked`];
    if (p.max_threat != null) lines.push(`höchster Threat-Score: ${p.max_threat}`);
    if (p.sample_ip) lines.push(`z.B. ${p.sample_ip}`);
    return lines.join('\n');
  };

  return (
    <div class="overflow-hidden rounded-lg border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-950">
      {/* Steuerzeile */}
      <div class="flex flex-wrap items-center gap-3 border-b border-gray-200 px-4 py-2.5 dark:border-gray-800">
        <div class="flex items-center gap-0.5">
          <For each={VIEWS}>
            {(v) => (
              <button
                type="button"
                onClick={() => setViewMode(v.id)}
                aria-pressed={viewMode() === v.id}
                class={
                  viewMode() === v.id
                    ? 'rounded border border-gray-300 bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-900 dark:border-gray-600 dark:bg-black dark:text-white'
                    : 'rounded border border-transparent px-2.5 py-1 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-600 dark:hover:text-gray-300'
                }
              >
                {v.label}
              </button>
            )}
          </For>
        </div>
        <div class="ml-auto flex items-center gap-3 text-xs text-gray-600 dark:text-gray-400">
          <Show when={!loaded()}>
            <span class="text-blue-600 dark:text-blue-400">Lädt…</span>
          </Show>
          <Show when={loaded()}>
            <span>{points().length.toLocaleString('en-GB')} locations</span>
            <span class="text-gray-700 dark:text-gray-300 dark:text-gray-700">|</span>
            <span>{totalEvents().toLocaleString('en-GB')} Ereignisse</span>
          </Show>
        </div>
      </div>

      {/* Karte + Seitenleiste */}
      <div class="flex">
        <div class="relative min-w-0 flex-1">
          {/* Hintergrund und Landmasse über CSS-Variablen statt Tailwind-Klassen:
              sie kippen von selbst mit dem Theme, ganz ohne JS. Die
              Länderkontur bekommt `var(--bg)` als Umrandung — derselbe Trick
              wie eine echte Karte: die Trennlinie zum "Ozean" ist einfach die
              Ozeanfarbe selbst, hell wie dunkel. */}
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            role="img"
            aria-label="Karte des blockierten Verkehrs"
            class="block h-auto w-full"
            style={{ background: 'var(--bg)' }}
          >
            <defs>
              <filter id="threat-heat-blur" x="-100%" y="-100%" width="300%" height="300%">
                <feGaussianBlur stdDeviation="6" />
              </filter>
            </defs>
            <For each={countryShapes}>
              {(c) => <path d={c.d} style={{ fill: 'var(--border)' }} stroke="var(--bg)" stroke-width="0.5" />}
            </For>
            <g style={viewMode() === 'heatmap' ? { 'mix-blend-mode': 'screen' } : undefined}>
              <For each={projected()}>
                {({ p, x, y }) => (
                  <circle
                    cx={x}
                    cy={y}
                    r={radius()(p.count)}
                    fill={pointColor(p)}
                    opacity={viewMode() === 'heatmap' ? 0.8 : p.max_threat != null ? 0.9 : 0.6}
                    filter={viewMode() === 'heatmap' ? 'url(#threat-heat-blur)' : undefined}
                    stroke={isSelectedPoint(p) ? 'var(--fg)' : 'rgba(0,0,0,0.4)'}
                    stroke-width={isSelectedPoint(p) ? 2 : 0.5}
                    class="cursor-pointer transition-opacity hover:opacity-100"
                    onClick={() => {
                      setSelected({ country: p.country, city: p.city, count: p.count, maxThreat: p.max_threat });
                      if (p.country) props.onFilter({ country: p.country });
                    }}
                  >
                    <title>{tooltip(p)}</title>
                  </circle>
                )}
              </For>
            </g>
            <Show when={viewMode() === 'clusters'}>
              <For each={projected()}>
                {({ p, x, y }) =>
                  radius()(p.count) >= 9 ? (
                    <text
                      x={x}
                      y={y}
                      text-anchor="middle"
                      dominant-baseline="central"
                      class="pointer-events-none fill-white"
                      style={{ 'font-size': '9px', 'font-weight': 600 }}
                    >
                      {p.count.toLocaleString('en-GB')}
                    </text>
                  ) : null
                }
              </For>
            </Show>
          </svg>

          {/* Leerzustand */}
          <Show when={loaded() && points().length === 0}>
            <div class="pointer-events-none absolute inset-0 flex items-center justify-center">
              <div class="max-w-xs rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950/90 px-6 py-4 text-center">
                <div class="text-sm font-medium text-gray-700 dark:text-gray-300">Keine Geodaten</div>
                <div class="mt-1 text-xs text-gray-500">
                  {blockedTotal() === 0
                    ? 'No blocked traffic in this window — the map simply has nothing to show.'
                    : `${blockedTotal().toLocaleString('en-GB')} blockierte Zeile${blockedTotal() === 1 ? '' : 'n'} in diesem Filter, aber keine ` +
                      'davon ist geografisch angereichert: entweder fehlen die GeoIP-Datenbanken, oder die Anreicherung läuft noch.'}
                </div>
              </div>
            </div>
          </Show>

          {/* Legende — je nach Ansicht Dichte-Rampe oder Bedrohungsstufen */}
          <Show when={points().length > 0}>
            <div class="pointer-events-none absolute bottom-4 left-4 rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950/90 px-3 py-2">
              <Show
                when={viewMode() === 'clusters'}
                fallback={
                  <>
                    {/* Die Legende selbst bleibt bewusst ein dunkler, fester
                        Chip in beiden Themes (wie im Original) — die Rampe
                        hier ist deshalb immer die dunkle Fassung, unabhängig
                        von `pointColor()`, das auf der eigentlichen Karte
                        zwischen hell/dunkel wechselt. */}
                    <div class="mb-1.5 text-[10px] uppercase tracking-wider text-gray-600 dark:text-gray-400">Ereignisdichte</div>
                    <div class="h-2 w-28 rounded-full" style={{ background: heatGradientCss.dark }} />
                    <div class="mt-0.5 flex w-28 justify-between text-[9px] text-gray-500">
                      <span>Weniger</span>
                      <span>Mehr</span>
                    </div>
                  </>
                }
              >
                <div class="mb-1.5 text-[10px] uppercase tracking-wider text-gray-600 dark:text-gray-400">Bedrohungsstufe</div>
                <div class="flex max-w-[220px] flex-wrap items-center gap-2 text-[10px] text-gray-800 dark:text-gray-200">
                  <For each={[...THREAT_LEVELS].reverse()}>
                    {(t) => (
                      <span class="flex items-center gap-1">
                        <span class={`inline-block h-2.5 w-2.5 rounded-full ${t.dot}`} />
                        {t.label}
                      </span>
                    )}
                  </For>
                </div>
                <div class="mt-1 text-[10px] text-gray-500">Kreisgröße = Ereigniszahl</div>
              </Show>
            </div>
          </Show>
        </div>

        {/* Seitenleiste — events am angeklickten Ort */}
        <Show when={selected()}>
          {(loc) => (
            <div class="flex max-h-[34rem] w-72 shrink-0 flex-col border-l border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950">
              <div class="flex shrink-0 items-center justify-between border-b border-gray-200 dark:border-gray-800 px-3 py-2">
                <div class="min-w-0">
                  <div class="flex items-center gap-1.5 truncate text-sm font-medium text-gray-800 dark:text-gray-200">
                    <CountryFlag code={loc().country} />
                    {[loc().city, countryName(loc().country)].filter(Boolean).join(', ') || 'Unbekannt'}
                  </div>
                  <div class="text-xs text-gray-500">
                    {loc().count.toLocaleString('en-GB')} events
                    <Show when={loc().maxThreat != null}> · Score {loc().maxThreat}</Show>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSelected(null)}
                  class="shrink-0 p-1 text-gray-500 hover:text-gray-900 dark:hover:text-gray-300"
                  title="Schließen"
                >
                  ×
                </button>
              </div>

              <Show when={sidebarLoading()}>
                <div class="flex flex-1 items-center justify-center py-6">
                  <span class="text-xs text-blue-400">Lädt Ereignisse…</span>
                </div>
              </Show>
              <Show when={!sidebarLoading() && sidebarLogs().length === 0}>
                <div class="flex flex-1 items-center justify-center py-6">
                  <span class="text-xs text-gray-500">Keine events gefunden</span>
                </div>
              </Show>
              <Show when={!sidebarLoading() && sidebarLogs().length > 0}>
                {selectedLog() ? (
                  <LogDetail log={selectedLog()!} onBack={() => setSelectedLogId(null)} />
                ) : (
                  <div class="flex-1 overflow-y-auto">
                    <For each={sidebarLogs()}>
                      {(log) => (
                        <button
                          type="button"
                          onClick={() => setSelectedLogId(log.id)}
                          class="w-full border-b border-gray-200 dark:border-gray-800/50 px-3 py-2 text-left transition-colors hover:bg-gray-200 dark:hover:bg-gray-800/30"
                        >
                          <div class="flex items-center justify-between gap-2">
                            <span class="flex-1 truncate text-xs text-gray-800 dark:text-gray-200">
                              {log.src_ip}
                              {log.src_port != null ? `:${log.src_port}` : ''}
                            </span>
                            <Show when={log.threat_score != null}>
                              <span class={levelFor(log.threat_score)?.text ?? 'text-gray-600 dark:text-gray-400'}>{log.threat_score}</span>
                            </Show>
                          </div>
                          <div class="mt-0.5 flex items-center justify-between gap-2">
                            <span class={`text-xs font-semibold uppercase ${ACTION_TEXT[log.rule_action ?? ''] ?? 'text-gray-500'}`}>
                              {log.rule_action ?? log.log_type ?? '—'}
                            </span>
                            <span class="text-xs text-gray-500">{new Date(log.timestamp).toLocaleString('en-GB')}</span>
                          </div>
                        </button>
                      )}
                    </For>
                  </div>
                )}
              </Show>
            </div>
          )}
        </Show>
      </div>
    </div>
  );
}
