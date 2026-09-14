import { createEffect, createMemo, createSignal, For, onCleanup } from 'solid-js';

interface Stats {
  total: number;
  blocked: number;
  allowed: number;
  by_type: Record<string, number>;
  unique_sources: number;
  threats: number;
}

interface SeriesPoint {
  t: string;
  allowed: number;
  blocked: number;
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

const DIMENSIONS: { id: Dimension; title: string }[] = [
  { id: 'countries', title: 'Länder' },
  { id: 'sources', title: 'Quellen' },
  { id: 'destinations', title: 'Ziele' },
  { id: 'ports', title: 'Ports' },
  { id: 'rules', title: 'Regeln' },
  { id: 'interfaces', title: 'Schnittstellen' },
  { id: 'asns', title: 'ASNs' },
  { id: 'threats', title: 'Bedrohungen' },
];

const EMPTY_STATS: Stats = { total: 0, blocked: 0, allowed: 0, by_type: {}, unique_sources: 0, threats: 0 };

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

/** Kleine Zusatzinfo unter dem Zeilennamen — je Dimension etwas anderes. */
function subline(dim: Dimension, row: TopRow): string {
  const extra = row.extra ?? {};
  switch (dim) {
    case 'countries':
    case 'ports':
    case 'interfaces':
    case 'asns': {
      const blocked = extra['blocked'];
      return typeof blocked === 'number' && blocked > 0 ? `${blocked.toLocaleString()} blockiert` : '';
    }
    case 'sources':
    case 'destinations': {
      const asn = extra['asn'];
      return typeof asn === 'string' ? asn : '';
    }
    case 'rules': {
      const descr = extra['descr'];
      return typeof descr === 'string' ? descr : '';
    }
    case 'threats': {
      const score = extra['max_threat'];
      const country = extra['country'];
      const parts: string[] = [];
      if (typeof score === 'number') parts.push(`Score ${score}`);
      if (typeof country === 'string') parts.push(country);
      return parts.join(' · ');
    }
  }
}

/** Kennzahlen, Zeitreihe und Top-Listen — alle drei teilen sich `props.query`
 * und laden neu, sobald sich der Filter ändert. */
export default function Dashboard(props: { query: string; onFilter: (patch: Record<string, string>) => void }) {
  const [stats, setStats] = createSignal<Stats>(EMPTY_STATS);
  const [series, setSeries] = createSignal<Series>({ bucket: '', points: [] });
  const [tops, setTops] = createSignal<Partial<Record<Dimension, TopRow[]>>>({});
  const [hoverIdx, setHoverIdx] = createSignal<number | null>(null);

  createEffect(() => {
    const q = props.query;
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });

    fetchJson<Stats>(buildUrl('/api/stats', q)).then((s) => {
      if (!cancelled) setStats(s);
    });
    fetchJson<Series>(buildUrl('/api/stats/series', q)).then((s) => {
      if (!cancelled) setSeries(s);
    });
    setTops({});
    for (const dim of DIMENSIONS) {
      fetchJson<{ rows: TopRow[] }>(buildUrl('/api/stats/top', q, { what: dim.id, limit: '8' })).then((res) => {
        if (!cancelled) setTops((prev) => ({ ...prev, [dim.id]: res.rows }));
      });
    }
  });

  // ── Zeitreihe als handgezeichnetes SVG: zwei gestapelte Flächen, eine
  // Achse, ein Tooltip — eine Bibliothek für zwei Pfade lohnt nicht.
  const W = 760;
  const H = 180;
  const PAD_L = 40;
  const PAD_B = 20;
  const PAD_T = 10;
  const PAD_R = 10;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;

  const points = createMemo(() => series().points);
  const maxTotal = createMemo(() => Math.max(1, ...points().map((p) => p.allowed + p.blocked)));

  const xAt = (i: number) => {
    const n = points().length;
    return PAD_L + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  };
  const yAt = (v: number) => PAD_T + innerH * (1 - v / maxTotal());

  const areaPath = (topFn: (i: number) => number, bottomFn: (i: number) => number) => {
    const pts = points();
    if (pts.length === 0) return '';
    const forward = pts.map((_, i) => `${i === 0 ? 'M' : 'L'} ${xAt(i).toFixed(1)} ${topFn(i).toFixed(1)}`);
    const backward = pts
      .map((_, i) => i)
      .reverse()
      .map((i) => `L ${xAt(i).toFixed(1)} ${bottomFn(i).toFixed(1)}`);
    return [...forward, ...backward, 'Z'].join(' ');
  };

  const allowedArea = createMemo(() => areaPath((i) => yAt(points()[i].allowed), () => PAD_T + innerH));
  const blockedArea = createMemo(() =>
    areaPath(
      (i) => yAt(points()[i].allowed + points()[i].blocked),
      (i) => yAt(points()[i].allowed),
    ),
  );

  const onMove = (e: MouseEvent) => {
    const svg = e.currentTarget as SVGSVGElement;
    const rect = svg.getBoundingClientRect();
    const n = points().length;
    if (n === 0) {
      setHoverIdx(null);
      return;
    }
    const x = ((e.clientX - rect.left) / rect.width) * W;
    const frac = n <= 1 ? 0 : (x - PAD_L) / innerW;
    setHoverIdx(Math.min(n - 1, Math.max(0, Math.round(frac * (n - 1)))));
  };

  const hovered = createMemo(() => {
    const i = hoverIdx();
    return i == null ? null : (points()[i] ?? null);
  });

  const formatTime = (t: string) =>
    new Date(t).toLocaleString(undefined, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });

  return (
    <div class="dashboard">
      <style>{`
        .dashboard { display: flex; flex-direction: column; gap: 1rem; }
        .stat-tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); gap: 0.6rem; }
        .stat-tile { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 0.8rem; }
        .stat-tile .n { font-size: 1.5rem; font-weight: 700; }
        .stat-tile .l { color: var(--muted); font-size: 0.8rem; }
        .stat-tile.danger .n { color: var(--danger-fg); }
        .by-type { display: flex; flex-wrap: wrap; gap: 0.4rem; }
        .by-type span { background: var(--surface); border: 1px solid var(--border); border-radius: 999px; padding: 0.1rem 0.6rem; font-size: 0.8rem; color: var(--muted); }
        .series-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem; position: relative; }
        .series-panel svg { width: 100%; height: auto; display: block; }
        .series-legend { display: flex; gap: 1rem; font-size: 0.8rem; color: var(--muted); margin-bottom: 0.3rem; }
        .series-legend .sw { display: inline-block; width: 0.7rem; height: 0.7rem; border-radius: 2px; margin-right: 0.3rem; vertical-align: -1px; }
        .sw.allowed { background: var(--accent); }
        .sw.blocked { background: var(--danger-fg); }
        .tooltip { position: absolute; pointer-events: none; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.3rem 0.5rem; font-size: 0.8rem; transform: translate(-50%, -100%); white-space: nowrap; }
        .top-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 0.75rem; }
        .top-card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 0.8rem; }
        .top-card h3 { margin: 0 0 0.4rem; font-size: 0.85rem; color: var(--muted); font-weight: 600; }
        .top-row { display: flex; align-items: center; gap: 0.5rem; width: 100%; background: none; border: none; padding: 0.25rem 0; cursor: pointer; text-align: left; color: var(--fg); font: inherit; }
        .top-row:hover { background: var(--surface-hover); }
        .top-row .bar-wrap { flex: 1; min-width: 0; }
        .top-row .bar-label { display: flex; justify-content: space-between; font-size: 0.85rem; gap: 0.5rem; }
        .top-row .bar-label .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .top-row .bar-track { height: 4px; background: var(--border); border-radius: 2px; margin-top: 0.2rem; overflow: hidden; }
        .top-row .bar-fill { height: 100%; background: var(--accent); }
        .top-row .sub { color: var(--muted); font-size: 0.75rem; }
        .top-empty { color: var(--muted); font-size: 0.85rem; padding: 0.25rem 0; }
      `}</style>

      <div class="stat-tiles">
        <div class="stat-tile">
          <div class="n">{stats().total.toLocaleString()}</div>
          <div class="l">Gesamt</div>
        </div>
        <div class="stat-tile">
          <div class="n">{stats().allowed.toLocaleString()}</div>
          <div class="l">Erlaubt</div>
        </div>
        <div class="stat-tile danger">
          <div class="n">{stats().blocked.toLocaleString()}</div>
          <div class="l">Blockiert</div>
        </div>
        <div class="stat-tile danger">
          <div class="n">{stats().threats.toLocaleString()}</div>
          <div class="l">Bedrohungen (≥50)</div>
        </div>
        <div class="stat-tile">
          <div class="n">{stats().unique_sources.toLocaleString()}</div>
          <div class="l">Eindeutige Quellen</div>
        </div>
      </div>

      <div class="by-type">
        <For each={Object.entries(stats().by_type)}>
          {([type, n]) => (
            <span>
              {type}: {n.toLocaleString()}
            </span>
          )}
        </For>
      </div>

      <div class="series-panel">
        <div class="series-legend">
          <span>
            <span class="sw allowed" />
            Erlaubt
          </span>
          <span>
            <span class="sw blocked" />
            Blockiert
          </span>
          <span>Bucket: {series().bucket || '—'}</span>
        </div>
        <svg viewBox={`0 0 ${W} ${H}`} onMouseMove={onMove} onMouseLeave={() => setHoverIdx(null)}>
          <line x1={PAD_L} y1={PAD_T + innerH} x2={W - PAD_R} y2={PAD_T + innerH} stroke="var(--border)" />
          <path d={allowedArea()} fill="var(--accent)" fill-opacity="0.55" stroke="var(--accent)" stroke-width="1" />
          <path d={blockedArea()} fill="var(--danger-fg)" fill-opacity="0.55" stroke="var(--danger-fg)" stroke-width="1" />
          {hoverIdx() != null && (
            <line
              x1={xAt(hoverIdx() as number)}
              y1={PAD_T}
              x2={xAt(hoverIdx() as number)}
              y2={PAD_T + innerH}
              stroke="var(--muted)"
              stroke-dasharray="3,3"
            />
          )}
        </svg>
        {hovered() && (
          <div class="tooltip" style={{ left: `${(xAt(hoverIdx() as number) / W) * 100}%`, top: '0.5rem' }}>
            {formatTime(hovered()!.t)} — erlaubt {hovered()!.allowed.toLocaleString()}, blockiert{' '}
            {hovered()!.blocked.toLocaleString()}
          </div>
        )}
      </div>

      <div class="top-grid">
        <For each={DIMENSIONS}>
          {(dim) => {
            const rows = createMemo(() => tops()[dim.id] ?? []);
            const max = createMemo(() => Math.max(1, ...rows().map((r) => r.count)));
            return (
              <div class="top-card">
                <h3>{dim.title}</h3>
                {rows().length === 0 && <div class="top-empty">Keine Daten</div>}
                <For each={rows()}>
                  {(row) => (
                    <button class="top-row" onClick={() => props.onFilter(filterFor(dim.id, row))} title={row.label}>
                      <div class="bar-wrap">
                        <div class="bar-label">
                          <span class="name">{row.label}</span>
                          <span>{row.count.toLocaleString()}</span>
                        </div>
                        <div class="bar-track">
                          <div class="bar-fill" style={{ width: `${(row.count / max()) * 100}%` }} />
                        </div>
                        {subline(dim.id, row) && <div class="sub">{subline(dim.id, row)}</div>}
                      </div>
                    </button>
                  )}
                </For>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
