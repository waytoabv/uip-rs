import { createEffect, createMemo, createSignal, For, Show } from 'solid-js';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import { scaleLinear, scaleSqrt } from 'd3-scale';
import { feature } from 'topojson-client';
import type { Topology } from 'topojson-specification';
import type { Feature, FeatureCollection, GeoJsonProperties, GeometryObject } from 'geojson';
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

const WIDTH = 960;
const HEIGHT = 500;

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

// Gelb bis Rot über den AbuseIPDB-Confidence-Bereich (0–100) — auf hellem wie
// dunklem Grund unterscheidbar, weil beide Enden gesättigt bleiben.
const threatColor = scaleLinear<string>().domain([0, 100]).range(['#f5b301', '#dc2626']).clamp(true);

async function fetchPoints(query: string): Promise<PointsResponse> {
  const res = await fetch(`/api/threats/points${query ? `?${query}` : ''}`);
  return (await res.json()) as PointsResponse;
}

/** Threat Map: woher blockierter Verkehr kommt, aus der mitgelieferten TopoJSON gezeichnet. */
export default function ThreatMap(props: { query: string; onFilter: (patch: Record<string, string>) => void }) {
  const [points, setPoints] = createSignal<ThreatPoint[]>([]);
  const [blockedTotal, setBlockedTotal] = createSignal(0);
  const [loaded, setLoaded] = createSignal(false);

  // Ändert sich der geteilte Filter, lädt die Karte neu.
  createEffect(() => {
    const q = props.query;
    let cancelled = false;
    setLoaded(false);
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

  // Sqrt-Skala: die Fläche, nicht der Radius, trägt die Anzahl.
  const radius = createMemo(() => {
    const max = points().reduce((m, p) => Math.max(m, p.count), 1);
    return scaleSqrt().domain([1, max]).range([2, 16]).clamp(true);
  });

  const projected = createMemo<Projected[]>(() =>
    points()
      .map((p) => {
        const xy = projection([p.lon, p.lat]);
        return xy ? { p, x: xy[0], y: xy[1] } : null;
      })
      .filter((v): v is Projected => v !== null),
  );

  const tooltip = (p: ThreatPoint) => {
    const where = p.city ? `${p.city}, ${p.country ?? '?'}` : (p.country ?? 'unbekannt');
    const lines = [where, `${p.count} blockiert`];
    if (p.max_threat != null) lines.push(`höchster Threat-Score: ${p.max_threat}`);
    if (p.sample_ip) lines.push(`z.B. ${p.sample_ip}`);
    return lines.join('\n');
  };

  return (
    <div class="threat-map">
      <style>{`
        .threat-map svg {
          display: block;
          width: 100%;
          height: auto;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 6px;
        }
        .threat-map .land {
          fill: var(--border);
          stroke: var(--bg);
          stroke-width: 0.5;
        }
        .threat-map .point {
          stroke: var(--bg);
          stroke-width: 0.5;
          cursor: pointer;
        }
        .threat-map .point:hover {
          stroke: var(--fg);
          stroke-width: 1;
        }
        .threat-map .point-unscored {
          fill: var(--muted);
        }
        .threat-map .empty-note {
          color: var(--danger-fg);
          padding: 0.6rem 0;
          margin: 0 0 0.5rem;
        }
      `}</style>
      <Show when={loaded() && points().length === 0}>
        <p class="empty-note">
          {blockedTotal() === 0
            ? 'Kein blockierter Verkehr in diesem Zeitfenster/Filter — die Karte hat schlicht nichts zu zeigen.'
            : `${blockedTotal()} blockierte Zeile${blockedTotal() === 1 ? '' : 'n'} in diesem Filter, aber keine ` +
              'davon ist geografisch angereichert: entweder fehlen die GeoIP-Datenbanken, oder die Anreicherung läuft noch.'}
        </p>
      </Show>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label="Karte des blockierten Verkehrs">
        <For each={countryShapes}>{(c) => <path class="land" d={c.d} />}</For>
        <For each={projected()}>
          {({ p, x, y }) => (
            <circle
              classList={{ point: true, 'point-unscored': p.max_threat == null }}
              cx={x}
              cy={y}
              r={radius()(p.count)}
              fill={p.max_threat != null ? threatColor(p.max_threat) : undefined}
              onClick={() => p.country && props.onFilter({ country: p.country })}
            >
              <title>{tooltip(p)}</title>
            </circle>
          )}
        </For>
      </svg>
    </div>
  );
}
