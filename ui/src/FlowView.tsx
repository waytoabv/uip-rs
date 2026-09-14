import { createEffect, createMemo, createSignal, For, type Component } from 'solid-js';
import { scaleLinear } from 'd3-scale';
import { sankeyLinkHorizontal } from 'd3-sankey';
import {
  computeLayout,
  HEIGHT,
  WIDTH,
  type LinkExtra,
  type NodeDatum,
  type SankeyResponse,
  type SLink,
  type SNode,
} from './sankeyLayout';

interface Props {
  query: string;
  onFilter: (patch: Record<string, string>) => void;
}

interface ZoneCell {
  from: string;
  to: string;
  allowed: number;
  blocked: number;
}

interface ZonesResponse {
  zones: string[];
  cells: ZoneCell[];
}

async function fetchSankey(query: string): Promise<SankeyResponse> {
  const res = await fetch(`/api/flows/sankey${query ? `?${query}` : ''}`);
  return (await res.json()) as SankeyResponse;
}

async function fetchZones(query: string): Promise<ZonesResponse> {
  const res = await fetch(`/api/flows/zones${query ? `?${query}` : ''}`);
  return (await res.json()) as ZonesResponse;
}

function isOther(n: { id: string }): boolean {
  return n.id.endsWith(':__other__');
}

const linkPath = sankeyLinkHorizontal<NodeDatum, LinkExtra>();

/** Fluss (Sankey) und Zonenmatrix — zwei Sichten auf denselben Filter. */
const FlowView: Component<Props> = (props) => {
  const [sankeyData, setSankeyData] = createSignal<SankeyResponse>({ nodes: [], links: [] });
  const [zonesData, setZonesData] = createSignal<ZonesResponse>({ zones: [], cells: [] });

  // Ändert sich der geteilte Filter, laden beide Endpunkte neu — dieselbe
  // Auswahl, zwei Blickwinkel.
  createEffect(() => {
    const q = props.query;
    fetchSankey(q).then(setSankeyData);
    fetchZones(q).then(setZonesData);
  });

  const graph = createMemo(() => computeLayout(sankeyData()));

  const cellIndex = createMemo(() => {
    const map = new Map<string, ZoneCell>();
    for (const c of zonesData().cells) map.set(`${c.from}|${c.to}`, c);
    return map;
  });

  const maxZoneVolume = createMemo(() =>
    zonesData().cells.reduce((m, c) => Math.max(m, c.allowed + c.blocked), 0),
  );

  const intensity = createMemo(() =>
    scaleLinear().domain([0, maxZoneVolume() || 1]).range([10, 85]).clamp(true),
  );

  // Adressknoten filtern auf die Adresse, Dienstknoten auf den Port —
  // "Weitere" ist ein Sammelknoten und trägt keinen Filterwert.
  const handleNodeClick = (n: SNode) => {
    if (isOther(n)) return;
    if (n.kind === 'service') {
      const port = n.label.split('/')[0];
      if (/^\d+$/.test(port)) props.onFilter({ port });
      return;
    }
    props.onFilter({ q: n.label });
  };

  const handleCellClick = (from: string, cell: ZoneCell | undefined) => {
    if (!cell) return;
    props.onFilter({ iface: from });
  };

  return (
    <div class="flow-view">
      <style>{`
        .flow-view {
          display: flex;
          gap: 1rem;
          align-items: flex-start;
        }
        .flow-sankey, .flow-zones {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 0.75rem;
        }
        .flow-sankey {
          flex: 3 1 26rem;
          min-width: 0;
        }
        .flow-zones {
          flex: 2 1 18rem;
          min-width: 0;
          overflow-x: auto;
        }
        .flow-view h2 {
          margin: 0 0 0.5rem;
          font-size: 1rem;
          color: var(--muted);
        }
        .sankey-svg {
          width: 100%;
          height: auto;
          overflow: visible;
        }
        .sankey-node rect {
          fill: var(--accent);
          stroke: var(--border);
        }
        .sankey-node.clickable {
          cursor: pointer;
        }
        .sankey-node.other rect {
          fill: var(--muted);
        }
        .sankey-node text {
          fill: var(--fg);
          font-size: 11px;
          pointer-events: none;
        }
        .sankey-link {
          fill: none;
          opacity: 0.55;
        }
        .sankey-link:hover {
          opacity: 0.85;
        }
        .zone-matrix {
          border-collapse: collapse;
        }
        .zone-matrix th,
        .zone-matrix td {
          border: 1px solid var(--border);
          padding: 0.25rem 0.4rem;
          text-align: center;
          white-space: nowrap;
          font-size: 0.85rem;
        }
        .zone-matrix th {
          color: var(--muted);
          font-weight: 600;
        }
        .zone-matrix th.zone-row-label {
          text-align: right;
        }
        .zone-cell.clickable {
          cursor: pointer;
        }
        .zone-blocked {
          color: var(--danger-fg);
        }
      `}</style>

      <section class="flow-sankey">
        <h2>Fluss: Quelle → Dienst → Ziel</h2>
        {sankeyData().nodes.length === 0 ? (
          <p class="view-placeholder">Keine Flussdaten für die aktuelle Auswahl.</p>
        ) : (
          <svg class="sankey-svg" viewBox={`0 0 ${WIDTH} ${HEIGHT}`}>
            <g>
              <For each={graph().links as SLink[]}>
                {(l) => {
                  const pct = l.value ? Math.round((l.blocked / l.value) * 100) : 0;
                  return (
                    <path
                      class="sankey-link"
                      d={linkPath(l) ?? undefined}
                      stroke-width={Math.max(1, l.width ?? 1)}
                      style={{ stroke: `color-mix(in srgb, var(--danger-fg) ${pct}%, var(--accent))` }}
                    />
                  );
                }}
              </For>
            </g>
            <g>
              <For each={graph().nodes as SNode[]}>
                {(n) => {
                  const x0 = n.x0 ?? 0;
                  const x1 = n.x1 ?? 0;
                  const y0 = n.y0 ?? 0;
                  const y1 = n.y1 ?? 0;
                  const other = isOther(n);
                  const labelPos =
                    n.depth === 0
                      ? { x: x0 - 8, y: (y0 + y1) / 2, anchor: 'end' as const, dy: '0.32em' }
                      : n.kind === 'destination'
                        ? { x: x1 + 8, y: (y0 + y1) / 2, anchor: 'start' as const, dy: '0.32em' }
                        : { x: (x0 + x1) / 2, y: y0 - 6, anchor: 'middle' as const, dy: '0' };
                  return (
                    <g
                      classList={{ 'sankey-node': true, clickable: !other, other }}
                      onClick={() => handleNodeClick(n)}
                    >
                      <rect x={x0} y={y0} width={Math.max(1, x1 - x0)} height={Math.max(1, y1 - y0)} />
                      <text x={labelPos.x} y={labelPos.y} dy={labelPos.dy} text-anchor={labelPos.anchor}>
                        {n.label}
                      </text>
                    </g>
                  );
                }}
              </For>
            </g>
          </svg>
        )}
      </section>

      <section class="flow-zones">
        <h2>Zonen</h2>
        {zonesData().zones.length === 0 ? (
          <p class="view-placeholder">Kein Zonenverkehr für die aktuelle Auswahl.</p>
        ) : (
          <table class="zone-matrix">
            <thead>
              <tr>
                <th></th>
                <For each={zonesData().zones}>{(z) => <th>{z}</th>}</For>
              </tr>
            </thead>
            <tbody>
              <For each={zonesData().zones}>
                {(from) => (
                  <tr>
                    <th class="zone-row-label">{from}</th>
                    <For each={zonesData().zones}>
                      {(to) => {
                        const cell = () => cellIndex().get(`${from}|${to}`);
                        return (
                          <td
                            classList={{ 'zone-cell': true, clickable: !!cell() }}
                            style={
                              cell()
                                ? {
                                    background: `color-mix(in srgb, var(--accent) ${intensity()(
                                      (cell()!.allowed + cell()!.blocked),
                                    )}%, var(--surface))`,
                                  }
                                : undefined
                            }
                            onClick={() => handleCellClick(from, cell())}
                          >
                            {cell() ? (
                              <>
                                {cell()!.allowed}
                                {cell()!.blocked > 0 ? <span class="zone-blocked"> / {cell()!.blocked}</span> : null}
                              </>
                            ) : null}
                          </td>
                        );
                      }}
                    </For>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
};

export default FlowView;
