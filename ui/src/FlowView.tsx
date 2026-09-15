import { createEffect, createMemo, createSignal, For, Show, type Component } from 'solid-js';
import { sankeyLinkHorizontal } from 'd3-sankey';
import VizHostPanel from './VizHostPanel';
import VizPairs from './VizPairs';
import {
  computeLayout,
  HEADER_HEIGHT,
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

type PanelKey = 'sankey' | 'zones' | 'pairs';
const PANELS: { key: PanelKey; label: string }[] = [
  { key: 'sankey', label: 'Flow Graph' },
  { key: 'zones', label: 'Zone Matrix' },
  { key: 'pairs', label: 'IP Pairs' },
];

// Eine Farbe je Knotenart — wie die Spaltenfarben des Originals (Quelle
// Türkis, Dienst Violett, Ziel Grün), hier direkt über `kind` statt über die
// x-Position bestimmt, weil unser Sankey immer genau diese drei Spalten hat.
const KIND_STYLE: Record<NodeDatum['kind'], { node: string; link: string; label: string }> = {
  source: { node: '#14b8a6', link: 'rgba(20,184,166,0.5)', label: 'Source' },
  service: { node: '#a855f7', link: 'rgba(168,85,247,0.5)', label: 'Service' },
  destination: { node: '#22c55e', link: 'rgba(34,197,94,0.5)', label: 'Destination' },
};
const OTHER_STYLE = { node: '#6b7280', link: 'rgba(107,114,128,0.35)' };

// Fünf Stufen von Blau (überwiegend erlaubt) nach Rosa/Rot (überwiegend
// blockiert) — dieselbe Idee wie ZoneMatrix im Original, nur nach Anteil
// blockiert statt nach Gesamtvolumen gestuft.
const ZONE_TIERS = [
  { bg: '#0ea5e9', fg: '#f0f9ff' },
  { bg: '#6366f1', fg: '#eef2ff' },
  { bg: '#8b5cf6', fg: '#f5f3ff' },
  { bg: '#d946ef', fg: '#fdf4ff' },
  { bg: '#ec4899', fg: '#fdf2f8' },
];

function zoneTier(total: number, maxTotal: number): { bg: string; fg: string } | null {
  if (!total || maxTotal <= 0) return null;
  const r = Math.log10(total + 1) / Math.log10(maxTotal + 1);
  if (r < 0.2) return ZONE_TIERS[0];
  if (r < 0.4) return ZONE_TIERS[1];
  if (r < 0.6) return ZONE_TIERS[2];
  if (r < 0.8) return ZONE_TIERS[3];
  return ZONE_TIERS[4];
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

/** Fluss (Sankey) und Zonenmatrix — zwei Sichten auf denselben Filter, als Unterreiter wie im Original. */
const FlowView: Component<Props> = (props) => {
  const [sankeyData, setSankeyData] = createSignal<SankeyResponse>({ nodes: [], links: [] });
  const [zonesData, setZonesData] = createSignal<ZonesResponse>({ zones: [], cells: [] });
  const [panel, setPanel] = createSignal<PanelKey>('sankey');
  const [activeNode, setActiveNode] = createSignal<{ kind: string; label: string } | null>(null);
  const [activeCell, setActiveCell] = createSignal<{ from: string; to: string } | null>(null);
  // Welche Adresse gerade aufgeschlüsselt wird. Ein Klick filtert weiterhin;
  // die Leiste kommt zusätzlich, weil Filtern die Frage "was macht dieser
  // Host?" nicht beantwortet, sondern nur die Liste kürzt.
  const [hostIp, setHostIp] = createSignal<string | null>(null);

  // Ändert sich der geteilte Filter, laden beide Endpunkte neu — dieselbe
  // Auswahl, zwei Blickwinkel.
  createEffect(() => {
    const q = props.query;
    fetchSankey(q).then(setSankeyData);
    fetchZones(q).then(setZonesData);
  });

  const graph = createMemo(() => computeLayout(sankeyData()));

  // Spaltenüberschriften: eine je eindeutiger x0-Position, Farbe/Beschriftung
  // von der ersten "echten" (nicht "Weitere") Knotenart dieser Spalte.
  const columnHeaders = createMemo(() => {
    const nodes = graph().nodes as SNode[];
    if (!nodes.length) return [];
    const byX0 = new Map<number, SNode[]>();
    for (const n of nodes) {
      const x0 = n.x0 ?? 0;
      const arr = byX0.get(x0) ?? [];
      arr.push(n);
      byX0.set(x0, arr);
    }
    const cols = [...byX0.entries()].sort((a, b) => a[0] - b[0]);
    return cols.map(([x0, ns], i) => {
      const x1 = ns[0]?.x1 ?? x0;
      const kind = (ns.find((n) => !isOther(n)) ?? ns[0]).kind;
      const isFirst = i === 0;
      const isLast = i === cols.length - 1;
      return {
        x: isFirst ? x0 : isLast ? x1 : (x0 + x1) / 2,
        anchor: (isFirst ? 'start' : isLast ? 'end' : 'middle') as 'start' | 'end' | 'middle',
        color: KIND_STYLE[kind].node,
        label: KIND_STYLE[kind].label,
      };
    });
  });

  const cellIndex = createMemo(() => {
    const map = new Map<string, ZoneCell>();
    for (const c of zonesData().cells) map.set(`${c.from}|${c.to}`, c);
    return map;
  });

  const maxZoneTotal = createMemo(() =>
    zonesData().cells.reduce((m, c) => Math.max(m, c.allowed + c.blocked), 0),
  );

  const isActiveNode = (n: SNode) => {
    const a = activeNode();
    return !!a && a.kind === n.kind && a.label === n.label;
  };
  const isDimmedNode = (n: SNode) => {
    const a = activeNode();
    return !!a && a.kind === n.kind && !isActiveNode(n) && !isOther(n);
  };

  // Adressknoten filtern auf die Adresse, Dienstknoten auf den Port —
  // "Weitere" ist ein Sammelknoten und trägt keinen Filterwert.
  const handleNodeClick = (n: SNode) => {
    if (isOther(n)) return;
    setActiveNode((prev) => (prev && prev.kind === n.kind && prev.label === n.label ? null : { kind: n.kind, label: n.label }));
    if (n.kind === 'service') {
      const port = n.label.split('/')[0];
      if (/^\d+$/.test(port)) props.onFilter({ port });
      return;
    }
    setHostIp(n.label);
    props.onFilter({ q: n.label });
  };

  const handleCellClick = (from: string, to: string, cell: ZoneCell | undefined) => {
    if (!cell) return;
    setActiveCell((prev) => (prev && prev.from === from && prev.to === to ? null : { from, to }));
    // Gerichtet, nicht nur die Quelle: eine Zelle ist der Verkehr von X
    // nach Y, und `iface` allein träfe auch die Gegenrichtung.
    props.onFilter({ iface_in: from, iface_out: to, iface: '' });
  };

  return (
    <div class="flex flex-col gap-3">
      <style>{`
        .flow-link { opacity: 0.35; transition: opacity 0.15s ease; }
        .flow-link:hover { opacity: 0.9; }
        .flow-node.clickable { cursor: pointer; }
        .flow-node text { pointer-events: none; }
      `}</style>

      {/* Unterreiter — wie im Original zwei Ansichten desselben Filters */}
      <div class="flex items-center gap-1">
        <For each={PANELS}>
          {(p) => (
            <button
              type="button"
              onClick={() => setPanel(p.key)}
              aria-pressed={panel() === p.key}
              class={
                panel() === p.key
                  ? 'rounded border border-gray-400 dark:border-gray-600 bg-white dark:bg-black px-3 py-1.5 text-xs font-medium text-gray-900 dark:text-white'
                  : 'rounded border border-transparent px-3 py-1.5 text-xs font-medium text-gray-500 hover:text-gray-900 dark:hover:text-gray-300'
              }
            >
              {p.label}
            </button>
          )}
        </For>
      </div>

      <Show when={panel() === 'sankey'}>
        <div class="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950">
          <div class="flex h-11 items-center gap-3 border-b border-gray-200 dark:border-gray-800 px-4">
            <h3 class="text-xs font-semibold uppercase tracking-wider text-gray-700 dark:text-gray-300">Flow Graph</h3>
          </div>
          <div class="overflow-x-auto p-3">
            {sankeyData().nodes.length === 0 ? (
              <p class="py-10 text-center text-sm text-gray-500">No flow data for the current selection.</p>
            ) : (
              <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} class="h-auto w-full min-w-[32rem]" style={{ overflow: 'visible' }}>
                {/* Spaltenüberschriften */}
                <g>
                  <For each={columnHeaders()}>
                    {(h) => (
                      <text
                        x={h.x}
                        y={HEADER_HEIGHT - 12}
                        text-anchor={h.anchor}
                        fill={h.color}
                        class="font-semibold uppercase tracking-wider"
                        style={{ 'font-size': '10px' }}
                      >
                        {h.label}
                      </text>
                    )}
                  </For>
                </g>

                {/* Verbindungen — Grundfarbe nach Herkunftsspalte, zu Rot
                    verschoben im Verhältnis zum blockierten Anteil. */}
                <g fill="none">
                  <For each={graph().links as SLink[]}>
                    {(l) => {
                      const source = l.source as SNode;
                      const base = isOther(source) ? OTHER_STYLE.link : KIND_STYLE[source.kind].link;
                      const pct = l.value ? Math.round((l.blocked / l.value) * 100) : 0;
                      return (
                        <path
                          class="flow-link"
                          d={linkPath(l) ?? undefined}
                          stroke-width={Math.max(1, l.width ?? 1)}
                          style={{ stroke: `color-mix(in srgb, ${base}, #ef4444 ${pct}%)` }}
                        >
                          <title>
                            {source.label} → {(l.target as SNode).label}: {l.value.toLocaleString()} ({pct}% blockiert)
                          </title>
                        </path>
                      );
                    }}
                  </For>
                </g>

                {/* Knoten */}
                <g>
                  <For each={graph().nodes as SNode[]}>
                    {(n) => {
                      const x0 = n.x0 ?? 0;
                      const x1 = n.x1 ?? 0;
                      const y0 = n.y0 ?? 0;
                      const y1 = n.y1 ?? 0;
                      const other = isOther(n);
                      const active = isActiveNode(n);
                      const dimmed = isDimmedNode(n);
                      const color = other ? OTHER_STYLE.node : KIND_STYLE[n.kind].node;
                      const labelPos =
                        n.depth === 0
                          ? { x: x0 - 8, y: (y0 + y1) / 2, anchor: 'end' as const }
                          : n.kind === 'destination'
                            ? { x: x1 + 8, y: (y0 + y1) / 2, anchor: 'start' as const }
                            : { x: (x0 + x1) / 2, y: y0 - 6, anchor: 'middle' as const };
                      return (
                        <g
                          classList={{ 'flow-node': true, clickable: !other }}
                          onClick={() => handleNodeClick(n)}
                          opacity={dimmed ? 0.3 : 1}
                        >
                          <rect
                            x={x0}
                            y={y0}
                            width={Math.max(1, x1 - x0)}
                            height={Math.max(2, y1 - y0)}
                            rx={2}
                            fill={color}
                            opacity={other ? 0.5 : active ? 1 : 0.85}
                            stroke={active ? '#ffffff' : other ? '#6b7280' : 'none'}
                            stroke-width={active ? 2 : 1}
                            stroke-dasharray={other ? '3,2' : undefined}
                          />
                          <text
                            x={labelPos.x}
                            y={labelPos.y}
                            dy="0.32em"
                            text-anchor={labelPos.anchor}
                            class="fill-gray-800 dark:fill-gray-200"
                            style={{ 'font-size': '11px', 'font-weight': 500 }}
                          >
                            {n.label}
                          </text>
                        </g>
                      );
                    }}
                  </For>
                </g>
              </svg>
            )}
          </div>
        </div>
      </Show>

      <Show when={panel() === 'zones'}>
        <div class="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950">
          <div class="flex h-11 items-center gap-3 border-b border-gray-200 dark:border-gray-800 px-4">
            <h3 class="text-xs font-semibold uppercase tracking-wider text-gray-700 dark:text-gray-300">Zone Traffic Matrix</h3>
          </div>
          <div class="overflow-auto p-4">
            {zonesData().zones.length === 0 ? (
              <p class="py-10 text-center text-sm text-gray-500">No zone traffic for the current selection.</p>
            ) : (
              <table class="border-separate text-[11px]" style={{ 'border-spacing': '3px' }}>
                <tbody>
                  <tr>
                    <td />
                    <td colSpan={zonesData().zones.length} class="pb-1 text-center text-[10px] uppercase tracking-widest text-gray-500">
                      Destination
                    </td>
                  </tr>
                  <tr>
                    <td class="w-4" />
                    <td class="rounded-tl-lg bg-gray-100 dark:bg-gray-800" />
                    <For each={zonesData().zones}>
                      {(z) => <td class="whitespace-nowrap rounded-t-lg bg-gray-100 dark:bg-gray-800 px-3 py-2.5 text-center font-medium text-gray-700 dark:text-gray-300">{z}</td>}
                    </For>
                  </tr>
                  <For each={zonesData().zones}>
                    {(from, ri) => (
                      <tr>
                        <Show when={ri() === 0}>
                          <td
                            rowSpan={zonesData().zones.length}
                            class="w-4 select-none text-[10px] uppercase tracking-widest text-gray-500"
                            style={{ 'writing-mode': 'vertical-lr', transform: 'rotate(180deg)' }}
                          >
                            <div class="flex h-full items-center justify-center">Source</div>
                          </td>
                        </Show>
                        <td class="whitespace-nowrap rounded-l-lg bg-gray-100 dark:bg-gray-800 px-3 py-2.5 text-right font-medium text-gray-700 dark:text-gray-300">{from}</td>
                        <For each={zonesData().zones}>
                          {(to) => {
                            const cell = () => cellIndex().get(`${from}|${to}`);
                            const active = () => {
                              const a = activeCell();
                              return !!a && a.from === from && a.to === to;
                            };
                            const tier = () => {
                              const c = cell();
                              return c ? zoneTier(c.allowed + c.blocked, maxZoneTotal()) : null;
                            };
                            return (
                              <td class="p-0">
                                {cell() ? (
                                  <button
                                    type="button"
                                    onClick={() => handleCellClick(from, to, cell())}
                                    class={
                                      active()
                                        ? 'block w-full whitespace-nowrap rounded-md border-2 border-white px-3 py-2.5 text-center font-medium'
                                        : 'block w-full whitespace-nowrap rounded-md border-2 border-transparent px-3 py-2.5 text-center font-medium hover:border-blue-400/40'
                                    }
                                    style={
                                      !active() && tier() ? { background: tier()!.bg, color: tier()!.fg } : { background: '#1f2937', color: '#e5e7eb' }
                                    }
                                    title={`${from} → ${to}: ${(cell()!.allowed + cell()!.blocked).toLocaleString()} gesamt, ${cell()!.allowed.toLocaleString()} erlaubt, ${cell()!.blocked.toLocaleString()} blockiert`}
                                  >
                                    {cell()!.allowed.toLocaleString()}
                                    {cell()!.blocked > 0 ? <span class="text-red-200"> / {cell()!.blocked.toLocaleString()}</span> : null}
                                  </button>
                                ) : (
                                  <div class="px-3 py-2.5 text-center text-gray-700 dark:text-gray-300">–</div>
                                )}
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
          </div>
        </div>
      </Show>
      <Show when={panel() === 'pairs'}>
        <VizPairs query={props.query} onFilter={props.onFilter} onInspect={setHostIp} />
      </Show>

      <Show when={hostIp()}>
        <VizHostPanel
          ip={hostIp()!}
          query={props.query}
          onClose={() => setHostIp(null)}
          onFilter={props.onFilter}
        />
      </Show>

    </div>
  );
};

export default FlowView;
