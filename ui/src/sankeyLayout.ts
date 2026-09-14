import { sankey, type SankeyLink, type SankeyNode } from 'd3-sankey';

export interface NodeDatum {
  id: string;
  label: string;
  kind: 'source' | 'service' | 'destination';
}

export interface LinkExtra {
  blocked: number;
}

export type RawLink = LinkExtra & { source: number; target: number; value: number };

export interface SankeyResponse {
  nodes: NodeDatum[];
  links: RawLink[];
}

export type SNode = SankeyNode<NodeDatum, LinkExtra>;
export type SLink = SankeyLink<NodeDatum, LinkExtra>;

// SVG-Koordinatenraum des Sankey; skaliert per viewBox auf jede Breite.
// MARGIN gibt den Beschriftungen der äußeren Spalten Platz.
export const WIDTH = 760;
export const HEIGHT = 420;
export const MARGIN = 100;

/**
 * Rechnet das Sankey-Layout.
 *
 * Getrennt von der Komponente, damit es ohne DOM testbar ist — die Rechnung
 * hat einmal die ganze Seite mitgerissen und soll das nie wieder tun.
 */
export function computeLayout(data: SankeyResponse): { nodes: SNode[]; links: SLink[] } {
  // d3-sankey rechnet die Spaltenzahl als `max(depth) + 1`. Ohne Knoten ist
  // das `NaN`, und das daraus erzeugte Array wirft `RangeError: Invalid array
  // length`. Der Platzhalter in der Ansicht fängt das nicht ab: `createMemo`
  // ist eager und rechnet schon beim Einhängen, also bevor die erste Antwort
  // da ist — genau dann ist die Liste leer.
  if (data.nodes.length === 0) {
    return { nodes: [], links: [] };
  }
  const gen = sankey<NodeDatum, LinkExtra>()
    .nodeWidth(14)
    .nodePadding(10)
    .extent([
      [MARGIN, 8],
      [WIDTH - MARGIN, HEIGHT - 8],
    ]);
  return gen({
    nodes: data.nodes.map((n) => ({ ...n })),
    links: data.links.map((l) => ({ ...l })),
  });
}
