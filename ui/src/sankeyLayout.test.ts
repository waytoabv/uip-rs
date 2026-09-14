// @vitest-environment node
// Reine Layout-Rechnung, kein DOM nötig — das spart jsdom als Abhängigkeit.
import { describe, expect, it } from 'vitest';
import { computeLayout } from './sankeyLayout';

describe('computeLayout', () => {
  // Der Absturz, der diese Testdatei ausgelöst hat: d3-sankey rechnet die
  // Spaltenzahl als `max(depth) + 1`, was ohne Knoten `NaN` ergibt, und legt
  // daraus ein Array an — `RangeError: Invalid array length`. Weil
  // `createMemo` eager ist, passierte das schon beim Öffnen der Ansicht,
  // bevor die erste Antwort da war, und riss die ganze Seite mit.
  it('übersteht einen leeren Graphen, statt die Seite mitzureißen', () => {
    expect(() => computeLayout({ nodes: [], links: [] })).not.toThrow();
    const g = computeLayout({ nodes: [], links: [] });
    expect(g.nodes).toHaveLength(0);
    expect(g.links).toHaveLength(0);
  });

  it('legt echte Daten aus', () => {
    const g = computeLayout({
      nodes: [
        { id: 'source:10.0.0.5', label: '10.0.0.5', kind: 'source' },
        { id: 'service:443/tcp', label: '443/tcp', kind: 'service' },
        { id: 'destination:1.2.3.4', label: '1.2.3.4', kind: 'destination' },
      ],
      links: [
        { source: 0, target: 1, value: 10, blocked: 2 },
        { source: 1, target: 2, value: 10, blocked: 2 },
      ],
    });
    expect(g.nodes).toHaveLength(3);
    expect(g.links).toHaveLength(2);
    // Jeder Knoten hat eine gerechnete Position — sonst zeichnet die Ansicht
    // alles übereinander in die linke obere Ecke.
    for (const n of g.nodes) {
      expect(n.x0).toBeTypeOf('number');
      expect(n.y0).toBeTypeOf('number');
    }
    // Die Spalten stehen in der erwarteten Reihenfolge nebeneinander.
    expect(g.nodes[0].x0!).toBeLessThan(g.nodes[1].x0!);
    expect(g.nodes[1].x0!).toBeLessThan(g.nodes[2].x0!);
  });
});
