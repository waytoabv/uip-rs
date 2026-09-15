// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { areaPath, tickIndices, xScale, yScale , niceAxis } from './DashChartMath';

describe('yScale', () => {
  it('bildet 0 auf das untere (rangeMax) und domainMax auf das obere Ende (rangeMin) ab', () => {
    const scale = yScale(100, 0, 200);
    expect(scale(0)).toBe(200);
    expect(scale(100)).toBe(0);
    expect(scale(50)).toBe(100);
  });

  it('erfindet keine Division durch 0, wenn alle Werte 0 sind', () => {
    const scale = yScale(0, 0, 200);
    expect(() => scale(0)).not.toThrow();
    expect(scale(0)).toBe(200);
  });

  it('kappt negative Werte statt sie unter die Achse zu zeichnen', () => {
    const scale = yScale(100, 0, 200);
    expect(scale(-10)).toBe(200);
  });
});

describe('xScale', () => {
  it('verteilt n Punkte gleichmäßig', () => {
    const scale = xScale(3, 0, 100);
    expect(scale(0)).toBe(0);
    expect(scale(1)).toBe(50);
    expect(scale(2)).toBe(100);
  });

  it('legt einen einzelnen Punkt in die Mitte', () => {
    const scale = xScale(1, 0, 100);
    expect(scale(0)).toBe(50);
  });

  it('wirft nicht bei null Punkten', () => {
    const scale = xScale(0, 0, 100);
    expect(() => scale(0)).not.toThrow();
  });
});

describe('areaPath', () => {
  it('gibt bei leerer Eingabe einen leeren Pfad statt zu werfen', () => {
    expect(areaPath([], [], [])).toBe('');
  });

  it('schließt die Fläche zwischen Ober- und Unterkante', () => {
    const d = areaPath([0, 10], [5, 5], [20, 20]);
    expect(d.startsWith('M0,5')).toBe(true);
    expect(d.endsWith('Z')).toBe(true);
    // Die Unterkante muss vorkommen, sonst ist es eine Linie, keine Fläche.
    expect(d).toContain('20');
  });

  /// Der Grund für die monotone Kurve: eine gewöhnliche Spline schwingt
  /// zwischen den Punkten über sie hinaus. Bei einem Verkehrsdiagramm wären
  /// das Ausschläge, die es nie gab — und unter null sogar unmögliche.
  it('schwingt nicht über die Datenpunkte hinaus', () => {
    const xs = [0, 10, 20, 30];
    const tops = [100, 20, 100, 20];
    const d = areaPath(xs, tops, [100, 100, 100, 100]);
    // Die Koordinaten stehen paarweise (x,y) — nur jede zweite ist ein y.
    const nums = (d.match(/-?\d+(?:\.\d+)?/g) ?? []).map(Number);
    const ys = nums.filter((_, i) => i % 2 === 1);
    // Kein Punkt der Kurve liegt oberhalb des höchsten oder unterhalb des
    // niedrigsten Datenwerts (y ist in SVG nach unten gerichtet).
    expect(Math.min(...ys)).toBeGreaterThanOrEqual(20 - 0.01);
    expect(Math.max(...ys)).toBeLessThanOrEqual(100 + 0.01);
  });
});

describe('tickIndices', () => {
  it('gibt bei n <= count jeden Index einmal zurück', () => {
    expect(tickIndices(3, 5)).toEqual([0, 1, 2]);
  });

  it('gibt bei null Punkten eine leere Liste statt zu werfen', () => {
    expect(tickIndices(0, 5)).toEqual([]);
  });

  it('verteilt count Indizes gleichmäßig über eine größere Reihe', () => {
    expect(tickIndices(9, 5)).toEqual([0, 2, 4, 6, 8]);
  });

  it('dedupliziert, wenn count nahe an n liegt', () => {
    const idx = tickIndices(4, 5);
    expect(new Set(idx).size).toBe(idx.length);
  });
});

describe('niceAxis', () => {
  it('rundet auf ablesbare Schritte auf', () => {
    const a = niceAxis(1183204);
    expect(a.max).toBeGreaterThanOrEqual(1183204);
    expect(a.ticks[0]).toBe(0);
    expect(a.ticks[a.ticks.length - 1]).toBe(a.max);
    // Gleichmäßige Abstände — sonst lügt das Raster.
    const step = a.ticks[1] - a.ticks[0];
    for (let i = 1; i < a.ticks.length; i++) {
      expect(a.ticks[i] - a.ticks[i - 1]).toBeCloseTo(step, 6);
    }
    // Und die Schritte sind glatt, nicht krumm.
    expect(step % 10 ** Math.floor(Math.log10(step))).toBeCloseTo(0, 6);
  });

  it('deckt das Maximum immer ab', () => {
    for (const m of [1, 7, 42, 99, 100, 101, 1234, 999999]) {
      expect(niceAxis(m).max).toBeGreaterThanOrEqual(m);
    }
  });

  it('überlebt leere und unsinnige Daten', () => {
    expect(niceAxis(0)).toEqual({ max: 1, ticks: [0, 1] });
    expect(niceAxis(-5)).toEqual({ max: 1, ticks: [0, 1] });
    expect(niceAxis(Number.NaN)).toEqual({ max: 1, ticks: [0, 1] });
  });
});
