// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { areaPath, tickIndices, xScale, yScale } from './DashChartMath';

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

  it('baut einen geschlossenen Pfad vorwärts über die Ober- und zurück über die Unterkante', () => {
    const d = areaPath([0, 10], [5, 5], [20, 20]);
    expect(d.startsWith('M 0.0 5.0')).toBe(true);
    expect(d.endsWith('Z')).toBe(true);
    expect(d).toContain('L 10.0 5.0');
    expect(d).toContain('L 10.0 20.0');
    expect(d).toContain('L 0.0 20.0');
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
