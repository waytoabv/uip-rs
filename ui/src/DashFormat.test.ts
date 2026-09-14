// @vitest-environment node
import { describe, expect, it } from 'vitest';
import {
  formatCompactNumber,
  formatNumber,
  formatShare,
  logTypeClass,
  sortLogTypeEntries,
} from './DashFormat';

describe('formatNumber', () => {
  it('setzt Tausendertrennzeichen', () => {
    expect(formatNumber(2148180)).toBe('2,148,180');
    expect(formatNumber(0)).toBe('0');
  });

  it('gibt bei Fehlendem einen Gedankenstrich statt einer Exception', () => {
    expect(formatNumber(null)).toBe('—');
    expect(formatNumber(undefined)).toBe('—');
    expect(formatNumber(Number.NaN)).toBe('—');
  });
});

describe('formatCompactNumber', () => {
  it('kürzt Tausender und Millionen', () => {
    expect(formatCompactNumber(0)).toBe('0');
    expect(formatCompactNumber(950)).toBe('950');
    expect(formatCompactNumber(300000)).toBe('300k');
    expect(formatCompactNumber(1200000)).toBe('1.2M');
    expect(formatCompactNumber(2000000)).toBe('2M');
  });

  it('macht aus Negativem nichts Negatives', () => {
    expect(formatCompactNumber(-5)).toBe('0');
  });
});

describe('formatShare', () => {
  it('rechnet einen normalen Anteil', () => {
    expect(formatShare(50, 100)).toBe('50%');
    expect(formatShare(1, 3)).toBe('33%');
  });

  it('rundet einen winzigen aber echten Anteil nicht auf 0%', () => {
    expect(formatShare(1, 10000)).toBe('<1%');
  });

  it('gibt 0% statt einer Division durch 0', () => {
    expect(formatShare(5, 0)).toBe('0%');
    expect(formatShare(0, 100)).toBe('0%');
  });
});

describe('logTypeClass', () => {
  it('färbt bekannte Typen unterschiedlich', () => {
    expect(logTypeClass('firewall')).toContain('blue');
    expect(logTypeClass('wifi')).toContain('amber');
    expect(logTypeClass('dhcp')).toContain('cyan');
  });

  it('fällt für Unbekanntes auf die System-Farbe zurück', () => {
    expect(logTypeClass('unbekannt')).toBe(logTypeClass('system'));
  });
});

describe('sortLogTypeEntries', () => {
  it('bringt die bekannte Reihenfolge, unabhängig von der Eingabe', () => {
    const input: [string, number][] = [
      ['system', 1],
      ['firewall', 2],
      ['wifi', 3],
      ['dhcp', 4],
    ];
    expect(sortLogTypeEntries(input).map(([t]) => t)).toEqual(['firewall', 'dhcp', 'wifi', 'system']);
  });

  it('schiebt Unbekanntes ans Ende, statt es zu verschlucken', () => {
    const input: [string, number][] = [
      ['mystery', 1],
      ['firewall', 2],
    ];
    expect(sortLogTypeEntries(input).map(([t]) => t)).toEqual(['firewall', 'mystery']);
  });
});
