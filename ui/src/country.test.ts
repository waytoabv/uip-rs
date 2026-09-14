// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { countryLabel, countryName } from './country';

describe('countryName', () => {
  it('übersetzt gängige Codes', () => {
    // Node und Browser bringen dieselben CLDR-Daten mit; welche Sprache
    // gewinnt, hängt von der Umgebung ab, deshalb wird hier nur geprüft,
    // dass überhaupt ein Name statt des Codes herauskommt.
    const name = countryName('CN');
    expect(name).not.toBe('CN');
    expect(name.length).toBeGreaterThan(2);
  });

  it('lässt Unbekanntes und Leeres in Ruhe', () => {
    expect(countryName(null)).toBe('');
    expect(countryName(undefined)).toBe('');
    expect(countryName('')).toBe('');
    // Kein gültiger Regionscode — der Code bleibt stehen, statt zu werfen.
    expect(countryName('XYZ')).toBe('XYZ');
    expect(countryName('1')).toBe('1');
  });

  it('normalisiert Kleinschreibung', () => {
    expect(countryName('de')).toBe(countryName('DE'));
  });
});

describe('countryLabel', () => {
  it('hängt den Code an, weil danach gefiltert wird', () => {
    expect(countryLabel('DE')).toMatch(/\(DE\)$/);
  });

  it('verdoppelt nichts, wenn es keinen Namen gibt', () => {
    expect(countryLabel('XYZ')).toBe('XYZ');
  });
});
