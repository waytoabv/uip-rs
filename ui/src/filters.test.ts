// @vitest-environment node
import { describe as suite, expect, it } from 'vitest';
import {
  ACTIONS,
  DIRECTIONS,
  LOG_TYPES,
  describe,
  emptyFilters,
  isMultiActive,
  toggleMulti,
  toQuery,
  type FilterState,
} from './filters';

suite('toggleMulti / isMultiActive', () => {
  it('behandelt einen leeren String als "alle aktiv"', () => {
    for (const t of LOG_TYPES) expect(isMultiActive('', LOG_TYPES, t)).toBe(true);
  });

  it('schaltet einen Wert ab und macht daraus eine explizite Liste', () => {
    const next = toggleMulti('', LOG_TYPES, 'dns');
    expect(next.split(',').sort()).toEqual(['dhcp', 'firewall', 'system', 'wifi'].sort());
    expect(isMultiActive(next, LOG_TYPES, 'dns')).toBe(false);
    expect(isMultiActive(next, LOG_TYPES, 'firewall')).toBe(true);
  });

  it('schaltet zurück auf den leeren String, sobald wieder alle aktiv sind', () => {
    let state = '';
    for (const a of ACTIONS) state = toggleMulti(state, ACTIONS, a); // alle abwählen
    expect(state).toBe('');
    for (const a of ACTIONS) state = toggleMulti(state, ACTIONS, a); // alle wieder anwählen
    expect(state).toBe('');
  });

  it('toggled unabhängig von der Reihenfolge der Werte', () => {
    const next = toggleMulti('inbound,outbound,nat,vpn', DIRECTIONS, 'inter_vlan');
    // Alle fünf sind jetzt wieder aktiv → das ist der leere String, nicht
    // eine ausgeschriebene Liste aller Werte.
    expect(next).toBe('');
    expect(isMultiActive(next, DIRECTIONS, 'inter_vlan')).toBe(true);
  });
});

suite('toQuery', () => {
  it('liefert einen leeren String ohne gesetzte Filter', () => {
    expect(toQuery(emptyFilters())).toBe('');
  });

  it('übernimmt direkte Backend-Parameter unverändert', () => {
    const state: FilterState = { ...emptyFilters(), log_type: 'firewall,dns', country: 'DE', range: '24h' };
    const params = new URLSearchParams(toQuery(state));
    expect(params.get('log_type')).toBe('firewall,dns');
    expect(params.get('country')).toBe('DE');
    expect(params.get('range')).toBe('24h');
  });

  it('verwirft ungültige Zahlen statt sie zu senden', () => {
    const state: FilterState = { ...emptyFilters(), port: 'abc', threat_min: '50' };
    const params = new URLSearchParams(toQuery(state));
    expect(params.has('port')).toBe(false);
    expect(params.get('threat_min')).toBe('50');
  });

  it('setzt Felder ohne eigenen Parameter zu einem q-Ausdruck zusammen', () => {
    const state: FilterState = {
      ...emptyFilters(),
      ip: '10.10.10.5',
      rule: 'WAN_IN',
      sport: '5000',
      dport: '443',
      asn: 'Cloudflare',
      service: 'https',
    };
    const q = new URLSearchParams(toQuery(state)).get('q') ?? '';
    expect(q).toContain('10.10.10.5');
    expect(q).toContain('rule:WAN_IN');
    expect(q).toContain('sport:5000');
    expect(q).toContain('dport:443');
    expect(q).toContain('asn:Cloudflare');
    expect(q).toContain('https');
  });

  it('quotet Begriffe mit Leerzeichen', () => {
    const state: FilterState = { ...emptyFilters(), rule: 'LAN to WAN' };
    const q = new URLSearchParams(toQuery(state)).get('q') ?? '';
    expect(q).toBe('rule:"LAN to WAN"');
  });

  it('verwirft nicht-numerische sport/dport statt sie als Volltext zu senden', () => {
    const state: FilterState = { ...emptyFilters(), sport: 'abc' };
    expect(toQuery(state)).toBe('');
  });

  it('hängt eine bereits von außen gesetzte q an den Rest an', () => {
    const state: FilterState = { ...emptyFilters(), ip: '1.2.3.4', q: 'src:9.9.9.9' };
    const q = new URLSearchParams(toQuery(state)).get('q') ?? '';
    expect(q).toBe('1.2.3.4 src:9.9.9.9');
  });
});

suite('describe', () => {
  it('zeigt keine Chips ohne aktive Filter', () => {
    expect(describe(emptyFilters())).toEqual([]);
  });

  it('zeigt keinen Chip für Pillen-Felder, solange alle aktiv sind (leerer String)', () => {
    expect(describe(emptyFilters()).some((c) => c.key === 'log_type')).toBe(false);
  });

  it('übersetzt den Zeitraum-Wert in sein Label', () => {
    const chips = describe({ ...emptyFilters(), range: '7d' });
    expect(chips).toEqual([{ key: 'range', label: 'Range: 7d' }]);
  });

  it('zeigt einen eigenen Chip je Textfeld', () => {
    const chips = describe({ ...emptyFilters(), ip: '1.2.3.4', asn: 'Cloudflare' });
    expect(chips.map((c) => c.key).sort()).toEqual(['asn', 'ip']);
  });
});
