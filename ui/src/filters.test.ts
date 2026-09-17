// @vitest-environment node
import { describe as suite, expect, it } from 'vitest';
import {
  ACTIONS,
  DIRECTIONS,
  LOG_TYPES,
  describe,
  removeTerm,
  splitTerms,
  defaultFilters,
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

  // Die Zonenmatrix (FlowView) setzt beide beim Klick auf eine Zelle. Fehlten
  // sie im Query-String, sah der Filter angewandt aus — Chips und Zähler
  // zeigten ihn —, und die Liste blieb unverändert.
  it('sendet die gerichteten Schnittstellen als eigene Parameter', () => {
    const state: FilterState = { ...emptyFilters(), iface_in: 'LAN', iface_out: 'WAN' };
    const params = new URLSearchParams(toQuery(state));
    expect(params.get('iface_in')).toBe('LAN');
    expect(params.get('iface_out')).toBe('WAN');
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

suite('defaultFilters — womit die Ansicht startet', () => {
  // Ein Firewall-Log, das beim Öffnen auch DNS und DHCP zeigt, verlangt als
  // Erstes eine Aufräumarbeit, die fast jeder gleich macht.
  it('zeigt erlaubten und geblockten Firewall-Verkehr, der irgendwohin geht', () => {
    const d = defaultFilters();
    expect(d.log_type).toBe('firewall');
    expect(d.action).toBe('allow,block');
    expect(d.direction).toBe('inbound,outbound,inter_vlan');
  });

  it('lässt alles andere offen — kein Zeitraum, keine Suche', () => {
    const d = defaultFilters();
    expect(d.range).toBe('');
    expect(d.q).toBe('');
    expect(d.country).toBe('');
  });

  it('erzeugt genau diese drei Parameter und sonst nichts', () => {
    const params = new URLSearchParams(toQuery(defaultFilters()));
    expect([...params.keys()].sort()).toEqual(['action', 'direction', 'log_type']);
  });

  // Die Vorauswahl ist eine Auswahl, keine Sperre: jede Pille lässt sich
  // zurücknehmen, und dann steht dort wieder der neutrale leere Wert.
  it('ist über die Pillen vollständig zurücknehmbar', () => {
    const d = defaultFilters();
    const all = toggleMulti(toggleMulti(d.action, ACTIONS, 'redirect'), ACTIONS, 'unknown');
    expect(all).toBe('');
  });
});

suite('describe — welche Filter einen Chip bekommen', () => {
  // Aktion und Richtung haben jeweils eine eigene Pillenreihe, die ihren
  // Zustand zeigt. Ein Chip daneben sagte dasselbe ein zweites Mal — und da
  // die Ansicht mit einer Vorauswahl startet, stünden dort zwei Chips, die
  // nie verschwinden.
  it('lässt Aktion und Richtung weg — dafür gibt es die Pillen', () => {
    const chips = describe({ ...emptyFilters(), action: 'block', direction: 'inbound' });
    const labels = chips.map((c: { label: string }) => c.label);
    expect(labels.some((l) => l.startsWith('Action:'))).toBe(false);
    expect(labels.some((l) => l.startsWith('Direction:'))).toBe(false);
  });

  it('zeigt weiter, was keine eigene Pille hat', () => {
    const chips = describe({ ...emptyFilters(), action: 'block', country: 'DE', port: '443' });
    expect(chips.map((c) => c.key).sort()).toEqual(['country', 'port']);
  });

  it('lässt den Log-Typ weg — seine Pillen zeigen ihren Zustand selbst', () => {
    const chips = describe({ ...emptyFilters(), log_type: 'firewall' });
    expect(chips.map((c: { label: string }) => c.label).some((l) => l.startsWith('Type:'))).toBe(false);
  });

  it('gibt für einen leeren Filter gar nichts zurück', () => {
    expect(describe(emptyFilters())).toEqual([]);
  });
});

suite('splitTerms / removeTerm — jeder Begriff eine eigene Pille', () => {
  it('trennt an Leerzeichen, hält Anführungen zusammen', () => {
    expect(splitTerms('10.0.0.5 443 !tcp')).toEqual(['10.0.0.5', '443', '!tcp']);
    expect(splitTerms('rule:"LAN to WAN" 443')).toEqual(['rule:"LAN to WAN"', '443']);
  });

  it('entfernt genau einen Begriff und lässt die übrigen stehen', () => {
    expect(removeTerm('10.0.0.5 443 !tcp', '443')).toBe('10.0.0.5 !tcp');
    // Ein Begriff mit Leerzeichen bleibt als Einheit entfernbar.
    expect(removeTerm('rule:"LAN to WAN" 443', 'rule:"LAN to WAN"')).toBe('443');
  });

  it('erzeugt je Begriff eine Pille statt einer gemeinsamen', () => {
    const chips = describe({ ...emptyFilters(), q: '10.0.0.5 443 !tcp' });
    expect(chips).toHaveLength(3);
    expect(chips.map((c: { label: string }) => c.label)).toEqual(['10.0.0.5', '443', '!tcp']);
    // Jede trägt ihren Begriff mit, damit sie einzeln entfernt werden kann.
    expect(chips.every((c: { term?: string }) => !!c.term)).toBe(true);
  });

  it('kommt mit leerem und mehrfach getrenntem Ausdruck zurecht', () => {
    expect(splitTerms('')).toEqual([]);
    expect(splitTerms('   ')).toEqual([]);
    expect(splitTerms('a   b')).toEqual(['a', 'b']);
    expect(removeTerm('a', 'a')).toBe('');
  });
});
