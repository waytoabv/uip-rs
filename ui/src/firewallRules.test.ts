// @vitest-environment node
import { afterEach, describe as suite, expect, it, vi } from 'vitest';
import { describeRule, loadFirewallRules, ruleLabel } from './firewallRules';

function answerWith(body: unknown, ok = true) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok, json: async () => body }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

suite('describeRule', () => {
  it('nennt eine eigene Regel bei ihrem Namen', () => {
    expect(
      describeRule({
        name: 'VL15 -> VL10 - Allow Pihole DNS and WebUI',
        src_zone: '#1 - Internes Netzwerk',
        dst_zone: '#0 - Servernetzwerk',
        predefined: false,
      }),
    ).toBe('VL15 -> VL10 - Allow Pihole DNS and WebUI');
  });

  it('stellt den Vorgaberegeln ihre Zonen voran', () => {
    // Achtunddreißig Regeln heißen „Block All Traffic" — erst die Zonen sagen,
    // welche die Zeile getroffen hat.
    expect(
      describeRule({
        name: 'Allow All Traffic',
        src_zone: 'Gateway',
        dst_zone: 'External',
        predefined: true,
      }),
    ).toBe('Gateway → External · Allow All Traffic');
  });

  it('lässt die Zonen weg, wenn eine fehlt', () => {
    expect(
      describeRule({ name: 'Block All Traffic', src_zone: 'Gateway', dst_zone: null, predefined: true }),
    ).toBe('Block All Traffic');
  });
});

suite('ruleLabel', () => {
  it('kennt nichts, solange nichts geladen ist', () => {
    expect(ruleLabel('CUSTOM2_CUSTOM1-A-10008')).toBe(null);
    expect(ruleLabel(null)).toBe(null);
  });

  it('löst den Regelnamen aus der Log-Zeile auf', async () => {
    answerWith({
      rules: {
        'CUSTOM2_CUSTOM1-A-10008': {
          name: 'VL15 -> VL10 - Allow Pihole DNS and WebUI',
          src_zone: '#1 - Internes Netzwerk',
          dst_zone: '#0 - Servernetzwerk',
          predefined: false,
        },
      },
    });
    await loadFirewallRules();

    expect(ruleLabel('CUSTOM2_CUSTOM1-A-10008')).toBe('VL15 -> VL10 - Allow Pihole DNS and WebUI');
    // Eine Regel, die der Controller nicht (mehr) kennt, bleibt unbeantwortet —
    // die Log-Zeile hat dann immer noch ihre eigene Beschreibung.
    expect(ruleLabel('WAN_LOCAL-D-10000')).toBe(null);
  });

  it('behält die bisherigen Namen, wenn die Abfrage scheitert', async () => {
    answerWith({
      rules: {
        'LAN_LOCAL-A-10000': {
          name: 'VLAN 1 To Gateway - Allow All',
          src_zone: 'Internal',
          dst_zone: 'Gateway',
          predefined: false,
        },
      },
    });
    await loadFirewallRules();

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    await loadFirewallRules();
    expect(ruleLabel('LAN_LOCAL-A-10000')).toBe('VLAN 1 To Gateway - Allow All');
  });
});
