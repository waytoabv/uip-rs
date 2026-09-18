// @vitest-environment node
import { afterEach, describe as suite, expect, it, vi } from 'vitest';
import { hasInterfaceName, interfaceName, loadInterfaceLabels, namedNetworkPath } from './interfaceLabels';

function answerWith(body: unknown, ok = true) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok, json: async () => body }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

suite('interfaceName', () => {
  it('nennt die rohe Kennung, solange nichts geladen ist', () => {
    // Der Ausgangszustand: `br15` ist unfreundlich, aber wahr.
    expect(interfaceName('br15')).toBe('br15');
    expect(namedNetworkPath('br15', 'eth4')).toBe('br15 → eth4');
    expect(interfaceName(null)).toBe('—');
  });

  it('übernimmt die Namen aus dem Controller', async () => {
    answerWith({ interfaces: { br15: { name: 'IoT', vlan: 15, purpose: 'corporate' },
                               eth4: { name: 'WAN', vlan: null, purpose: 'wan' } } });
    await loadInterfaceLabels();

    expect(interfaceName('br15')).toBe('IoT');
    expect(namedNetworkPath('br15', 'eth4')).toBe('IoT → WAN');
    expect(hasInterfaceName('br15')).toBe(true);
  });

  it('nimmt den selbst vergebenen Namen vor den des Controllers', async () => {
    answerWith({
      interfaces: {
        br15: { name: '#1 - VLAN15 - Intern', vlan: 15, purpose: 'corporate', custom: 'Intern' },
        // Eine Schnittstelle, die der Controller nicht kennt, kann trotzdem
        // einen eigenen Namen tragen.
        ppp0: { name: null, vlan: null, purpose: null, custom: 'Glasfaser' },
      },
    });
    await loadInterfaceLabels();

    expect(interfaceName('br15')).toBe('Intern');
    expect(interfaceName('ppp0')).toBe('Glasfaser');
    expect(namedNetworkPath('br15', 'ppp0')).toBe('Intern → Glasfaser');
  });

  it('bleibt bei der rohen Kennung, wenn niemand einen Namen kennt', async () => {
    answerWith({ interfaces: { tun0: { name: null, vlan: null, purpose: null, custom: null } } });
    await loadInterfaceLabels();

    expect(interfaceName('tun0')).toBe('tun0');
    expect(hasInterfaceName('tun0')).toBe(false);
  });

  it('lässt unbekannte Schnittstellen bei ihrem Namen', async () => {
    answerWith({ interfaces: { br15: { name: 'IoT', vlan: 15, purpose: 'corporate' } } });
    await loadInterfaceLabels();

    // Kein „unbekannt": wgsrv0 sagt mehr als ein Fragezeichen.
    expect(interfaceName('wgsrv0')).toBe('wgsrv0');
    expect(namedNetworkPath('wgsrv0', 'br15')).toBe('wgsrv0 → IoT');
    expect(hasInterfaceName('wgsrv0')).toBe(false);
  });

  it('nennt nur eine Seite, wenn nur eine bekannt ist', async () => {
    answerWith({ interfaces: { br0: { name: 'LAN', vlan: 1, purpose: 'corporate' } } });
    await loadInterfaceLabels();

    expect(namedNetworkPath('br0', null)).toBe('LAN');
    expect(namedNetworkPath(null, 'br0')).toBe('LAN');
    expect(namedNetworkPath(null, null)).toBe('—');
  });

  it('behält die bisherigen Namen, wenn die Abfrage scheitert', async () => {
    answerWith({ interfaces: { br0: { name: 'LAN', vlan: 1, purpose: 'corporate' } } });
    await loadInterfaceLabels();

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    await loadInterfaceLabels();
    // Ein Aussetzer löscht nichts — sonst blinkten bei jedem Netzhänger alle
    // Namen auf ihre Kennungen zurück.
    expect(interfaceName('br0')).toBe('LAN');
  });
});
