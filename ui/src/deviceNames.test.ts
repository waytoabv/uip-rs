// @vitest-environment node
import { afterEach, describe as suite, expect, it, vi } from 'vitest';
import { deviceName, loadDeviceNames } from './deviceNames';

function answerWith(body: unknown, ok = true) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok, json: async () => body }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

suite('deviceName', () => {
  it('kennt nichts, solange nichts geladen ist', () => {
    expect(deviceName('10.10.15.56')).toBe(null);
    expect(deviceName(null)).toBe(null);
  });

  it('nennt das Gerät hinter der Adresse', async () => {
    answerWith({ devices: { '10.10.15.56': 'MacBook Pro', '10.10.15.1': 'Express 7' } });
    await loadDeviceNames();

    expect(deviceName('10.10.15.56')).toBe('MacBook Pro');
    // Auch das Gateway: es steht in jeder VLAN-Zeile.
    expect(deviceName('10.10.15.1')).toBe('Express 7');
    // Eine fremde Adresse bleibt eine Adresse — kein „unbekannt".
    expect(deviceName('1.1.1.1')).toBe(null);
  });

  it('behält die bisherigen Namen, wenn die Abfrage scheitert', async () => {
    answerWith({ devices: { '10.10.10.9': 'Proxmox Backup Server' } });
    await loadDeviceNames();

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    await loadDeviceNames();
    expect(deviceName('10.10.10.9')).toBe('Proxmox Backup Server');
  });
});
