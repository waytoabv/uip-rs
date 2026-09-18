// Der Abschnitt „Interfaces": er entsteht nicht aus einer festen Feldliste
// wie der Rest des Dialogs, sondern aus dem, was der Server kennt — und er
// schreibt an einen anderen Endpunkt. Beides kann ein Test über die reinen
// Hilfsfunktionen nicht abdecken.
import { fireEvent, render, waitFor } from '@solidjs/testing-library';
import { afterEach, describe, expect, it, vi } from 'vitest';
import ShellSettings from './ShellSettings';

const NETWORKS = {
  interfaces: {
    br15: { name: '#1 - VLAN15 - Intern', vlan: 15, purpose: 'corporate', custom: null },
    ppp0: { name: null, vlan: null, purpose: null, custom: null },
  },
};

/** Sammelt die PUTs mit, die der Dialog absetzt. */
function stubFetch(): { puts: { path: string; body: unknown }[] } {
  const puts: { path: string; body: unknown }[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(input), 'http://localhost').pathname;
      if (init?.method === 'PUT') {
        puts.push({ path, body: JSON.parse(String(init.body)) });
        return { ok: true, json: async () => ({ written: [], cleared: [], rejected: [] }) } as Response;
      }
      const body =
        path === '/api/networks' ? NETWORKS : path === '/api/status' ? {} : { unifi_enabled: true };
      return { ok: true, json: async () => body } as Response;
    }),
  );
  return { puts };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('ShellSettings — Interfaces', () => {
  it('listet jede Schnittstelle mit dem Namen des Controllers als Vorgabe', async () => {
    stubFetch();
    const { findByPlaceholderText, getByText } = render(() => <ShellSettings onClose={() => {}} />);

    // Der Controller-Name steht als Platzhalter im Feld: er gilt, solange
    // niemand etwas einträgt.
    expect(await findByPlaceholderText('#1 - VLAN15 - Intern')).toBeTruthy();
    // Und eine Schnittstelle, die nur im Log vorkam, ist trotzdem da.
    expect(await findByPlaceholderText('ppp0')).toBeTruthy();
    expect(getByText('VLAN 15')).toBeTruthy();
  });

  it('schickt einen eigenen Namen an /api/networks/names', async () => {
    const { puts } = stubFetch();
    const { findByPlaceholderText, getByText } = render(() => <ShellSettings onClose={() => {}} />);

    const field = (await findByPlaceholderText('#1 - VLAN15 - Intern')) as HTMLInputElement;
    fireEvent.input(field, { target: { value: '  Intern  ' } });
    fireEvent.click(getByText('Save'));

    await waitFor(() => expect(puts.length).toBe(1));
    expect(puts[0].path).toBe('/api/networks/names');
    expect(puts[0].body).toEqual({ br15: 'Intern' });
  });

  it('meldet ein geleertes Feld als Löschung, nicht als leeren Namen', async () => {
    const { puts } = stubFetch();
    const { findByPlaceholderText, getByText } = render(() => <ShellSettings onClose={() => {}} />);

    const field = (await findByPlaceholderText('ppp0')) as HTMLInputElement;
    fireEvent.input(field, { target: { value: 'Glasfaser' } });
    fireEvent.input(field, { target: { value: '' } });
    fireEvent.click(getByText('Save'));

    // Nichts geändert: der Entwurf entspricht wieder dem gespeicherten Zustand.
    await waitFor(() => expect(getByText('Nothing changed.')).toBeTruthy());
    expect(puts.length).toBe(0);
  });
});
