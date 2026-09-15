import { createSignal, For, onMount, Show } from 'solid-js';

/**
 * Die Einstellungen als Überlagerung.
 *
 * Geheimnisse kommen vom Server nie im Klartext zurück — nur ob eines
 * gesetzt ist (`<key>_set`). Ein leeres Feld heißt deshalb „unverändert",
 * nicht „löschen"; zum Löschen gibt es einen eigenen Knopf. Ohne diese
 * Unterscheidung löscht das bloße Öffnen und Speichern des Dialogs jeden
 * hinterlegten Schlüssel.
 */
interface SettingsData {
  [key: string]: unknown;
}

type Field =
  | { key: string; label: string; kind: 'text'; hint?: string }
  | { key: string; label: string; kind: 'bool'; hint?: string }
  | { key: string; label: string; kind: 'number'; hint?: string }
  | { key: string; label: string; kind: 'secret'; hint?: string };

const SECTIONS: { title: string; note?: string; fields: Field[] }[] = [
  {
    title: 'Network',
    note: 'Addresses of your own gateway, so they are never looked up as if they were someone else.',
    fields: [
      { key: 'wan_ips', label: 'WAN addresses', kind: 'text', hint: 'comma separated' },
      { key: 'gateway_ips', label: 'Gateway addresses', kind: 'text', hint: 'comma separated' },
    ],
  },
  {
    title: 'Enrichment',
    fields: [
      { key: 'rdns_enabled', label: 'Reverse DNS', kind: 'bool' },
      { key: 'geoip_dir', label: 'GeoIP directory', kind: 'text', hint: 'where the .mmdb files live' },
      { key: 'abuseipdb_api_key', label: 'AbuseIPDB key', kind: 'secret', hint: 'blocked firewall rows only' },
    ],
  },
  {
    title: 'Pi-hole',
    note: 'Pulls DNS queries that never pass the gateway’s syslog.',
    fields: [
      { key: 'pihole_enabled', label: 'Enabled', kind: 'bool' },
      { key: 'pihole_url', label: 'Address', kind: 'text', hint: 'http://pi.hole' },
      { key: 'pihole_password', label: 'Password', kind: 'secret' },
    ],
  },
  {
    title: 'UniFi',
    note: 'Device names from your controller, resolved when reading — so they apply to logs already stored.',
    fields: [
      { key: 'unifi_enabled', label: 'Enabled', kind: 'bool' },
      { key: 'unifi_url', label: 'Controller', kind: 'text', hint: 'https://192.168.1.1' },
      { key: 'unifi_api_key', label: 'API key', kind: 'secret' },
      { key: 'unifi_site', label: 'Site', kind: 'text', hint: 'default' },
    ],
  },
  {
    title: 'Retention',
    note: 'Handled by TimescaleDB policies; a change takes effect on the next restart.',
    fields: [
      { key: 'retention_days', label: 'Keep logs (days)', kind: 'number' },
      { key: 'retention_days_dns', label: 'Keep DNS (days)', kind: 'number' },
    ],
  },
];

export default function ShellSettings(props: { onClose: () => void }) {
  const [data, setData] = createSignal<SettingsData>({});
  const [draft, setDraft] = createSignal<Record<string, string | boolean | number>>({});
  const [status, setStatus] = createSignal<string | null>(null);
  const [piholeTest, setPiholeTest] = createSignal<string | null>(null);
  const [unifiTest, setUnifiTest] = createSignal<string | null>(null);

  onMount(async () => {
    const res = await fetch('/api/settings');
    if (res.ok) setData((await res.json()) as SettingsData);
  });

  const valueOf = (f: Field): string | boolean | number => {
    const d = draft();
    if (f.key in d) return d[f.key];
    const stored = data()[f.key];
    if (f.kind === 'bool') return stored === true;
    if (f.kind === 'number') return typeof stored === 'number' ? stored : '';
    if (f.kind === 'secret') return '';
    return typeof stored === 'string' ? stored : '';
  };

  const isSecretSet = (key: string) => data()[`${key}_set`] === true;

  const save = async () => {
    const patch: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(draft())) {
      const field = SECTIONS.flatMap((s) => s.fields).find((f) => f.key === k);
      if (!field) continue;
      // Ein leer gelassenes Geheimnis ist keine Änderung.
      if (field.kind === 'secret' && v === '') continue;
      patch[k] = field.kind === 'number' ? Number(v) : v;
    }
    if (Object.keys(patch).length === 0) {
      setStatus('Nothing changed.');
      return;
    }
    const res = await fetch('/api/settings', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(patch),
    });
    if (!res.ok) {
      setStatus('Saving failed.');
      return;
    }
    const body = (await res.json()) as { written: string[]; rejected: string[] };
    setStatus(
      body.rejected.length
        ? `Saved ${body.written.length}, refused: ${body.rejected.join(', ')}`
        : `Saved ${body.written.length} setting${body.written.length === 1 ? '' : 's'}.`,
    );
    setDraft({});
    const fresh = await fetch('/api/settings');
    if (fresh.ok) setData((await fresh.json()) as SettingsData);
  };

  const clearSecret = (key: string) => setDraft((d) => ({ ...d, [key]: '' }));

  const testPihole = async () => {
    setPiholeTest('Testing…');
    const res = await fetch('/api/settings/pihole/test');
    const b = (await res.json()) as { ok: boolean; reason?: string; version?: string };
    setPiholeTest(
      b.ok
        ? `Reachable${b.version ? ` — Pi-hole ${b.version}` : ''}`
        : b.reason === 'bad_credentials'
          ? 'Wrong password'
          : b.reason === 'no_url'
            ? 'No address configured'
            : 'Not reachable',
    );
  };

  const testUnifi = async () => {
    setUnifiTest('Testing…');
    const res = await fetch('/api/settings/unifi/test');
    const b = (await res.json()) as { ok: boolean; reason?: string; clients?: number; devices?: number };
    setUnifiTest(
      b.ok
        ? `Connected — ${b.clients ?? 0} clients, ${b.devices ?? 0} devices`
        : b.reason === 'bad_credentials'
          ? 'Key refused'
          : b.reason === 'no_url'
            ? 'No controller configured'
            : 'Not reachable',
    );
  };

  return (
    <div
      class="fixed inset-0 z-40 flex items-start justify-center bg-black/40 p-6 backdrop-blur-sm"
      onClick={(e) => e.target === e.currentTarget && props.onClose()}
    >
      <div class="max-h-full w-[42rem] max-w-full overflow-y-auto rounded-lg border border-gray-300 bg-white shadow-xl dark:border-gray-700 dark:bg-gray-950">
        <div class="flex items-center justify-between border-b border-gray-200 px-5 py-3 dark:border-gray-800">
          <h2 class="text-sm font-semibold text-gray-900 dark:text-gray-100">Settings</h2>
          <button
            type="button"
            onClick={props.onClose}
            aria-label="Close settings"
            class="rounded px-2 py-1 text-gray-500 hover:text-gray-900 dark:hover:text-gray-200"
          >
            ✕
          </button>
        </div>

        <div class="space-y-6 px-5 py-4">
          <For each={SECTIONS}>
            {(section) => (
              <section>
                <h3 class="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                  {section.title}
                </h3>
                <Show when={section.note}>
                  <p class="mt-0.5 text-[11px] text-gray-500">{section.note}</p>
                </Show>
                <div class="mt-2 space-y-2">
                  <For each={section.fields}>
                    {(f) => (
                      <label class="flex items-center gap-3">
                        <span class="w-40 shrink-0 text-xs text-gray-700 dark:text-gray-300">
                          {f.label}
                        </span>
                        <Show
                          when={f.kind !== 'bool'}
                          fallback={
                            <input
                              type="checkbox"
                              checked={valueOf(f) === true}
                              onChange={(e) =>
                                setDraft((d) => ({ ...d, [f.key]: e.currentTarget.checked }))
                              }
                              class="h-4 w-4 accent-teal-600"
                            />
                          }
                        >
                          <input
                            type={f.kind === 'secret' ? 'password' : 'text'}
                            inputmode={f.kind === 'number' ? 'numeric' : undefined}
                            value={String(valueOf(f))}
                            placeholder={
                              f.kind === 'secret' && isSecretSet(f.key)
                                ? '•••••••• (unchanged)'
                                : (f.hint ?? '')
                            }
                            onInput={(e) =>
                              setDraft((d) => ({ ...d, [f.key]: e.currentTarget.value }))
                            }
                            class="min-w-0 flex-1 rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-800 placeholder-gray-400 focus:border-teal-500 focus:outline-none dark:border-gray-700 dark:bg-black dark:text-gray-200 dark:placeholder-gray-600"
                          />
                        </Show>
                        <Show when={f.kind === 'secret' && isSecretSet(f.key)}>
                          <button
                            type="button"
                            onClick={() => clearSecret(f.key)}
                            class="shrink-0 text-[11px] text-gray-500 hover:text-red-600 dark:hover:text-red-400"
                          >
                            clear
                          </button>
                        </Show>
                      </label>
                    )}
                  </For>
                  <Show when={section.title === 'UniFi'}>
                    <div class="flex items-center gap-3 pl-[10.75rem]">
                      <button
                        type="button"
                        onClick={testUnifi}
                        class="rounded border border-gray-300 px-2 py-1 text-[11px] text-gray-700 hover:text-gray-900 dark:border-gray-700 dark:text-gray-300 dark:hover:text-gray-100"
                      >
                        Test connection
                      </button>
                      <Show when={unifiTest()}>
                        <span class="text-[11px] text-gray-600 dark:text-gray-400">{unifiTest()}</span>
                      </Show>
                    </div>
                  </Show>
                  <Show when={section.title === 'Pi-hole'}>
                    <div class="flex items-center gap-3 pl-[10.75rem]">
                      <button
                        type="button"
                        onClick={testPihole}
                        class="rounded border border-gray-300 px-2 py-1 text-[11px] text-gray-700 hover:text-gray-900 dark:border-gray-700 dark:text-gray-300 dark:hover:text-gray-100"
                      >
                        Test connection
                      </button>
                      <Show when={piholeTest()}>
                        <span class="text-[11px] text-gray-600 dark:text-gray-400">
                          {piholeTest()}
                        </span>
                      </Show>
                    </div>
                  </Show>
                </div>
              </section>
            )}
          </For>
        </div>

        <div class="flex items-center justify-between gap-3 border-t border-gray-200 px-5 py-3 dark:border-gray-800">
          <span class="text-[11px] text-gray-600 dark:text-gray-400">{status()}</span>
          <div class="flex gap-2">
            <button
              type="button"
              onClick={props.onClose}
              class="rounded border border-gray-300 px-3 py-1 text-xs text-gray-700 hover:text-gray-900 dark:border-gray-700 dark:text-gray-300"
            >
              Close
            </button>
            <button
              type="button"
              onClick={save}
              class="rounded border border-teal-500/60 bg-teal-500/10 px-3 py-1 text-xs text-teal-700 hover:bg-teal-500/20 dark:text-teal-300"
            >
              Save
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
