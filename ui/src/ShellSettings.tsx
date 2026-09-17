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
  // `fallback`: was gilt, solange nichts gespeichert ist. Ohne das zeigte der
  // Schalter „aus", während im Hintergrund die Vorgabe „an" wirkt — der Dialog
  // behauptete dann das Gegenteil dessen, was der Dienst tut.
  | { key: string; label: string; kind: 'bool'; hint?: string; fallback?: boolean }
  | { key: string; label: string; kind: 'number'; hint?: string }
  | { key: string; label: string; kind: 'secret'; hint?: string };

/** Was `/api/status` über die laufenden Verbindungen meldet. */
interface Live {
  abuseipdb: { remaining: number; limit: number | null; reset_at: string | null } | null;
  maxmind: { last_update: string | null };
  maxmind_error: string | null;
  pihole: { enabled: boolean; last: { ok: boolean; at: string; error: string | null } | null };
  unifi: {
    enabled: boolean;
    last: { ok: boolean; at: string; error: string | null; clients: number | null; devices: number | null } | null;
  };
  syslog: { received: number; dropped: number; port: number; addresses: string[]; at: string } | null;
}

type Tone = 'ok' | 'warn' | 'off';

/** Eine Zeile Zustand: Punkt, Aussage, Zeitpunkt. */
function health(live: Live | null, which: string): { tone: Tone; text: string } {
  if (!live) return { tone: 'off', text: 'unknown' };
  const fresh = (at: string | undefined, within: number) =>
    !!at && Date.now() - new Date(at).getTime() < within;

  switch (which) {
    case 'syslog': {
      const s = live.syslog;
      if (!s) return { tone: 'off', text: 'no datagram seen yet' };
      // Der Buchhalter schreibt alle 30 s, auch wenn nichts ankam. Bleibt der
      // Zeitstempel stehen, läuft der Empfänger nicht mehr.
      if (!fresh(s.at, 120_000)) return { tone: 'warn', text: 'the receiver stopped reporting' };
      const where = s.addresses.length ? ` at ${s.addresses.join(', ')}:${s.port}` : '';
      return {
        tone: s.received > 0 ? 'ok' : 'warn',
        text: s.received > 0
          ? `${s.received.toLocaleString('en-GB')} received${where}`
          : `listening${where} — nothing has arrived`,
      };
    }
    case 'pihole': {
      const p = live.pihole;
      if (!p.enabled) return { tone: 'off', text: 'off' };
      if (!p.last) return { tone: 'warn', text: 'waiting for the first poll' };
      if (!p.last.ok) return { tone: 'warn', text: p.last.error ?? 'the last poll failed' };
      return fresh(p.last.at, 120_000)
        ? { tone: 'ok', text: 'connected' }
        : { tone: 'warn', text: 'nothing polled recently' };
    }
    case 'unifi': {
      const u = live.unifi;
      if (!u.enabled) return { tone: 'off', text: 'off' };
      if (!u.last) return { tone: 'warn', text: 'waiting for the first sync' };
      if (!u.last.ok) return { tone: 'warn', text: u.last.error ?? 'the last sync failed' };
      return { tone: 'ok', text: `connected — ${u.last.clients ?? 0} clients, ${u.last.devices ?? 0} devices` };
    }
    case 'abuseipdb': {
      const q = live.abuseipdb;
      if (!q) return { tone: 'off', text: 'no key, or nothing looked up yet' };
      const used = q.limit == null ? null : q.limit - q.remaining;
      return q.remaining === 0
        ? { tone: 'warn', text: 'daily quota spent' }
        : { tone: 'ok', text: used == null ? `${q.remaining} left` : `${used}/${q.limit} used today` };
    }
    case 'maxmind': {
      if (live.maxmind_error) return { tone: 'warn', text: live.maxmind_error };
      if (!live.maxmind.last_update) return { tone: 'off', text: 'no database yet' };
      return { tone: 'ok', text: `database from ${new Date(live.maxmind.last_update).toLocaleDateString('en-GB')}` };
    }
    default:
      return { tone: 'off', text: '' };
  }
}

const DOT: Record<Tone, string> = {
  ok: 'bg-emerald-400',
  warn: 'bg-amber-400',
  off: 'bg-gray-400 dark:bg-gray-600',
};

const SECTIONS: { title: string; note?: string; status?: string; fields: Field[] }[] = [
  {
    title: 'Syslog',
    note:
      'Everything the gateway sends arrives here. The firewall rows describing that traffic itself are ' +
      'dropped rather than stored — thousands a minute saying only that the connection works, which the ' +
      'counter says once.',
    status: 'syslog',
    fields: [
      { key: 'drop_syslog_traffic', label: 'Drop own traffic', kind: 'bool', fallback: true },
    ],
  },
  {
    title: 'Network',
    note:
      'Which interface faces your provider, and under which address. Everything leaving through that ' +
      'interface is outbound, everything arriving on it inbound — get it wrong and every internet ' +
      'connection looks like traffic between two VLANs. Read from the controller when UniFi is ' +
      'connected; fill these in only to override what it reports.',
    fields: [
      { key: 'wan_interfaces', label: 'WAN interfaces', kind: 'text', hint: 'optional override, e.g. eth1, ppp0' },
      { key: 'wan_ips', label: 'WAN addresses', kind: 'text', hint: 'optional override, comma separated' },
    ],
  },
  {
    title: 'Enrichment',
    fields: [{ key: 'rdns_enabled', label: 'Reverse DNS', kind: 'bool', fallback: true }],
  },
  {
    title: 'MaxMind',
    note: 'Country and ASN. The databases are fetched here and checked daily for a newer build.',
    status: 'maxmind',
    fields: [
      { key: 'maxmind_account_id', label: 'Account', kind: 'text', hint: 'from a free GeoLite2 signup' },
      { key: 'maxmind_license_key', label: 'Licence key', kind: 'secret' },
      { key: 'geoip_dir', label: 'Directory', kind: 'text', hint: 'where the .mmdb files live' },
    ],
  },
  {
    title: 'AbuseIPDB',
    note:
      'Threat scores, asked only for blocked firewall rows. The free tier allows 1,000 checks a day. ' +
      'A stored score is asked again once it is a fortnight old and its address turns up in the log — ' +
      'but only so many times a day, so a backlog of old entries cannot spend the allowance a new ' +
      'address needs. 0 turns refreshing off.',
    status: 'abuseipdb',
    fields: [
      { key: 'abuseipdb_api_key', label: 'API key', kind: 'secret' },
      { key: 'abuseipdb_refresh_per_day', label: 'Refresh budget', kind: 'number', hint: 'checks a day, default 200' },
    ],
  },
  {
    title: 'Pi-hole',
    note: 'Pulls DNS queries that never pass the gateway’s syslog.',
    status: 'pihole',
    fields: [
      { key: 'pihole_enabled', label: 'Enabled', kind: 'bool' },
      { key: 'pihole_url', label: 'Address', kind: 'text', hint: 'http://pi.hole' },
      { key: 'pihole_password', label: 'Password', kind: 'secret' },
    ],
  },
  {
    title: 'UniFi',
    note:
      'Device and network names from your controller, resolved when reading — so they apply to logs ' +
      'already stored. Also where the WAN address comes from.',
    status: 'unifi',
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

  const [live, setLive] = createSignal<Live | null>(null);

  const loadLive = async () => {
    try {
      const res = await fetch('/api/status');
      if (res.ok) setLive((await res.json()) as Live);
    } catch {
      // Ohne Antwort bleibt der Punkt grau — das ist die ehrliche Aussage.
    }
  };

  onMount(async () => {
    const res = await fetch('/api/settings');
    if (res.ok) setData((await res.json()) as SettingsData);
    void loadLive();
    // Solange der Dialog offen ist, mitlaufen lassen: wer gerade einen
    // Schlüssel einträgt, will sehen, ob die Verbindung danach steht.
    const timer = window.setInterval(loadLive, 10_000);
    return () => window.clearInterval(timer);
  });

  const valueOf = (f: Field): string | boolean | number => {
    const d = draft();
    if (f.key in d) return d[f.key];
    const stored = data()[f.key];
    if (f.kind === 'bool') return typeof stored === 'boolean' ? stored : (f.fallback ?? false);
    if (f.kind === 'number') return typeof stored === 'number' ? stored : '';
    if (f.kind === 'secret') return '';
    return typeof stored === 'string' ? stored : '';
  };

  const isSecretSet = (key: string) => data()[`${key}_set`] === true;

  /** Was der Controller über das WAN gemeldet hat, falls etwas. */
  const detected = () => {
    const text = (key: string) => {
      const v = data()[key];
      return typeof v === 'string' && v !== '' ? v : null;
    };
    const parts = [text('wan_interfaces_detected'), text('wan_ips_detected')].filter(Boolean);
    return parts.length ? parts.join(' · ') : null;
  };

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
                <div class="flex items-baseline justify-between gap-3">
                  <h3 class="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                    {section.title}
                  </h3>
                  {/* Ob die Verbindung gerade steht, gehört neben ihre
                      Einstellungen — sonst muss man sie speichern und danach
                      anderswo nachsehen, ob es geklappt hat. */}
                  <Show when={section.status}>
                    {(which) => {
                      const state = () => health(live(), which());
                      return (
                        <span class="flex shrink-0 items-center gap-1.5 text-[11px] text-gray-600 dark:text-gray-400">
                          <span class={`h-1.5 w-1.5 rounded-full ${DOT[state().tone]}`} />
                          {state().text}
                        </span>
                      );
                    }}
                  </Show>
                </div>
                <Show when={section.note}>
                  <p class="mt-0.5 text-[11px] text-gray-500">{section.note}</p>
                </Show>
                {/* Was der Controller gemeldet hat, statt einer Zeile, die
                    jemand von Hand pflegen müsste. */}
                <Show when={section.title === 'Network' && detected()}>
                  <p class="mt-1 text-[11px] text-gray-600 dark:text-gray-400">
                    Reported by the controller: <span class="font-medium">{detected()}</span>
                  </p>
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
