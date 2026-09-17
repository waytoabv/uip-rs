import { createSignal, For, onMount, Show, type JSX } from 'solid-js';

/**
 * Kopfzeile: Zeichen + Name, Reiter, Statusleiste.
 *
 * Kontingent, GeoIP-Stand und der nächste Lauf kommen aus `/api/status`.
 * Wo die Antwort `null` sagt, bleibt „—" stehen: die Quelle hat noch nichts
 * gemeldet. Das ist ausdrücklich nicht dasselbe wie „0" oder „veraltet", und
 * die Leiste darf den Unterschied nicht verwischen.
 */

export interface NavTab<View extends string> {
  id: View;
  label: string;
}

interface Props<View extends string> {
  onOpenSettings: () => void;
  tabs: readonly NavTab<View>[];
  activeView: View;
  onSelectView: (id: View) => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}

async function fetchTotalLogs(): Promise<number | null> {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return null;
    const body = (await res.json()) as { total?: number };
    return typeof body.total === 'number' ? body.total : null;
  } catch {
    return null;
  }
}

interface Status {
  abuseipdb: {
    remaining: number;
    limit: number | null;
    reset_at: string | null;
    paused_until: string | null;
  } | null;
  pihole: { enabled: boolean; last: { ok: boolean; at: string; error: string | null } | null };
  maxmind: { last_update: string | null; city: string | null; asn: string | null };
  maxmind_next_update: string | null;
  maxmind_error: string | null;
}

async function fetchStatus(): Promise<Status | null> {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return null;
    return (await res.json()) as Status;
  } catch {
    return null;
  }
}

/** Datum samt Uhrzeit, wie in der Vorlage: „12 Sep 2026 14:23". */
function stamp(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const date = d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  return `${date} ${time}`;
}

/** Ganze Tage seit `iso`, für die Alterswarnung. */
function daysSince(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return Math.floor((Date.now() - d.getTime()) / 86_400_000);
}

/**
 * Das Kontingent als „987/1000", oder nur „987", solange das Limit unbekannt
 * ist. AbuseIPDB nennt es erst in der ersten Antwort.
 */
function quotaText(q: Status['abuseipdb']): string {
  if (!q) return '—';
  const left = q.remaining.toLocaleString('en-GB');
  return q.limit == null ? left : `${left}/${q.limit.toLocaleString('en-GB')}`;
}

async function pingHealth(): Promise<boolean> {
  try {
    const res = await fetch('/api/health');
    return res.ok;
  } catch {
    return false;
  }
}

function formatCount(n: number | null): string {
  return n == null ? '—' : `${n.toLocaleString('en-GB')} logs`;
}

export default function ShellHeader<View extends string>(props: Props<View>): JSX.Element {
  const [totalLogs, setTotalLogs] = createSignal<number | null>(null);
  const [alive, setAlive] = createSignal(true);
  const [status, setStatus] = createSignal<Status | null>(null);

  // Ein aufgebrauchtes Kontingent ist der Grund, warum Threat-Scores fehlen —
  // das darf nicht dieselbe Farbe haben wie ein gesunder Stand.
  const quotaSpent = () => {
    const q = status()?.abuseipdb;
    if (q == null) return false;
    const paused = q.paused_until ? new Date(q.paused_until).getTime() > Date.now() : false;
    return q.remaining === 0 || paused;
  };

  /**
   * Der Zustand des Pi-hole-Abrufs, für den zweiten Punkt.
   *
   * `stale` ist der Fall, den ein bloßes ok/Fehler nicht abdeckt: die Schleife
   * meldet sich bei jedem Durchlauf, auch wenn nichts zu holen war. Bleibt die
   * Meldung aus, läuft sie nicht mehr — und das sieht von außen sonst genauso
   * aus wie „läuft".
   */
  const piholeState = (): 'off' | 'ok' | 'error' | 'stale' | 'waiting' => {
    const p = status()?.pihole;
    if (!p?.enabled) return 'off';
    if (!p.last) return 'waiting';
    if (!p.last.ok) return 'error';
    // Abgerufen wird alle 30 s; nach zwei Minuten Stille stimmt etwas nicht.
    const age = Date.now() - new Date(p.last.at).getTime();
    return age > 120_000 ? 'stale' : 'ok';
  };

  const PIHOLE_DOT: Record<string, string> = {
    ok: 'bg-emerald-400',
    error: 'bg-red-400',
    stale: 'bg-amber-400',
    waiting: 'bg-gray-400',
    off: '',
  };

  const piholeTitle = () => {
    const p = status()?.pihole;
    switch (piholeState()) {
      case 'ok':
        return `Pi-hole: last poll ${stamp(p?.last?.at)}`;
      case 'error':
        return `Pi-hole: ${p?.last?.error ?? 'last poll failed'}`;
      case 'stale':
        return `Pi-hole: nothing since ${stamp(p?.last?.at)} — the poll loop looks stuck`;
      default:
        return 'Pi-hole: enabled, waiting for the first poll';
    }
  };
  // GeoLite2 erscheint wöchentlich; einen Monat ohne Aktualisierung hat
  // niemand absichtlich.
  const geoStale = () =>
    status()?.maxmind_error != null || (daysSince(status()?.maxmind.last_update) ?? 0) > 30;

  onMount(() => {
    fetchTotalLogs().then(setTotalLogs);
    pingHealth().then(setAlive);
    fetchStatus().then(setStatus);
    // Hält den Log-Zähler und den "lebt"-Punkt frisch, ohne dass jede
    // andere Ansicht davon wissen muss.
    const timer = window.setInterval(() => {
      fetchTotalLogs().then(setTotalLogs);
      pingHealth().then(setAlive);
      fetchStatus().then(setStatus);
    }, 30_000);
    return () => window.clearInterval(timer);
  });

  return (
    <header class="flex items-center justify-between gap-4 border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950 px-4 py-2">
      <div class="flex min-w-0 flex-1 items-center gap-4 overflow-x-auto [&::-webkit-scrollbar]:hidden">
        <div class="flex shrink-0 items-center gap-2">
          <span
            class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border-[1.5px] border-teal-500 text-[11px] font-bold text-teal-400"
            aria-hidden="true"
          >
            U
          </span>
          <span class="hidden text-sm font-semibold text-gray-800 dark:text-gray-200 sm:inline">UniFi Log Insight</span>
        </div>

        <nav class="flex items-center gap-0.5">
          <For each={props.tabs}>
            {(tab) => (
              <button
                type="button"
                onClick={() => props.onSelectView(tab.id)}
                classList={{
                  'bg-gray-200 text-gray-900 dark:bg-gray-800 dark:text-white': props.activeView === tab.id,
                  'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200': props.activeView !== tab.id,
                }}
                class="rounded px-3 py-1.5 text-sm font-medium transition-colors"
              >
                {tab.label}
              </button>
            )}
          </For>
        </nav>
      </div>

      <div class="flex shrink-0 items-center gap-3">
        <div class="hidden items-center gap-3 md:flex">
          <span
            class={`text-xs ${quotaSpent() ? 'text-amber-700 dark:text-amber-400' : 'text-gray-600 dark:text-gray-400'}`}
            title={
              status()?.abuseipdb == null
                ? 'No AbuseIPDB response yet — no key, or nothing looked up so far'
                : quotaSpent()
                  ? 'Daily quota spent — threat scores resume after the reset'
                  : 'Checks left in the current AbuseIPDB quota'
            }
          >
            AbuseIPDB: {quotaText(status()?.abuseipdb ?? null)}
            <Show when={status()?.abuseipdb?.reset_at}>
              {' · '}Reset {stamp(status()!.abuseipdb!.reset_at)}
            </Show>
          </span>
          <span class="text-xs text-gray-400 dark:text-gray-600">|</span>
          <span
            class={`text-xs ${geoStale() ? 'text-amber-700 dark:text-amber-400' : 'text-gray-600 dark:text-gray-400'}`}
            title={
              status()?.maxmind_error != null
                ? `Last GeoLite2 download failed — ${status()!.maxmind_error}`
                : status()?.maxmind.last_update == null
                  ? 'No GeoLite2 database found in the configured directory'
                  : `City: ${stamp(status()?.maxmind.city)} · ASN: ${stamp(status()?.maxmind.asn)}`
            }
          >
            MaxMind: {stamp(status()?.maxmind.last_update)}
          </span>
          <span class="text-xs text-gray-400 dark:text-gray-600">|</span>
          <span
            class="text-xs text-gray-600 dark:text-gray-400"
            title={
              status()?.maxmind_next_update == null
                ? 'No MaxMind credentials — add an account and licence key under Settings'
                : 'When the GeoLite2 databases are checked for a newer build'
            }
          >
            Next pull: {stamp(status()?.maxmind_next_update)}
          </span>
          <span class="text-xs text-gray-400 dark:text-gray-600">|</span>
          <span class="text-xs text-gray-600 dark:text-gray-400">{formatCount(totalLogs())}</span>
        </div>

        <Show when={piholeState() !== 'off'}>
          <span
            class={`h-1.5 w-1.5 shrink-0 rounded-full ${PIHOLE_DOT[piholeState()]}`}
            title={piholeTitle()}
            aria-label={piholeTitle()}
          />
        </Show>

        <span
          class="h-1.5 w-1.5 shrink-0 rounded-full"
          classList={{ 'bg-emerald-400': alive(), 'bg-red-400': !alive() }}
          title={alive() ? 'Server reachable' : 'Server unreachable'}
        />

        <button
          type="button"
          onClick={props.onToggleTheme}
          class="rounded p-1.5 text-gray-600 dark:text-gray-400 transition-colors hover:bg-gray-200 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-gray-200"
          title={props.theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {props.theme === 'dark' ? (
            <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path
                fill-rule="evenodd"
                d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"
                clip-rule="evenodd"
              />
            </svg>
          ) : (
            <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
            </svg>
          )}
        </button>

        <button
          type="button"
          onClick={() => props.onOpenSettings()}
          class="rounded p-1.5 text-gray-600 transition-colors hover:bg-gray-200 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200"
          title="Settings"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.8"
            stroke-linecap="round"
            stroke-linejoin="round"
            class="h-4 w-4"
            aria-hidden="true"
          >
            <line x1="3.5" y1="5" x2="20.5" y2="5" />
            <circle cx="9" cy="5" r="2" />
            <line x1="3.5" y1="12" x2="20.5" y2="12" />
            <circle cx="15" cy="12" r="2" />
            <line x1="3.5" y1="19" x2="20.5" y2="19" />
            <circle cx="7" cy="19" r="2" />
          </svg>
        </button>
      </div>
    </header>
  );
}
