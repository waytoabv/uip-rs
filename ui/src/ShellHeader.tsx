import { createSignal, For, onMount, type JSX } from 'solid-js';

/**
 * Kopfzeile: Zeichen + Name, Reiter, Statusleiste.
 *
 * Für AbuseIPDB-Kontingent, MaxMind-Stand und den nächsten Abruf gibt es
 * noch keine Datenquelle — `/api/health` liefert nur "ok" als Klartext,
 * kein JSON mit diesen Feldern. Wir zeigen die Spalten trotzdem, mit „—"
 * statt sie wegzulassen: eine Leerstelle an erwarteter Stelle sagt „noch
 * nichts", eine fehlende Spalte sagt „gibt es nicht". Wird das Phase 4
 * nachliefert, ist hier nur der Platzhalter durch echte Werte zu ersetzen.
 */

export interface NavTab<View extends string> {
  id: View;
  label: string;
}

interface Props<View extends string> {
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

async function pingHealth(): Promise<boolean> {
  try {
    const res = await fetch('/api/health');
    return res.ok;
  } catch {
    return false;
  }
}

function formatCount(n: number | null): string {
  return n == null ? '—' : `${n.toLocaleString()} logs`;
}

export default function ShellHeader<View extends string>(props: Props<View>): JSX.Element {
  const [totalLogs, setTotalLogs] = createSignal<number | null>(null);
  const [alive, setAlive] = createSignal(true);

  onMount(() => {
    fetchTotalLogs().then(setTotalLogs);
    pingHealth().then(setAlive);
    // Hält den Log-Zähler und den "lebt"-Punkt frisch, ohne dass jede
    // andere Ansicht davon wissen muss.
    const timer = window.setInterval(() => {
      fetchTotalLogs().then(setTotalLogs);
      pingHealth().then(setAlive);
    }, 30_000);
    return () => window.clearInterval(timer);
  });

  return (
    <header class="flex items-center justify-between gap-4 border-b border-gray-800 bg-gray-950 px-4 py-2">
      <div class="flex min-w-0 flex-1 items-center gap-4 overflow-x-auto [&::-webkit-scrollbar]:hidden">
        <div class="flex shrink-0 items-center gap-2">
          <span
            class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border-[1.5px] border-teal-500 text-[11px] font-bold text-teal-400"
            aria-hidden="true"
          >
            U
          </span>
          <span class="hidden text-sm font-semibold text-gray-200 sm:inline">UniFi Log Insight</span>
        </div>

        <nav class="flex items-center gap-0.5">
          <For each={props.tabs}>
            {(tab) => (
              <button
                type="button"
                onClick={() => props.onSelectView(tab.id)}
                classList={{
                  'bg-gray-800 text-white': props.activeView === tab.id,
                  'text-gray-400 hover:text-gray-200': props.activeView !== tab.id,
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
          <span class="text-xs text-gray-400">AbuseIPDB: {'—'}</span>
          <span class="text-xs text-gray-600">|</span>
          <span class="text-xs text-gray-400">MaxMind: {'—'}</span>
          <span class="text-xs text-gray-600">|</span>
          <span class="text-xs text-gray-400">Next pull: {'—'}</span>
          <span class="text-xs text-gray-600">|</span>
          <span class="text-xs text-gray-400">{formatCount(totalLogs())}</span>
        </div>

        <span
          class="h-1.5 w-1.5 shrink-0 rounded-full"
          classList={{ 'bg-emerald-400': alive(), 'bg-red-400': !alive() }}
          title={alive() ? 'Server reachable' : 'Server unreachable'}
        />

        <button
          type="button"
          onClick={props.onToggleTheme}
          class="rounded p-1.5 text-gray-400 transition-colors hover:bg-gray-800 hover:text-gray-200"
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
          disabled
          class="cursor-not-allowed rounded p-1.5 text-gray-600 opacity-50"
          title="Settings (Phase 4)"
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
