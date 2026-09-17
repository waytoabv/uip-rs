import { createEffect, createMemo, createSignal, Match, Show, Switch } from 'solid-js';
import Dashboard from './Dashboard';
import FilterBar from './FilterBar';
import FlowView from './FlowView';
import LogsView from './LogsView';
import ShellHeader, { type NavTab } from './ShellHeader';
import ShellSettings from './ShellSettings';
import ThreatMap from './ThreatMap';
import { defaultFilters, describe, toQuery, type FilterState } from './filters';
import { loadInterfaceLabels } from './interfaceLabels';

const THEME_KEY = 'uip-theme';

type Theme = 'light' | 'dark';
type View = 'logs' | 'flows' | 'map' | 'dashboard';

// Reihenfolge und Beschriftung wie in der Vorlage: Log Stream, Flow View,
// Threat Map, Dashboard.
const TABS: readonly NavTab<View>[] = [
  { id: 'logs', label: 'Log Stream' },
  { id: 'flows', label: 'Flow View' },
  { id: 'map', label: 'Threat Map' },
  { id: 'dashboard', label: 'Dashboard' },
];

function storedTheme(): Theme | null {
  const raw = localStorage.getItem(THEME_KEY);
  return raw === 'light' || raw === 'dark' ? raw : null;
}

function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export default function App() {
  const [filters, setFilters] = createSignal<FilterState>(defaultFilters());
  const [view, setView] = createSignal<View>('logs');
  // `null` heißt: keine gespeicherte Wahl, die Systemeinstellung gilt.
  const [theme, setTheme] = createSignal<Theme | null>(storedTheme());
  // Die Filterleiste ist im Log offen — dort filtert man laufend. In den
  // anderen Ansichten kostet sie nur Höhe, die den Diagrammen fehlt, also
  // startet sie dort eingeklappt. Wer sie aufklappt, behält sie beim
  // Ansichtswechsel nicht: die Vorgabe richtet sich nach der Ansicht.
  const [filtersOpen, setFiltersOpen] = createSignal(true);
  const [settingsOpen, setSettingsOpen] = createSignal(false);
  // Der gerade getippte Suchbegriff. Er filtert schon mit, wird aber erst
  // mit Enter zu einem übernommenen Begriff — sonst entstünde aus jedem
  // Zwischenstand eine eigene Pille.
  const [searchDraft, setSearchDraft] = createSignal('');

  const showView = (v: View) => {
    setView(v);
    setFiltersOpen(v === 'logs');
  };

  const query = createMemo(() => {
    const f = filters();
    const d = searchDraft().trim();
    if (!d) return toQuery(f);
    const combined = [f.q.trim(), d].filter(Boolean).join(' ');
    return toQuery({ ...f, q: combined });
  });

  // Alle Ansichten teilen sich einen Filter: einmal filtern, aus vier
  // Blickwinkeln dieselbe Auswahl sehen. Ein Klick in Dashboard, Karte oder
  // Flussdiagramm setzt ihn hier.
  const applyFilter = (patch: Record<string, string>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  };

  // Die Namen der Netze einmal holen. Sie gelten für jede Ansicht, also
  // gehören sie hierher und nicht in die Tabelle, die sie zufällig zuerst
  // braucht.
  createEffect(() => {
    void loadInterfaceLabels();
  });

  // Setzt `data-theme` nur, wenn eine explizite Wahl getroffen wurde — sonst
  // bleibt das Attribut weg und `index.css` folgt der Systemeinstellung.
  createEffect(() => {
    const t = theme();
    if (t) {
      document.documentElement.setAttribute('data-theme', t);
      localStorage.setItem(THEME_KEY, t);
    } else {
      document.documentElement.removeAttribute('data-theme');
      localStorage.removeItem(THEME_KEY);
    }
  });

  const effectiveTheme = () => theme() ?? systemTheme();
  const toggleTheme = () => setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark');

  return (
    <div class="flex h-dvh flex-col bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-200">
      <ShellHeader tabs={TABS} activeView={view()} onSelectView={showView} theme={effectiveTheme()} onToggleTheme={toggleTheme} onOpenSettings={() => setSettingsOpen(true)} />
      <div class="flex items-center gap-2 border-b border-gray-200 px-4 py-1.5 dark:border-gray-800">
        <button
          type="button"
          aria-expanded={filtersOpen()}
          onClick={() => setFiltersOpen((v) => !v)}
          class="flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px] text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
        >
          <span class={`inline-block transition-transform ${filtersOpen() ? 'rotate-90' : ''}`}>›</span>
          Filters
        </button>
        {/* Eingeklappt muss ablesbar bleiben, dass überhaupt gefiltert wird —
            sonst sucht man den Grund für eine kurze Liste an der falschen
            Stelle. */}
        <Show when={!filtersOpen() && describe(filters()).length > 0}>
          <span class="text-[11px] text-teal-700 dark:text-teal-300">
            {describe(filters()).length} active
          </span>
        </Show>
      </div>
      <Show when={filtersOpen()}>
        <FilterBar
          filters={filters()}
          onChange={setFilters}
          draft={searchDraft()}
          onDraft={setSearchDraft}
        />
      </Show>
      <main class="flex-1 overflow-auto">
        <Switch>
          <Match when={view() === 'logs'}>
            <LogsView query={query()} />
          </Match>
          <Match when={view() === 'dashboard'}>
            <Dashboard query={query()} onFilter={applyFilter} />
          </Match>
          <Match when={view() === 'map'}>
            <ThreatMap query={query()} onFilter={applyFilter} />
          </Match>
          <Match when={view() === 'flows'}>
            <FlowView query={query()} onFilter={applyFilter} />
          </Match>
        </Switch>
      </main>
      <Show when={settingsOpen()}>
        <ShellSettings onClose={() => setSettingsOpen(false)} />
      </Show>
    </div>
  );
}
