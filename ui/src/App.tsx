import { createEffect, createMemo, createSignal, For, Match, Switch } from 'solid-js';
import Dashboard from './Dashboard';
import FilterBar from './FilterBar';
import FlowView from './FlowView';
import LogsView from './LogsView';
import ThreatMap from './ThreatMap';
import { emptyFilters, toQuery, type FilterState } from './filters';

const THEME_KEY = 'uip-theme';

type Theme = 'light' | 'dark';
type View = 'logs' | 'dashboard' | 'map' | 'flows';

const VIEWS: { id: View; label: string }[] = [
  { id: 'logs', label: 'Logs' },
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'map', label: 'Karte' },
  { id: 'flows', label: 'Flüsse' },
];

function storedTheme(): Theme | null {
  const raw = localStorage.getItem(THEME_KEY);
  return raw === 'light' || raw === 'dark' ? raw : null;
}

function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export default function App() {
  const [filters, setFilters] = createSignal<FilterState>(emptyFilters());
  const [view, setView] = createSignal<View>('logs');
  // `null` heißt: keine gespeicherte Wahl, die Systemeinstellung gilt.
  const [theme, setTheme] = createSignal<Theme | null>(storedTheme());

  const query = createMemo(() => toQuery(filters()));

  // Alle Ansichten teilen sich einen Filter: einmal filtern, aus vier
  // Blickwinkeln dieselbe Auswahl sehen. Ein Klick in Dashboard, Karte oder
  // Flussdiagramm setzt ihn hier.
  const applyFilter = (patch: Record<string, string>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  };

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
    <main>
      <header class="app-header">
        <h1>uip</h1>
        <nav class="app-nav">
          <For each={VIEWS}>
            {(v) => (
              <button
                classList={{ active: view() === v.id }}
                onClick={() => setView(v.id)}
              >
                {v.label}
              </button>
            )}
          </For>
        </nav>
        <div class="app-actions">
          <button onClick={toggleTheme}>
            {effectiveTheme() === 'dark' ? 'Helles Design' : 'Dunkles Design'}
          </button>
        </div>
      </header>
      <FilterBar filters={filters()} onChange={setFilters} />
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
  );
}
