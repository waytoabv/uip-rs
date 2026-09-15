import { createSignal, For, Show, type Component } from 'solid-js';
import FilterPanel from './FilterPanel';
import {
  ACTIONS,
  describe,
  DIRECTIONS,
  emptyFilters,
  isMultiActive,
  LOG_TYPES,
  RANGE_OPTIONS,
  toggleMulti,
  type FilterState,
} from './filters';

interface Props {
  filters: FilterState;
  onChange: (next: FilterState) => void;
}

// Aktive Pille je Log-Typ — Original: bg-<farbe>-500/15 text-<farbe>-400
// border-<farbe>-500/30. Inaktiv sind alle Pillen gleich: transparent und
// gedämpft.
const LOG_TYPE_STYLES: Record<string, string> = {
  firewall: 'bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30',
  dns: 'bg-violet-500/15 text-violet-700 dark:text-violet-400 border-violet-500/30',
  dhcp: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-400 border-cyan-500/30',
  wifi: 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30',
  system: 'bg-gray-500/15 text-gray-700 dark:text-gray-300 border-gray-500/30',
};

const ACTION_STYLES: Record<string, string> = {
  allow: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30',
  block: 'bg-red-500/20 text-red-700 dark:text-red-400 border-red-500/40',
  redirect: 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border-yellow-500/30',
  unknown: 'bg-gray-500/15 text-gray-600 dark:text-gray-400 border-gray-500/30',
};

const INACTIVE_PILL = 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-400';

const DIRECTION_ICONS: Record<string, string> = {
  inbound: '↓',
  outbound: '↑',
  inter_vlan: '⇔',
  nat: '↳',
  vpn: '⛨',
};

const DIRECTION_LABELS: Record<string, string> = {
  inbound: 'inbound',
  outbound: 'outbound',
  inter_vlan: 'vlan',
  nat: 'nat',
  vpn: 'vpn',
};

const DIRECTION_COLORS: Record<string, string> = {
  inbound: 'text-red-700 dark:text-red-400',
  outbound: 'text-blue-700 dark:text-blue-400',
  inter_vlan: 'text-gray-700 dark:text-gray-300',
  nat: 'text-yellow-700 dark:text-yellow-400',
  vpn: 'text-teal-700 dark:text-teal-400',
};

// Tooltip des Suchfelds. Begriffe werden UND-verknüpft, das Feld ist also
// zugleich der schnelle Weg, Filter zu stapeln, ohne das Panel zu öffnen.
// Wie im Fork: 'unknown' wird als UNK abgekürzt, der Rest ausgeschrieben.
const ACTION_LABELS: Record<string, string> = { unknown: 'UNK' };

const SEARCH_HELP = [
  'Every term must match. Enter keeps the term.',
  '',
  '10.10.10.10      that address exactly',
  '10.10.30.0/24    that subnet  (10.10.30.* works too)',
  '443              that port, either end',
  'nas              anywhere it is displayed',
  '"allow new"      an exact phrase',
  '!tcp             exclude',
  '',
  'Scope a term:  src: dst: ip: port: sport: dport:',
  '               rule: host: iface: country: asn: proto: action: type:',
].join('\n');

const FilterBar: Component<Props> = (props) => {
  const set = <K extends keyof FilterState>(key: K, value: string) => {
    props.onChange({ ...props.filters, [key]: value });
  };

  const toggleType = (t: string) => set('log_type', toggleMulti(props.filters.log_type, LOG_TYPES, t));
  const toggleAction = (a: string) => set('action', toggleMulti(props.filters.action, ACTIONS, a));
  const toggleDirection = (d: string) => set('direction', toggleMulti(props.filters.direction, DIRECTIONS, d));

  // Der getippte Begriff lebt getrennt vom übernommenen Filter. Beide in
  // `q` zu halten machte im Fork jeden Zwischenstand zu einem eigenen
  // Begriff — aus "10.10.10.0/24" wurden fünf.
  const [draft, setDraft] = createSignal('');
  const [showPanel, setShowPanel] = createSignal(false);

  // Wie viele Filter gerade wirken — die Zahl steht am Knopf, damit man
  // ein zugeklapptes Panel nicht für leer hält.
  const activeCount = () => describe(props.filters).length;

  const commitDraft = () => {
    const term = draft().trim();
    if (!term) return;
    const existing = props.filters.q.trim();
    set('q', existing ? `${existing} ${term}` : term);
    setDraft('');
  };

  return (
    <div class="space-y-3 border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950 px-4 py-3">
      {/* Reihe 1: Log-Typ, Aktion, Richtung, Zeitraum */}
      <div class="flex flex-wrap items-center gap-4">
        <div class="flex items-center gap-1.5">
          <For each={LOG_TYPES}>
            {(t) => (
              <button
                type="button"
                onClick={() => toggleType(t)}
                class={`rounded border px-2.5 py-[3px] text-xs font-medium uppercase transition-all ${
                  isMultiActive(props.filters.log_type, LOG_TYPES, t) ? LOG_TYPE_STYLES[t] : INACTIVE_PILL
                }`}
              >
                {t}
              </button>
            )}
          </For>
        </div>

        <div class="h-5 w-px bg-gray-300 dark:bg-gray-700" />

        <div class="flex items-center gap-1.5">
          <For each={ACTIONS}>
            {(a) => (
              <button
                type="button"
                onClick={() => toggleAction(a)}
                class={`rounded border px-2 py-[3px] text-xs font-medium uppercase transition-all ${
                  isMultiActive(props.filters.action, ACTIONS, a) ? ACTION_STYLES[a] : INACTIVE_PILL
                }`}
              >
                {ACTION_LABELS[a] ?? a}
              </button>
            )}
          </For>
        </div>

        <div class="h-5 w-px bg-gray-300 dark:bg-gray-700" />

        <div class="flex items-center gap-1">
          <For each={DIRECTIONS}>
            {(d) => {
              const active = () => isMultiActive(props.filters.direction, DIRECTIONS, d);
              return (
                <button
                  type="button"
                  onClick={() => toggleDirection(d)}
                  class={`rounded px-2 py-1 text-xs font-medium uppercase transition-all ${
                    active() ? 'border border-gray-400 dark:border-gray-600 bg-white dark:bg-black text-gray-900 dark:text-white' : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-400'
                  }`}
                >
                  <span classList={{ [DIRECTION_COLORS[d]]: active() }}>{DIRECTION_ICONS[d]}</span>{' '}
                  {DIRECTION_LABELS[d]}
                </button>
              );
            }}
          </For>
        </div>

        <div class="h-5 w-px bg-gray-300 dark:bg-gray-700" />

        <div class="flex items-center gap-1">
          <For each={RANGE_OPTIONS}>
            {(r) => (
              <button
                type="button"
                onClick={() => set('range', r.value)}
                class={`rounded px-2 py-1 text-xs font-medium transition-all ${
                  props.filters.range === r.value
                    ? 'border border-gray-400 dark:border-gray-600 bg-white dark:bg-black text-gray-900 dark:text-white'
                    : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-300'
                }`}
              >
                {r.label}
              </button>
            )}
          </For>
          {/* Kein Kalender-Picker in dieser Phase — statt sie zu verstecken,
              bleibt die Pille sichtbar (Bild der Vorlage bleibt vollständig),
              aber sichtbar abgeschaltet statt so zu tun als reagiere sie. */}
          <button
            type="button"
            disabled
            title="Custom date range — not available yet"
            class="cursor-not-allowed rounded px-2 py-1 text-xs font-medium text-gray-700 dark:text-gray-400 dark:text-gray-600 opacity-50"
          >
            Custom
          </button>
        </div>
      </div>

      {/* Reihe 2: was gerade filtert, und die zwei Wege es zu ändern.
          Der Fork hat die zehn Einzelfelder durch ein Suchfeld mit
          Übernahme-auf-Enter plus ein Filterpanel ersetzt; die Chips zeigen,
          was davon gerade wirkt. */}
      <div class="flex flex-col gap-2 lg:flex-row lg:items-start">
        <div class="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
          <Show
            when={describe(props.filters).length > 0}
            fallback={<span class="py-1 text-[11px] text-gray-700 dark:text-gray-400 dark:text-gray-600">No filters</span>}
          >
            <For each={describe(props.filters)}>
              {(chip) => (
                <span class="filter-chip">
                  <span class="filter-chip-value">{chip.label}</span>
                  <button
                    type="button"
                    aria-label={`Remove filter ${chip.label}`}
                    class="filter-chip-remove"
                    onClick={() => set(chip.key, '')}
                  >
                    ✕
                  </button>
                </span>
              )}
            </For>
            <button
              type="button"
              class="px-1.5 py-0.5 text-[11px] text-gray-500 hover:text-gray-900 dark:hover:text-gray-300"
              onClick={() => {
                setDraft('');
                props.onChange(emptyFilters());
              }}
            >
              Clear all
            </button>
          </Show>
        </div>

        <div class="flex shrink-0 items-center gap-2">
          <div class="relative w-full sm:w-72">
            <input
              type="text"
              placeholder="Filter — Enter to keep"
              title={SEARCH_HELP}
              value={draft()}
              onInput={(e) => setDraft(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  commitDraft();
                }
                if (e.key === 'Escape') {
                  e.preventDefault();
                  setDraft('');
                }
              }}
              class="w-full rounded border border-gray-300 dark:border-gray-700 bg-white dark:bg-black py-1.5 pl-7 pr-7 text-xs text-gray-700 dark:text-gray-300 placeholder-gray-400 dark:placeholder-gray-500 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20"
            />
            <span class="absolute left-2.5 top-1.5 text-xs text-gray-700 dark:text-gray-400 dark:text-gray-600">⌕</span>
            <Show when={draft()}>
              <button
                type="button"
                aria-label="Clear search"
                onClick={() => setDraft('')}
                class="absolute right-2 top-1.5 text-xs text-gray-500 hover:text-gray-900 dark:hover:text-gray-300"
              >
                ✕
              </button>
            </Show>
          </div>

          <div class="relative">
            <button
              type="button"
              aria-expanded={showPanel()}
              onClick={() => setShowPanel((v) => !v)}
              class={`whitespace-nowrap rounded border px-3 py-1.5 text-xs transition-colors ${
                activeCount() > 0
                  ? 'border-teal-500/60 bg-teal-500/10 text-teal-700 dark:text-teal-300'
                  : 'border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
              }`}
            >
              Filters{activeCount() > 0 ? ` (${activeCount()})` : ''}
            </button>
            <Show when={showPanel()}>
              <FilterPanel
                filters={props.filters}
                onApply={(patch) => props.onChange({ ...props.filters, ...patch })}
                onClose={() => setShowPanel(false)}
              />
            </Show>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FilterBar;
