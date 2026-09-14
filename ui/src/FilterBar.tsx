import { createEffect, createSignal, For, type Component, type JSX } from 'solid-js';
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
  firewall: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  dns: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  dhcp: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  wifi: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  system: 'bg-gray-500/15 text-gray-300 border-gray-500/30',
};

const ACTION_STYLES: Record<string, string> = {
  allow: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  block: 'bg-red-500/20 text-red-400 border-red-500/40',
  redirect: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
};

const INACTIVE_PILL = 'border-transparent text-gray-500 hover:text-gray-400';

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
  inbound: 'text-red-400',
  outbound: 'text-blue-400',
  inter_vlan: 'text-gray-300',
  nat: 'text-yellow-400',
  vpn: 'text-teal-400',
};

/// Freitextfelder übernehmen erst bei Enter oder beim Verlassen des Felds —
/// nicht bei jedem Tastendruck, sonst schickt jeder Buchstabe eine neue
/// Abfrage los und die Ergebnisse springen, während noch getippt wird.
function useCommittedText(
  props: Props,
  key: keyof FilterState,
): {
  value: () => string;
  onInput: JSX.EventHandler<HTMLInputElement, InputEvent>;
  onKeyDown: JSX.EventHandler<HTMLInputElement, KeyboardEvent>;
  onBlur: JSX.EventHandler<HTMLInputElement, FocusEvent>;
} {
  const [local, setLocal] = createSignal(props.filters[key]);
  // Ein von außen geänderter Filter (z.B. ein gelöschter Chip) muss das
  // Feld zurücksetzen, auch wenn gerade nicht getippt wird.
  createEffect(() => setLocal(props.filters[key]));

  const commit = () => {
    if (local() !== props.filters[key]) {
      props.onChange({ ...props.filters, [key]: local() });
    }
  };

  return {
    value: local,
    onInput: (e) => setLocal(e.currentTarget.value),
    onKeyDown: (e) => {
      if (e.key === 'Enter') commit();
    },
    onBlur: commit,
  };
}

const FilterBar: Component<Props> = (props) => {
  const set = <K extends keyof FilterState>(key: K, value: string) => {
    props.onChange({ ...props.filters, [key]: value });
  };

  const toggleType = (t: string) => set('log_type', toggleMulti(props.filters.log_type, LOG_TYPES, t));
  const toggleAction = (a: string) => set('action', toggleMulti(props.filters.action, ACTIONS, a));
  const toggleDirection = (d: string) => set('direction', toggleMulti(props.filters.direction, DIRECTIONS, d));

  const ip = useCommittedText(props, 'ip');
  const rule = useCommittedText(props, 'rule');
  const iface = useCommittedText(props, 'iface');
  const sport = useCommittedText(props, 'sport');
  const dport = useCommittedText(props, 'dport');
  const proto = useCommittedText(props, 'proto');
  const service = useCommittedText(props, 'service');
  const country = useCommittedText(props, 'country');
  const asn = useCommittedText(props, 'asn');
  const q = useCommittedText(props, 'q');

  const textInputClass =
    'w-full min-w-0 rounded border border-gray-700 bg-black px-2 py-1.5 text-xs text-gray-300 ' +
    'placeholder-gray-500 focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-500/20';

  return (
    <div class="space-y-3 border-b border-gray-800 bg-gray-950 px-4 py-3">
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

        <div class="h-5 w-px bg-gray-700" />

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
                {a}
              </button>
            )}
          </For>
        </div>

        <div class="h-5 w-px bg-gray-700" />

        <div class="flex items-center gap-1">
          <For each={DIRECTIONS}>
            {(d) => {
              const active = () => isMultiActive(props.filters.direction, DIRECTIONS, d);
              return (
                <button
                  type="button"
                  onClick={() => toggleDirection(d)}
                  class={`rounded px-2 py-1 text-xs font-medium uppercase transition-all ${
                    active() ? 'border border-gray-600 bg-black text-white' : 'text-gray-500 hover:text-gray-400'
                  }`}
                >
                  <span classList={{ [DIRECTION_COLORS[d]]: active() }}>{DIRECTION_ICONS[d]}</span>{' '}
                  {DIRECTION_LABELS[d]}
                </button>
              );
            }}
          </For>
        </div>

        <div class="h-5 w-px bg-gray-700" />

        <div class="flex items-center gap-1">
          <For each={RANGE_OPTIONS}>
            {(r) => (
              <button
                type="button"
                onClick={() => set('range', r.value)}
                class={`rounded px-2 py-1 text-xs font-medium transition-all ${
                  props.filters.range === r.value
                    ? 'border border-gray-600 bg-black text-white'
                    : 'text-gray-400 hover:text-gray-300'
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
            class="cursor-not-allowed rounded px-2 py-1 text-xs font-medium text-gray-600 opacity-50"
          >
            Custom
          </button>
        </div>
      </div>

      {/* Reihe 2: Freitextfelder */}
      <div class="flex flex-wrap items-center gap-2">
        <input
          class={`${textInputClass} sm:w-32`}
          placeholder="IP address…"
          value={ip.value()}
          onInput={ip.onInput}
          onKeyDown={ip.onKeyDown}
          onBlur={ip.onBlur}
        />
        <input
          class={`${textInputClass} sm:w-32`}
          placeholder="Rule name…"
          value={rule.value()}
          onInput={rule.onInput}
          onKeyDown={rule.onKeyDown}
          onBlur={rule.onBlur}
        />
        <input
          class={`${textInputClass} sm:w-28`}
          placeholder="Interface…"
          value={iface.value()}
          onInput={iface.onInput}
          onKeyDown={iface.onKeyDown}
          onBlur={iface.onBlur}
        />
        <input
          class={`${textInputClass} sm:w-24`}
          type="text"
          inputmode="numeric"
          placeholder="Src port…"
          value={sport.value()}
          onInput={sport.onInput}
          onKeyDown={sport.onKeyDown}
          onBlur={sport.onBlur}
        />
        <input
          class={`${textInputClass} sm:w-24`}
          type="text"
          inputmode="numeric"
          placeholder="Dst port…"
          value={dport.value()}
          onInput={dport.onInput}
          onKeyDown={dport.onKeyDown}
          onBlur={dport.onBlur}
        />
        <input
          class={`${textInputClass} sm:w-24`}
          placeholder="Protocol…"
          value={proto.value()}
          onInput={proto.onInput}
          onKeyDown={proto.onKeyDown}
          onBlur={proto.onBlur}
        />
        <input
          class={`${textInputClass} sm:w-28`}
          placeholder="Service…"
          value={service.value()}
          onInput={service.onInput}
          onKeyDown={service.onKeyDown}
          onBlur={service.onBlur}
        />
        <input
          class={`${textInputClass} sm:w-28`}
          placeholder="Country code…"
          value={country.value()}
          onInput={country.onInput}
          onKeyDown={country.onKeyDown}
          onBlur={country.onBlur}
        />
        <input
          class={`${textInputClass} sm:w-24`}
          placeholder="ASN…"
          value={asn.value()}
          onInput={asn.onInput}
          onKeyDown={asn.onKeyDown}
          onBlur={asn.onBlur}
        />
        <input
          class={`${textInputClass} min-w-[10rem] flex-1`}
          placeholder="Search raw log…"
          value={q.value()}
          onInput={q.onInput}
          onKeyDown={q.onKeyDown}
          onBlur={q.onBlur}
        />
        <button
          type="button"
          class="shrink-0 px-1.5 py-0.5 text-xs text-gray-500 hover:text-gray-300"
          onClick={() => props.onChange(emptyFilters())}
        >
          Reset
        </button>
      </div>

      {/* Aktive Filter als Chips — jeder einzeln entfernbar. */}
      <div class="flex flex-wrap items-center gap-1.5">
        <For each={describe(props.filters)} fallback={<span class="py-1 text-[11px] text-gray-600">No filters</span>}>
          {(chip) => (
            <span class="inline-flex items-center gap-1 rounded-full bg-gray-800 py-0.5 pl-2.5 pr-1 text-[11px] text-gray-300">
              {chip.label}
              <button
                type="button"
                aria-label={`${chip.label} entfernen`}
                class="rounded-full px-1 text-gray-500 hover:text-gray-200"
                onClick={() => set(chip.key, '')}
              >
                ×
              </button>
            </span>
          )}
        </For>
      </div>
    </div>
  );
};

export default FilterBar;
