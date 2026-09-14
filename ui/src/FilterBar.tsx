import { createEffect, createSignal, For, type Component, type JSX } from 'solid-js';
import {
  ACTIONS,
  describe,
  DIRECTIONS,
  LOG_TYPES,
  RANGE_OPTIONS,
  toQuery,
  type FilterState,
} from './filters';

interface Props {
  filters: FilterState;
  onChange: (next: FilterState) => void;
}

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

  const q = useCommittedText(props, 'q');
  const iface = useCommittedText(props, 'iface');
  const proto = useCommittedText(props, 'proto');
  const country = useCommittedText(props, 'country');
  const port = useCommittedText(props, 'port');
  const threatMin = useCommittedText(props, 'threat_min');

  const exportHref = () => {
    const query = toQuery(props.filters);
    return `/api/export${query ? `?${query}` : ''}`;
  };

  return (
    <div class="filter-bar">
      <div class="filter-row">
        <select value={props.filters.range} onChange={(e) => set('range', e.currentTarget.value)}>
          <option value="">Zeitraum: alle</option>
          <For each={RANGE_OPTIONS}>{(r) => <option value={r.value}>{r.label}</option>}</For>
        </select>
        <select value={props.filters.log_type} onChange={(e) => set('log_type', e.currentTarget.value)}>
          <option value="">Typ: alle</option>
          <For each={LOG_TYPES}>{(t) => <option value={t}>{t}</option>}</For>
        </select>
        <select value={props.filters.action} onChange={(e) => set('action', e.currentTarget.value)}>
          <option value="">Aktion: alle</option>
          <For each={ACTIONS}>{(a) => <option value={a}>{a}</option>}</For>
        </select>
        <select value={props.filters.direction} onChange={(e) => set('direction', e.currentTarget.value)}>
          <option value="">Richtung: alle</option>
          <For each={DIRECTIONS}>{(d) => <option value={d}>{d}</option>}</For>
        </select>
        <input
          class="filter-input"
          placeholder="Schnittstelle"
          value={iface.value()}
          onInput={iface.onInput}
          onKeyDown={iface.onKeyDown}
          onBlur={iface.onBlur}
        />
        <input
          class="filter-input"
          placeholder="Protokoll"
          value={proto.value()}
          onInput={proto.onInput}
          onKeyDown={proto.onKeyDown}
          onBlur={proto.onBlur}
        />
        <input
          class="filter-input"
          placeholder="Land"
          value={country.value()}
          onInput={country.onInput}
          onKeyDown={country.onKeyDown}
          onBlur={country.onBlur}
        />
        <input
          class="filter-input filter-input-narrow"
          type="number"
          min="1"
          max="65535"
          placeholder="Port"
          value={port.value()}
          onInput={port.onInput}
          onKeyDown={port.onKeyDown}
          onBlur={port.onBlur}
        />
        <input
          class="filter-input filter-input-narrow"
          type="number"
          min="0"
          max="100"
          placeholder="Threat ≥"
          value={threatMin.value()}
          onInput={threatMin.onInput}
          onKeyDown={threatMin.onKeyDown}
          onBlur={threatMin.onBlur}
        />
      </div>
      <div class="filter-row">
        <input
          class="filter-input search-input"
          placeholder="Suche… (Enter zum Anwenden)"
          value={q.value()}
          onInput={q.onInput}
          onKeyDown={q.onKeyDown}
          onBlur={q.onBlur}
        />
        <a class="csv-button" href={exportHref()} target="_blank" rel="noreferrer">
          CSV
        </a>
      </div>
      <div class="chip-row">
        <For each={describe(props.filters)}>
          {(chip) => (
            <span class="chip">
              {chip.label}
              <button
                class="chip-close"
                type="button"
                aria-label={`${chip.label} entfernen`}
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
