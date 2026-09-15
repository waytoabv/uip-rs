import { createSignal, For, onCleanup, onMount, Show } from 'solid-js';
import { ACTIONS, DIRECTIONS, type FilterState } from './filters';

/**
 * Das grafische Filterpanel des Forks.
 *
 * Jedes Feld wird zu einem Suchbegriff mit Präfix (`src:`, `dport:`, …), der
 * „is not"-Schalter setzt ein `!` davor. Damit braucht das Panel keinen
 * eigenen Zustand im Backend — es schreibt dieselbe Abfragesprache, die man
 * auch von Hand tippen kann, und alles Gesetzte erscheint anschließend als
 * Chip.
 */
const FIELDS: Array<{ key: string; prefix: string; label: string; hint: string }> = [
  { key: 'src', prefix: 'src', label: 'Source IP', hint: '10.10.30.5 or 10.10.30.0/24' },
  { key: 'dst', prefix: 'dst', label: 'Dest IP', hint: '1.1.1.1 or 1.1.1.*' },
  { key: 'ip', prefix: 'ip', label: 'Either IP', hint: 'matches source or dest' },
  { key: 'sport', prefix: 'sport', label: 'Source port', hint: '51234' },
  { key: 'dport', prefix: 'dport', label: 'Dest port', hint: '443' },
  { key: 'rule', prefix: 'rule', label: 'Rule', hint: 'LAN-to-WAN' },
  { key: 'iface', prefix: 'iface', label: 'Interface', hint: 'br20, ppp0' },
  { key: 'proto', prefix: 'proto', label: 'Protocol', hint: 'tcp, udp' },
  { key: 'country', prefix: 'country', label: 'Country', hint: 'DE, US, CN' },
  { key: 'asn', prefix: 'asn', label: 'ASN', hint: 'Cloudflare or 13335' },
  { key: 'free', prefix: '', label: 'Anything', hint: 'searched across every column' },
];

interface Draft {
  value: string;
  negated: boolean;
}

type Drafts = Record<string, Draft>;

function emptyDrafts(): Drafts {
  const d: Drafts = {};
  for (const f of FIELDS) d[f.key] = { value: '', negated: false };
  return d;
}

/** Ein Begriff so schreiben, dass der Parser ihn wieder auseinandernimmt. */
function toTerm(prefix: string, draft: Draft): string | null {
  const v = draft.value.trim();
  if (!v) return null;
  // Werte mit Leerzeichen brauchen Anführungen, sonst zerfallen sie in
  // mehrere Begriffe.
  const quoted = /\s/.test(v) ? `"${v}"` : v;
  const body = prefix ? `${prefix}:${quoted}` : quoted;
  return draft.negated ? `!${body}` : body;
}

/** Ein Segment-Schalter wie im Fork: „Any" plus die konkreten Werte. */
function Segmented(props: {
  options: readonly string[];
  labels?: Record<string, string>;
  value: string;
  onPick: (v: string) => void;
}) {
  return (
    <div class="flex gap-1">
      <For each={['', ...props.options]}>
        {(opt) => (
          <button
            type="button"
            onClick={() => props.onPick(opt)}
            class={`rounded border px-2.5 py-1 text-[11px] transition-colors ${
              props.value === opt
                ? 'border-teal-500/60 bg-teal-500/10 text-teal-700 dark:text-teal-300'
                : 'border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
            }`}
          >
            {opt === '' ? 'Any' : (props.labels?.[opt] ?? opt)}
          </button>
        )}
      </For>
    </div>
  );
}

export default function FilterPanel(props: {
  filters: FilterState;
  onApply: (patch: Partial<FilterState>) => void;
  onClose: () => void;
}) {
  const [drafts, setDrafts] = createSignal<Drafts>(emptyDrafts());
  const [action, setAction] = createSignal(props.filters.action);
  const [direction, setDirection] = createSignal(props.filters.direction);
  let root: HTMLDivElement | undefined;

  // Klick daneben schließt. Der Timeout verhindert, dass derselbe Klick, der
  // das Panel geöffnet hat, es sofort wieder zuklappt.
  onMount(() => {
    const onDown = (e: MouseEvent) => {
      if (root && !root.contains(e.target as Node)) props.onClose();
    };
    const t = setTimeout(() => document.addEventListener('mousedown', onDown), 0);
    onCleanup(() => {
      clearTimeout(t);
      document.removeEventListener('mousedown', onDown);
    });
  });

  const setField = (key: string, patch: Partial<Draft>) =>
    setDrafts((d) => ({ ...d, [key]: { ...d[key], ...patch } }));

  const apply = () => {
    const terms = FIELDS.map((f) => toTerm(f.prefix, drafts()[f.key])).filter(
      (t): t is string => t !== null,
    );
    const existing = props.filters.q.trim();
    props.onApply({
      q: [existing, ...terms].filter(Boolean).join(' '),
      action: action(),
      direction: direction(),
    });
    props.onClose();
  };

  const clearAll = () => {
    setDrafts(emptyDrafts());
    setAction('');
    setDirection('');
  };

  const anySet = () =>
    FIELDS.some((f) => drafts()[f.key].value.trim()) || action() !== '' || direction() !== '';

  return (
    <div
      ref={root}
      class="absolute right-0 top-full z-30 mt-2 w-[26rem] max-w-[calc(100vw-2rem)]
             rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-950 p-3 shadow-xl"
    >
      <div class="mb-3 flex items-center justify-between">
        <span class="text-xs font-medium text-gray-800 dark:text-gray-200">Filters</span>
        <span class="text-[10px] text-gray-500">* matches any characters</span>
      </div>

      <div class="max-h-[60vh] space-y-2.5 overflow-y-auto pr-1">
        <For each={FIELDS}>
          {(f) => (
            <label class="flex items-center gap-2">
              <span class="w-24 shrink-0 text-[11px] text-gray-600 dark:text-gray-400">{f.label}</span>
              <button
                type="button"
                aria-pressed={drafts()[f.key].negated}
                title={
                  drafts()[f.key].negated
                    ? 'Excluding — click to include'
                    : 'Click to exclude instead'
                }
                onClick={() => setField(f.key, { negated: !drafts()[f.key].negated })}
                class={`w-12 shrink-0 rounded border text-[11px] font-medium transition-colors ${
                  drafts()[f.key].negated
                    ? 'border-amber-500/60 bg-amber-500/20 text-amber-300'
                    : 'border-gray-300 dark:border-gray-700 bg-white dark:bg-black text-gray-400 dark:text-gray-600 hover:text-gray-700 dark:hover:text-gray-400'
                }`}
              >
                {drafts()[f.key].negated ? 'is not' : 'is'}
              </button>
              <input
                type="text"
                placeholder={f.hint}
                value={drafts()[f.key].value}
                onInput={(e) => setField(f.key, { value: e.currentTarget.value })}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    apply();
                  }
                }}
                class="min-w-0 flex-1 rounded border border-gray-300 dark:border-gray-700 bg-white dark:bg-black px-2 py-1 text-[11px]
                       text-gray-700 dark:text-gray-300 placeholder-gray-400 dark:placeholder-gray-600 focus:border-teal-500 focus:outline-none"
              />
            </label>
          )}
        </For>

        <div class="flex items-center gap-2 pt-1">
          <span class="w-24 shrink-0 text-[11px] text-gray-600 dark:text-gray-400">Action</span>
          <Segmented options={ACTIONS} value={action()} onPick={setAction} />
        </div>
        <div class="flex items-center gap-2">
          <span class="w-24 shrink-0 text-[11px] text-gray-600 dark:text-gray-400">Direction</span>
          <Segmented
            options={DIRECTIONS}
            labels={{ inter_vlan: 'Inter-VLAN' }}
            value={direction()}
            onPick={setDirection}
          />
        </div>
      </div>

      <div class="mt-3 flex items-center justify-end gap-2 border-t border-gray-200 dark:border-gray-800 pt-2.5">
        <Show when={anySet()}>
          <button
            type="button"
            onClick={clearAll}
            class="px-2 py-1 text-[11px] text-gray-500 hover:text-gray-900 dark:hover:text-gray-300"
          >
            Clear
          </button>
        </Show>
        <button
          type="button"
          onClick={props.onClose}
          class="rounded border border-gray-300 dark:border-gray-700 px-2.5 py-1 text-[11px] text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={apply}
          class="rounded border border-teal-500/60 bg-teal-500/10 px-2.5 py-1 text-[11px] text-teal-700 dark:text-teal-300 hover:bg-teal-500/20"
        >
          Apply
        </button>
      </div>
    </div>
  );
}
