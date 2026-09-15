import { createEffect, createSignal, For, Show } from 'solid-js';
import CountryFlag from './CountryFlag';
import { countryName } from './country';

/**
 * Was eine einzelne Adresse treibt.
 *
 * Das Flussdiagramm zeigt Ströme, die Paarliste Verbindungen — hier steht,
 * mit wem dieser eine Host spricht, auf welchen Diensten, seit wann und wie
 * viel davon blockiert wurde. Das ist der Schritt von „da stimmt etwas nicht"
 * zu „das ist es".
 *
 * Der geteilte Filter gilt mit: sonst zeigte die Leiste andere Zahlen als die
 * Liste, aus der man sie geöffnet hat.
 */
interface Summary {
  ip: string;
  total: number;
  allowed: number;
  blocked: number;
  peers: number;
  first_seen: string | null;
  last_seen: string | null;
  asn_name: string | null;
  rdns: string | null;
  geo_country: string | null;
  geo_city: string | null;
  max_threat: number | null;
}

interface Detail {
  summary: Summary;
  peers: { ip: string; total: number; blocked: number }[];
  services: { port: number | null; protocol: string | null; service: string | null; total: number; blocked: number }[];
  rules: { rule: string | null; total: number }[];
  error?: string;
}

function when(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString('en-GB');
}

function Stat(props: { label: string; value: string | number; tone?: 'good' | 'bad' }) {
  return (
    <div>
      <div class="text-[10px] uppercase tracking-wider text-gray-500">{props.label}</div>
      <div
        class={`text-sm ${
          props.tone === 'bad'
            ? 'text-red-700 dark:text-red-400'
            : props.tone === 'good'
              ? 'text-emerald-700 dark:text-emerald-400'
              : 'text-gray-900 dark:text-gray-100'
        }`}
      >
        {props.value}
      </div>
    </div>
  );
}

export default function VizHostPanel(props: {
  ip: string;
  query: string;
  onClose: () => void;
  onFilter: (patch: Record<string, string>) => void;
}) {
  const [detail, setDetail] = createSignal<Detail | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(() => {
    const params = new URLSearchParams(props.query);
    params.set('ip', props.ip);
    setLoading(true);
    fetch(`/api/flows/host-detail?${params.toString()}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d: Detail | null) => setDetail(d))
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
  });

  const s = () => detail()?.summary;

  return (
    <aside class="fixed right-0 top-0 z-30 flex h-dvh w-[26rem] max-w-full flex-col border-l border-gray-200 bg-white shadow-xl dark:border-gray-800 dark:bg-gray-950">
      <div class="flex items-start justify-between gap-2 border-b border-gray-200 px-4 py-3 dark:border-gray-800">
        <div class="min-w-0">
          <div class="truncate text-sm font-semibold text-gray-900 dark:text-gray-100">{props.ip}</div>
          <Show when={s()?.rdns || s()?.asn_name}>
            <div class="truncate text-[11px] text-gray-500">
              {[s()?.rdns, s()?.asn_name].filter(Boolean).join(' · ')}
            </div>
          </Show>
          <Show when={s()?.geo_country}>
            <div class="mt-0.5 flex items-center gap-1.5 text-[11px] text-gray-500">
              <CountryFlag code={s()!.geo_country} />
              {[s()!.geo_city, countryName(s()!.geo_country)].filter(Boolean).join(', ')}
            </div>
          </Show>
        </div>
        <button
          type="button"
          onClick={props.onClose}
          aria-label="Close host detail"
          class="shrink-0 rounded px-2 py-1 text-gray-500 hover:text-gray-900 dark:hover:text-gray-200"
        >
          ✕
        </button>
      </div>

      <div class="flex-1 overflow-y-auto px-4 py-3">
        <Show
          when={!loading() && detail() && !detail()!.error}
          fallback={
            <p class="py-8 text-center text-sm text-gray-500">
              {loading() ? 'Loading…' : 'Nothing to show for this address.'}
            </p>
          }
        >
          <div class="grid grid-cols-4 gap-3">
            <Stat label="Events" value={s()!.total.toLocaleString('en-GB')} />
            <Stat label="Allowed" value={s()!.allowed.toLocaleString('en-GB')} tone="good" />
            <Stat label="Blocked" value={s()!.blocked.toLocaleString('en-GB')} tone="bad" />
            <Stat label="Peers" value={s()!.peers.toLocaleString('en-GB')} />
          </div>

          <div class="mt-3 grid grid-cols-2 gap-3 border-t border-gray-200 pt-3 dark:border-gray-800">
            <Stat label="First seen" value={when(s()!.first_seen)} />
            <Stat label="Last seen" value={when(s()!.last_seen)} />
          </div>

          <Show when={s()!.max_threat != null}>
            <div class="mt-3 border-t border-gray-200 pt-3 dark:border-gray-800">
              <Stat label="Highest threat score" value={s()!.max_threat!} tone="bad" />
            </div>
          </Show>

          <Section title="Top peers">
            <For each={detail()!.peers} fallback={<Empty />}>
              {(p) => (
                <Row
                  label={p.ip}
                  total={p.total}
                  blocked={p.blocked}
                  onClick={() => props.onFilter({ q: p.ip })}
                />
              )}
            </For>
          </Section>

          <Section title="Top services">
            <For each={detail()!.services} fallback={<Empty />}>
              {(sv) => (
                <Row
                  label={`${sv.service ?? sv.port ?? '—'}${sv.protocol ? `/${sv.protocol}` : ''}`}
                  total={sv.total}
                  blocked={sv.blocked}
                  onClick={() => sv.port != null && props.onFilter({ port: String(sv.port) })}
                />
              )}
            </For>
          </Section>

          <Section title="Rules hit">
            <For each={detail()!.rules} fallback={<Empty />}>
              {(r) => (
                <Row
                  label={r.rule ?? '—'}
                  total={r.total}
                  blocked={0}
                  onClick={() => r.rule && props.onFilter({ q: `rule:"${r.rule}"` })}
                />
              )}
            </For>
          </Section>
        </Show>
      </div>
    </aside>
  );
}

function Section(props: { title: string; children: unknown }) {
  return (
    <section class="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
      <h4 class="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
        {props.title}
      </h4>
      <div>{props.children as never}</div>
    </section>
  );
}

function Empty() {
  return <p class="py-1 text-[11px] text-gray-500">Nothing in this window.</p>;
}

function Row(props: { label: string; total: number; blocked: number; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      class="flex w-full items-center justify-between gap-2 rounded px-1 py-1 text-left text-[12px] hover:bg-gray-100 dark:hover:bg-gray-900"
    >
      <span class="min-w-0 truncate text-gray-800 dark:text-gray-200">{props.label}</span>
      <span class="shrink-0 tabular-nums text-gray-600 dark:text-gray-400">
        {props.total.toLocaleString('en-GB')}
        <Show when={props.blocked > 0}>
          <span class="ml-1 text-red-700 dark:text-red-400">
            ({props.blocked.toLocaleString('en-GB')} blocked)
          </span>
        </Show>
      </span>
    </button>
  );
}
