import { createEffect, createSignal, For, Show } from 'solid-js';

/**
 * Verkehrspaare — wer spricht mit wem, auf welchem Dienst.
 *
 * Das Flussdiagramm zeigt, *wohin* Verkehr geht, und fasst dafür auf zwölf
 * Knoten je Spalte zusammen. Diese Liste beantwortet die andere Frage: welche
 * konkrete Verbindung wie oft vorkam, erlaubt und blockiert getrennt. Das ist
 * die Sicht, die man beim Aufräumen von Firewall-Regeln braucht.
 */
interface Pair {
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  service: string | null;
  total: number;
  allowed: number;
  blocked: number;
  max_threat: number | null;
  asn_name: string | null;
}

async function fetchPairs(query: string): Promise<Pair[]> {
  const res = await fetch(`/api/stats/ip-pairs${query ? `?${query}` : ''}`);
  if (!res.ok) return [];
  const body = (await res.json()) as { pairs?: Pair[] };
  return body.pairs ?? [];
}

export default function VizPairs(props: {
  query: string;
  onFilter: (patch: Record<string, string>) => void;
  onInspect?: (ip: string) => void;
}) {
  const [pairs, setPairs] = createSignal<Pair[]>([]);
  const [loading, setLoading] = createSignal(true);

  createEffect(() => {
    const q = props.query;
    setLoading(true);
    fetchPairs(q)
      .then(setPairs)
      .finally(() => setLoading(false));
  });

  const maxTotal = () => pairs().reduce((m, p) => Math.max(m, p.total), 0);

  return (
    <div class="overflow-hidden rounded-lg border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-950">
      <div class="flex h-11 items-center gap-3 border-b border-gray-200 px-4 dark:border-gray-800">
        <h3 class="text-xs font-semibold uppercase tracking-wider text-gray-700 dark:text-gray-300">
          IP Pairs
        </h3>
        <span class="text-[11px] text-gray-500">who talks to whom, by volume</span>
      </div>

      <Show
        when={!loading() && pairs().length > 0}
        fallback={
          <p class="py-10 text-center text-sm text-gray-500">
            {loading() ? 'Loading…' : 'No traffic pairs for the current selection.'}
          </p>
        }
      >
        <table class="w-full text-left text-[13px]">
          <thead class="text-[10px] uppercase tracking-wider text-gray-500">
            <tr class="border-b border-gray-200 dark:border-gray-800">
              <th class="px-4 py-2 font-medium">Source</th>
              <th class="px-4 py-2 font-medium">Destination</th>
              <th class="px-4 py-2 font-medium">Service</th>
              <th class="px-4 py-2 text-right font-medium">Allowed</th>
              <th class="px-4 py-2 text-right font-medium">Blocked</th>
              <th class="px-4 py-2 text-right font-medium">Total</th>
            </tr>
          </thead>
          <tbody>
            <For each={pairs()}>
              {(p) => (
                <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50 dark:border-gray-900 dark:hover:bg-gray-900">
                  <td class="px-4 py-2">
                    <button
                      type="button"
                      class="text-gray-800 hover:underline dark:text-gray-200"
                      onClick={() => p.src_ip && (props.onInspect ? props.onInspect(p.src_ip) : props.onFilter({ q: `src:${p.src_ip}` }))}
                    >
                      {p.src_ip ?? '—'}
                    </button>
                  </td>
                  <td class="px-4 py-2">
                    <button
                      type="button"
                      class="text-gray-800 hover:underline dark:text-gray-200"
                      onClick={() => p.dst_ip && (props.onInspect ? props.onInspect(p.dst_ip) : props.onFilter({ q: `dst:${p.dst_ip}` }))}
                    >
                      {p.dst_ip ?? '—'}
                    </button>
                    <Show when={p.asn_name}>
                      <div class="text-[11px] text-gray-500">{p.asn_name}</div>
                    </Show>
                  </td>
                  <td class="px-4 py-2">
                    <button
                      type="button"
                      class="text-gray-700 hover:underline dark:text-gray-300"
                      onClick={() => p.dst_port != null && props.onFilter({ port: String(p.dst_port) })}
                    >
                      {p.service ?? p.dst_port ?? '—'}
                      <Show when={p.protocol}>
                        <span class="text-gray-500">/{p.protocol}</span>
                      </Show>
                    </button>
                  </td>
                  <td class="px-4 py-2 text-right text-emerald-700 dark:text-emerald-400">
                    {p.allowed ? p.allowed.toLocaleString('en-GB') : '—'}
                  </td>
                  <td class="px-4 py-2 text-right text-red-700 dark:text-red-400">
                    {p.blocked ? p.blocked.toLocaleString('en-GB') : '—'}
                  </td>
                  <td class="px-4 py-2 text-right">
                    <div class="text-gray-800 dark:text-gray-200">
                      {p.total.toLocaleString('en-GB')}
                    </div>
                    {/* Ein Balken je Zeile macht das Verhältnis ablesbar,
                        ohne dass man Zahlen vergleichen muss. */}
                    <div class="mt-1 h-0.5 w-full bg-gray-200 dark:bg-gray-800">
                      <div
                        class="h-full bg-blue-500"
                        style={{ width: `${maxTotal() ? (p.total / maxTotal()) * 100 : 0}%` }}
                      />
                    </div>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Show>
    </div>
  );
}
