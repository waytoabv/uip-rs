import { createEffect, createSignal, For, Show, onCleanup } from 'solid-js';
import CountryFlag from './CountryFlag';
import { countryName } from './country';
import {
  actionPillClass,
  decodeThreatCategories,
  directionColorClass,
  directionGlyph,
  isHighThreat,
  localSide,
  logTypePillClass,
  networkPath,
  normalizeRuleDesc,
  rawMessage,
  serviceName,
  threatDotClass,
} from './LogHelpers';
import LogRowDetail from './LogRowDetail';

const PAGE_SIZE = 50;
/** TIME, TYPE, ACTION, SOURCE, dir, DESTINATION, COUNTRY, NETWORK, PROTO, SERVICE, RULE/INFO, ABUSEIPDB, CATEGORIES */
const COLUMN_COUNT = 13;

/**
 * Eine Log-Zeile, wie `/api/logs` und `/api/stream` sie liefern (siehe
 * `crates/uip-api/src/logs.rs`). Umfangreicher als die einfache `LogRow` aus
 * `api.ts`, die nur die Felder trägt, die die erste Fassung brauchte.
 */
export interface LogEntry {
  id: number;
  timestamp: string;
  log_type: string | null;
  direction: string | null;
  rule_action: string | null;
  rule_name: string | null;
  rule_desc: string | null;
  iface_in: string | null;
  iface_out: string | null;
  protocol: string | null;
  hostname: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  mac_address: string | null;
  dns_query: string | null;
  dns_type: string | null;
  dns_answer: string | null;
  dhcp_event: string | null;
  wifi_event: string | null;
  raw_log: string | null;
  geo_country: string | null;
  geo_city: string | null;
  geo_lat: number | null;
  geo_lon: number | null;
  asn_number: number | null;
  asn_name: string | null;
  rdns: string | null;
  threat_score: number | null;
  threat_categories: string[] | null;
  abuse_is_tor: boolean | null;
}

interface LogsResponse {
  rows: LogEntry[];
  next_cursor: string | null;
}

function logsUrl(query: string, before: string | undefined): string {
  const params = new URLSearchParams(query);
  params.set('limit', String(PAGE_SIZE));
  if (before) params.set('before', before);
  else params.delete('before');
  return `/api/logs?${params.toString()}`;
}

async function fetchLogsPage(query: string, before: string | undefined): Promise<LogsResponse> {
  const res = await fetch(logsUrl(query, before));
  if (!res.ok) return { rows: [], next_cursor: null };
  const body = (await res.json()) as Partial<LogsResponse>;
  return { rows: body.rows ?? [], next_cursor: body.next_cursor ?? null };
}

/** Firewall zeigt die Regel, alles andere die jeweils aussagekräftigste Nutzlast. */
function infoFor(row: LogEntry): string {
  if (row.log_type === 'firewall') {
    return normalizeRuleDesc(row.rule_desc) ?? row.rule_name ?? '—';
  }
  return row.dns_query ?? row.hostname ?? row.wifi_event ?? row.dhcp_event ?? rawMessage(row.raw_log) ?? '—';
}

/** Gerätename (eigene Seite) bzw. rDNS (Gegenseite) — siehe `localSide` in LogHelpers. */
function addressName(row: LogEntry, side: 'src' | 'dst'): string | null {
  const local = localSide(row.direction, row.src_ip, row.dst_ip);
  return side === local ? row.hostname : row.rdns;
}

function formatClock(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString('en-GB');
}

function TypePill(props: { type: string | null }) {
  return (
    <Show when={props.type} fallback={<span class="text-gray-700 text-[12px]">—</span>}>
      <span
        class={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${logTypePillClass(props.type)}`}
      >
        {props.type}
      </span>
    </Show>
  );
}

function ActionPill(props: { action: string | null; dhcpEvent: string | null; wifiEvent: string | null }) {
  const label = () => props.action ?? props.dhcpEvent ?? props.wifiEvent ?? null;
  return (
    <Show when={label()} fallback={<span class="text-gray-700 text-[12px]">—</span>}>
      <span
        class={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${actionPillClass(label())}`}
      >
        {label()}
      </span>
    </Show>
  );
}

function AddressCell(props: { ip: string | null; port: number | null; name: string | null }) {
  return (
    <Show when={props.ip} fallback={<span class="text-gray-700">—</span>}>
      <Show
        when={props.name}
        fallback={
          <span class="text-[13px] text-gray-300 whitespace-nowrap">
            {props.ip}
            <Show when={props.port != null}>
              <span class="text-gray-500">:{props.port}</span>
            </Show>
          </span>
        }
      >
        <div class="leading-tight min-w-0">
          <div class="text-[12px] text-gray-200 truncate max-w-[160px]" title={props.name ?? undefined}>
            {props.name}
          </div>
          <div class="text-[11px] text-gray-500 truncate max-w-[160px]">
            {props.ip}
            <Show when={props.port != null}>:{props.port}</Show>
          </div>
        </div>
      </Show>
    </Show>
  );
}

function CountryCell(props: { code: string | null }) {
  return (
    <Show when={props.code} fallback={<span class="text-gray-700">—</span>}>
      <span class="inline-flex items-center justify-center" title={countryName(props.code)}>
        <CountryFlag code={props.code} />
      </span>
    </Show>
  );
}

function ThreatCell(props: { score: number | null }) {
  return (
    <Show when={props.score != null} fallback={<span class="text-gray-700">—</span>}>
      <span class="inline-flex items-center gap-1.5">
        <span class={`w-1.5 h-1.5 rounded-full ${threatDotClass(props.score)}`} />
        <span class="text-gray-300 text-[13px]">{props.score}</span>
      </span>
    </Show>
  );
}

function CategoriesCell(props: { categories: string[] | null }) {
  const text = () => decodeThreatCategories(props.categories);
  return (
    <Show when={text()} fallback={<span class="text-gray-700">—</span>}>
      <span class="text-[11px] text-purple-400/70 truncate max-w-[180px] inline-block align-bottom" title={text() ?? undefined}>
        {text()}
      </span>
    </Show>
  );
}

/** Die Log-Tabelle mit ihrem Live-Stream, seitenweise blätterbar über den Cursor der API. */
export default function LogsView(props: { query: string }) {
  const [rows, setRows] = createSignal<LogEntry[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [paused, setPaused] = createSignal(false);
  // Ob der Live-Stream gerade pausiert ist, weil der aktive Filter nach
  // Feldern fragt, die erst die Anreicherung liefert (Land, Threat-Score).
  const [suspended, setSuspended] = createSignal(false);
  const [lastUpdate, setLastUpdate] = createSignal<Date | null>(null);
  const [expandedId, setExpandedId] = createSignal<number | null>(null);
  const [total, setTotal] = createSignal<{ total: number; exact: boolean } | null>(null);

  // Cursor-Stack für Zurück-Blättern: Index 0 ist die erste Seite (kein
  // `before`), jeder weitere Eintrag ist der Cursor, mit dem diese Seite
  // geladen wurde.
  const [beforeStack, setBeforeStack] = createSignal<(string | undefined)[]>([undefined]);
  const [nextCursor, setNextCursor] = createSignal<string | null>(null);

  const atFirstPage = () => beforeStack().length === 1;
  const pageNumber = () => beforeStack().length;

  /** Die Gesamtzahl für die Fußzeile — eigener Aufruf, damit das Blättern
   *  nicht darauf wartet. */
  function loadTotal(query: string) {
    setTotal(null);
    fetch(`/api/logs/count${query ? `?${query}` : ''}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((b) => setTotal(b ? { total: b.total, exact: b.exact } : null))
      .catch(() => setTotal(null));
  }

  function loadPage(query: string, before: string | undefined) {
    setLoading(true);
    fetchLogsPage(query, before)
      .then((body) => {
        setRows(body.rows);
        setNextCursor(body.next_cursor);
        setLastUpdate(new Date());
      })
      .catch(() => {
        setRows([]);
        setNextCursor(null);
      })
      .finally(() => setLoading(false));
  }

  // Ändert sich der Filter, springt die Ansicht zurück auf Seite 1 und baut
  // die SSE-Verbindung mit dem neuen Query-String neu auf — `EventSource`
  // kann ihre URL nachträglich nicht ändern.
  createEffect(() => {
    const q = props.query;
    setSuspended(false);
    setExpandedId(null);
    setBeforeStack([undefined]);
    loadTotal(q);
    loadPage(q, undefined);

    const es = new EventSource(`/api/stream${q ? `?${q}` : ''}`);
    es.addEventListener('log', (e) => {
      // Neue Zeilen laufen nur oben ein, solange man die neueste Seite
      // ansieht — sonst würden sie in eine ältere, bewusst aufgerufene Seite
      // hineinrutschen.
      if (paused() || !atFirstPage()) return;
      const row = JSON.parse((e as MessageEvent).data) as LogEntry;
      setRows((prev) => [row, ...prev].slice(0, PAGE_SIZE));
      setLastUpdate(new Date());
    });
    es.addEventListener('suspended', () => setSuspended(true));
    onCleanup(() => es.close());
  });

  const goNext = () => {
    const cursor = nextCursor();
    if (!cursor) return;
    setExpandedId(null);
    setBeforeStack((prev) => [...prev, cursor]);
    loadPage(props.query, cursor);
  };

  const goPrev = () => {
    const stack = beforeStack();
    if (stack.length <= 1) return;
    const next = stack.slice(0, -1);
    setExpandedId(null);
    setBeforeStack(next);
    loadPage(props.query, next[next.length - 1]);
  };

  const start = () => (rows().length === 0 ? 0 : (pageNumber() - 1) * PAGE_SIZE + 1);
  const end = () => (pageNumber() - 1) * PAGE_SIZE + rows().length;

  const isLive = () => !paused() && atFirstPage();

  return (
    <div class="flex flex-col h-full bg-gray-950 text-gray-200">
      {/* Werkzeugleiste */}
      <div class="flex items-center justify-between px-3 py-1.5 border-b border-gray-800/50">
        <div class="flex items-center gap-3">
          <button
            onClick={() => setPaused((v) => !v)}
            class={`flex items-center gap-1.5 text-[11px] transition-colors ${
              isLive() ? 'text-emerald-400' : 'text-amber-400'
            }`}
          >
            <span class={`w-1.5 h-1.5 rounded-full ${isLive() ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            {paused() ? 'Resume' : isLive() ? 'Live' : 'Paused'}
          </button>
          <Show when={lastUpdate()}>
            <span class="text-[10px] text-gray-500">Updated {lastUpdate()!.toLocaleTimeString('en-GB')}</span>
          </Show>
        </div>
      </div>

      <Show when={suspended()}>
        <p class="px-3 py-1.5 text-[11px] text-amber-400 bg-amber-500/10 border-b border-amber-500/30">
          Live-Stream pausiert: dieser Filter fragt nach Feldern (Land, Threat-Score, ASN), die erst nach der
          Anreicherung bekannt sind.
        </p>
      </Show>

      {/* Tabelle */}
      <div class="flex-1 overflow-auto">
        <table class="w-full text-left border-collapse">
          <thead class="sticky top-0 z-10 bg-gray-950">
            <tr>
              <th class="px-3 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Time</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Type</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Action</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Source</th>
              <th class="px-1 py-2 w-6"></th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Destination</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider text-center">
                Country
              </th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Network</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Proto</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Service</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Rule / Info</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">AbuseIPDB</th>
              <th class="px-2 py-2 text-[11px] text-gray-400 font-medium uppercase tracking-wider">Categories</th>
            </tr>
          </thead>
          <tbody>
            <Show
              when={!loading()}
              fallback={
                <tr>
                  <td colSpan={COLUMN_COUNT} class="text-center py-10 text-gray-500 text-sm">
                    Lädt…
                  </td>
                </tr>
              }
            >
              <Show
                when={rows().length > 0}
                fallback={
                  <tr>
                    <td colSpan={COLUMN_COUNT} class="text-center py-10 text-gray-500 text-sm">
                      No logs match this filter. Try a wider time range or reset the filters.
                    </td>
                  </tr>
                }
              >
                <For each={rows()}>
                  {(row) => {
                    const expanded = () => expandedId() === row.id;
                    const tint = isHighThreat(row.threat_score);
                    return (
                      <>
                        <tr
                          onClick={() => setExpandedId((cur) => (cur === row.id ? null : row.id))}
                          class={`cursor-pointer transition-colors hover:bg-gray-800/30 ${
                            expanded() ? '' : 'border-b border-gray-800/50'
                          } ${tint ? 'bg-red-950/20' : ''}`}
                        >
                          <td class="px-3 py-1.5 whitespace-nowrap text-[13px] text-gray-400" title={row.timestamp}>
                            {formatClock(row.timestamp)}
                          </td>
                          <td class="px-2 py-1.5">
                            <TypePill type={row.log_type} />
                          </td>
                          <td class="px-2 py-1.5">
                            <ActionPill action={row.rule_action} dhcpEvent={row.dhcp_event} wifiEvent={row.wifi_event} />
                          </td>
                          <td class="px-2 py-1.5">
                            <AddressCell ip={row.src_ip} port={row.src_port} name={addressName(row, 'src')} />
                          </td>
                          <td
                            class={`px-1 py-1.5 text-center text-sm ${directionColorClass(row.direction)}`}
                            title={row.direction ?? undefined}
                          >
                            {directionGlyph(row.direction)}
                          </td>
                          <td class="px-2 py-1.5">
                            <AddressCell ip={row.dst_ip} port={row.dst_port} name={addressName(row, 'dst')} />
                          </td>
                          <td class="px-2 py-1.5 text-center">
                            <CountryCell code={row.geo_country} />
                          </td>
                          <td class="px-2 py-1.5 text-[12px] text-gray-300 whitespace-nowrap">
                            {networkPath(row.iface_in, row.iface_out)}
                          </td>
                          <td class="px-2 py-1.5 text-[12px] text-gray-400 uppercase">{row.protocol ?? '—'}</td>
                          <td class="px-2 py-1.5 text-[12px] text-gray-400">{serviceName(row.dst_port)}</td>
                          <td
                            class="px-2 py-1.5 text-[12px] text-gray-400 whitespace-nowrap max-w-[200px] truncate"
                            title={infoFor(row)}
                          >
                            {infoFor(row)}
                          </td>
                          <td class="px-2 py-1.5 text-[13px]">
                            <ThreatCell score={row.threat_score} />
                          </td>
                          <td class="px-2 py-1.5">
                            <CategoriesCell categories={row.threat_categories} />
                          </td>
                        </tr>
                        <Show when={expanded()}>
                          <tr class="border-b border-gray-800/50">
                            <td colSpan={COLUMN_COUNT} class="p-0">
                              <LogRowDetail log={row} />
                            </td>
                          </tr>
                        </Show>
                      </>
                    );
                  }}
                </For>
              </Show>
            </Show>
          </tbody>
        </table>
      </div>

      {/* Fußzeile */}
      <div class="flex items-center justify-between px-3 py-2 border-t border-gray-800 text-[11px] text-gray-400">
        <span>
          {rows().length === 0
            ? 'No results'
            : `${start()}–${end()} of ${
                total() ? `${total()!.exact ? '' : '~'}${total()!.total.toLocaleString('en-GB')}` : '…'
              }`}
        </span>
        <div class="flex items-center gap-1">
          <button
            disabled={atFirstPage()}
            onClick={goPrev}
            class="px-2 py-1 text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            «
          </button>
          <span class="px-2 text-gray-300">Page {pageNumber()}</span>
          <button
            disabled={!nextCursor()}
            onClick={goNext}
            class="px-2 py-1 text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            »
          </button>
        </div>
      </div>
    </div>
  );
}
