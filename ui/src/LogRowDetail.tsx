import { For, Show } from 'solid-js';
import CountryFlag from './CountryFlag';
import { countryName } from './country';
import { decodeThreatCategories, normalizeRuleDesc, serviceName } from './LogHelpers';
import { type LogEntry } from './LogsView';
import { interfaceName } from './interfaceLabels';

/** Aus `wifiChannelWidth` wird „Wifi Channel Width" — lesbar, ohne dass für
 *  jedes Feld des Herstellers eine Übersetzung gepflegt werden müsste. */
function humanKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/^./, (c) => c.toUpperCase());
}

/** Die Felder eines Ereignisses, ohne die, die schon als Spalte dastehen. */
function detailEntries(details: Record<string, unknown> | null | undefined): [string, string][] {
  if (!details) return [];
  const skip = new Set(['msg', 'event', 'signature', 'host', 'utcTime']);
  return Object.entries(details)
    .filter(([k, v]) => !skip.has(k) && v != null && v !== '')
    .map(([k, v]) => [humanKey(k), typeof v === 'object' ? JSON.stringify(v) : String(v)]);
}

function Field(props: { label: string; children: unknown }) {
  return (
    <div class="min-w-0">
      <div class="text-[12px] uppercase tracking-wider text-gray-400 mb-0.5">{props.label}</div>
      <div class="text-sm text-gray-600 dark:text-gray-300 break-words">{props.children as never}</div>
    </div>
  );
}

/**
 * Aufgeklappte Detailzeile unter einer Log-Zeile — Gegenstück zu
 * `expanded-log-detail.png`: dieselben Gruppen (Adressen, Geo, Regel,
 * AbuseIPDB, Rohzeile), nur mit den Feldern, die unsere API tatsächlich
 * liefert.
 */
export default function LogRowDetail(props: { log: LogEntry }) {
  const l = () => props.log;

  return (
    <div class="px-4 py-3 bg-gray-50/60 dark:bg-gray-900/40 border-y border-gray-200/70 dark:border-gray-800/70 grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-3">
      <Field label="Source IP">
        {l().src_ip ?? '—'}
        {l().src_port != null ? `:${l().src_port}` : ''}
      </Field>
      <Field label="Destination IP">
        {l().dst_ip ?? '—'}
        {l().dst_port != null ? `:${l().dst_port}` : ''}
      </Field>
      <Field label="GeoIP">
        <Show when={l().geo_country} fallback="—">
          <span class="inline-flex items-center gap-1">
            <CountryFlag code={l().geo_country} /> {countryName(l().geo_country)}
            {l().geo_city ? ` · ${l().geo_city}` : ''}
          </span>
          <Show when={l().geo_lat != null && l().geo_lon != null}>
            <div class="text-[11px] text-gray-500">
              {l().geo_lat}, {l().geo_lon}
            </div>
          </Show>
        </Show>
      </Field>
      <Field label="ASN">
        <Show when={l().asn_name} fallback="—">
          {l().asn_name}
          <Show when={l().asn_number != null}>
            <span class="text-gray-500 ml-1.5">AS{l().asn_number}</span>
          </Show>
        </Show>
      </Field>
      <Field label="Protocol">{l().protocol?.toUpperCase() ?? '—'}</Field>

      <Field label="Rule">
        {normalizeRuleDesc(l().rule_desc) ?? l().rule_name ?? '—'}
      </Field>
      <Field label="Network">
        IN: {interfaceName(l().iface_in)} · OUT: {interfaceName(l().iface_out)}
        <Show when={l().mac_address}>
          <div class="text-[11px] text-gray-500">MAC: {l().mac_address}</div>
        </Show>
      </Field>
      <Field label="Service">
        {l().service ?? serviceName(l().dst_port)}
        <Show when={l().dst_port != null}>
          <span class="text-gray-500"> (port {l().dst_port})</span>
        </Show>
      </Field>
      <Field label="Hostname / rDNS">
        {l().hostname ?? l().rdns ?? '—'}
      </Field>

      <Field label="AbuseIPDB Score">
        <Show when={l().threat_score != null} fallback="—">
          {l().threat_score}% {l().abuse_is_tor ? '· Tor' : ''}
        </Show>
      </Field>
      <Field label="Categories">{decodeThreatCategories(l().threat_categories) ?? '—'}</Field>
      <Field label="DNS">
        <Show when={l().dns_query} fallback="—">
          {l().dns_query} {l().dns_type ? `(${l().dns_type})` : ''}
          <Show when={l().dns_answer}>
            <div class="text-[11px] text-gray-500 truncate">{l().dns_answer}</div>
          </Show>
        </Show>
      </Field>
      <Field label="Log ID">{l().id}</Field>

      {/* Was ein strukturiertes Ereignis mitbringt: Access Point, SSID, Kanal
          und Signalstärke bei einer WLAN-Verbindung; Zieldomain, erkannte
          Anwendung und Risiko bei einer Blockade; die geänderte Einstellung
          bei einem Eingriff im Controller. Welche Felder das sind, bestimmt
          das Ereignis — deshalb als Liste und nicht als feste Spalten. */}
      <Show when={detailEntries(l().details).length > 0}>
        <div class="col-span-2 sm:col-span-4">
          <Field label={(l().details?.event as string) ?? 'Event'}>
            <Show when={l().details?.msg as string}>
              <div class="mb-2 text-gray-700 dark:text-gray-200">{l().details?.msg as string}</div>
            </Show>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-1">
              <For each={detailEntries(l().details)}>
                {([key, value]) => (
                  <div class="min-w-0 text-[11px]">
                    <span class="text-gray-400">{key}: </span>
                    <span class="text-gray-600 dark:text-gray-300 break-words">{value}</span>
                  </div>
                )}
              </For>
            </div>
          </Field>
        </div>
      </Show>

      <div class="col-span-2 sm:col-span-4">
        <Field label="Raw Log">
          <pre class="whitespace-pre-wrap break-all text-[11px] text-gray-600 dark:text-gray-400 font-mono bg-gray-100 dark:bg-black/30 rounded p-2 mt-1">
            {l().raw_log ?? '—'}
          </pre>
        </Field>
      </div>
    </div>
  );
}
