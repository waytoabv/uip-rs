import { Show } from 'solid-js';
import CountryFlag from './CountryFlag';
import { countryName } from './country';
import { decodeThreatCategories, normalizeRuleDesc, serviceName } from './LogHelpers';
import { type LogEntry } from './LogsView';

function Field(props: { label: string; children: unknown }) {
  return (
    <div class="min-w-0">
      <div class="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">{props.label}</div>
      <div class="text-[13px] text-gray-200 break-words">{props.children as never}</div>
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
    <div class="px-4 py-3 bg-gray-900/40 border-y border-gray-800/70 grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-3">
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
      <Field label="Protocol">{l().protocol?.toUpperCase() ?? '—'}</Field>

      <Field label="Rule">
        {normalizeRuleDesc(l().rule_desc) ?? l().rule_name ?? '—'}
      </Field>
      <Field label="Network">
        IN: {l().iface_in ?? '—'} · OUT: {l().iface_out ?? '—'}
        <Show when={l().mac_address}>
          <div class="text-[11px] text-gray-500">MAC: {l().mac_address}</div>
        </Show>
      </Field>
      <Field label="Service">
        {serviceName(l().dst_port)}
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

      <div class="col-span-2 sm:col-span-4">
        <Field label="Raw Log">
          <pre class="whitespace-pre-wrap break-all text-[11px] text-gray-400 font-mono bg-black/30 rounded p-2 mt-1">
            {l().raw_log ?? '—'}
          </pre>
        </Field>
      </div>
    </div>
  );
}
