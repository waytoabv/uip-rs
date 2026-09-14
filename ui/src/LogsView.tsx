import { createEffect, createSignal, For, onCleanup } from 'solid-js';
import { fetchLogs, type LogRow } from './api';

const MAX_ROWS = 500;

/** Die Log-Tabelle mit ihrem Live-Stream. */
export default function LogsView(props: { query: string }) {
  const [rows, setRows] = createSignal<LogRow[]>([]);
  const [paused, setPaused] = createSignal(false);
  // Ob der Live-Stream gerade pausiert ist, weil der aktive Filter nach
  // Feldern fragt, die erst die Anreicherung liefert (Land, Threat-Score).
  const [suspended, setSuspended] = createSignal(false);

  // Ändert sich der Filter, lädt das eine `/api/logs` neu und baut die
  // SSE-Verbindung mit dem neuen Query-String neu auf — `EventSource` kann
  // ihre URL nachträglich nicht ändern.
  createEffect(() => {
    const q = props.query;
    setSuspended(false);
    fetchLogs(q).then(setRows);

    const es = new EventSource(`/api/stream${q ? `?${q}` : ''}`);
    es.addEventListener('log', (e) => {
      if (paused()) return;
      const row = JSON.parse((e as MessageEvent).data) as LogRow;
      setRows((prev) => [row, ...prev].slice(0, MAX_ROWS));
    });
    es.addEventListener('suspended', () => setSuspended(true));
    onCleanup(() => es.close());
  });

  return (
    <>
      <div class="view-actions">
        <button onClick={() => setPaused(!paused())}>{paused() ? 'Fortsetzen' : 'Pause'}</button>
      </div>
      {suspended() && (
        <p class="suspended-note">
          Live-Stream pausiert: dieser Filter fragt nach Feldern (Land, Threat-Score, ASN), die erst
          nach der Anreicherung bekannt sind.
        </p>
      )}
      <table>
        <thead>
          <tr>
            <th>Zeit</th>
            <th>Typ</th>
            <th>Richtung</th>
            <th>Aktion</th>
            <th>Quelle</th>
            <th>Ziel</th>
            <th>Proto</th>
            <th>Herkunft</th>
            <th>Threat</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          <For each={rows()}>
            {(r) => (
              <tr>
                <td>{new Date(r.timestamp).toLocaleTimeString()}</td>
                <td>{r.log_type}</td>
                <td>{r.direction}</td>
                <td>{r.rule_action}</td>
                <td title={r.rdns ?? ''}>
                  {r.src_ip}
                  {r.src_port != null ? `:${r.src_port}` : ''}
                </td>
                <td title={r.rdns ?? ''}>
                  {r.dst_ip}
                  {r.dst_port != null ? `:${r.dst_port}` : ''}
                </td>
                <td>{r.protocol}</td>
                <td>
                  {r.geo_country}
                  {r.geo_city ? ` / ${r.geo_city}` : ''}
                </td>
                <td>{r.threat_score != null ? r.threat_score : ''}</td>
                <td>{r.dns_query ?? r.dhcp_event ?? r.wifi_event ?? r.rule_name ?? r.raw_log}</td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </>
  );
}
