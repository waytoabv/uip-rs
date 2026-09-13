import { createSignal, For, onCleanup, onMount } from 'solid-js';
import { fetchLogs, type LogRow } from './api';

const MAX_ROWS = 500;

export default function App() {
  const [rows, setRows] = createSignal<LogRow[]>([]);
  const [paused, setPaused] = createSignal(false);

  onMount(async () => {
    setRows(await fetchLogs());
    const es = new EventSource('/api/stream');
    es.addEventListener('log', (e) => {
      if (paused()) return;
      const row = JSON.parse((e as MessageEvent).data) as LogRow;
      setRows((prev) => [row, ...prev].slice(0, MAX_ROWS));
    });
    onCleanup(() => es.close());
  });

  return (
    <main style={{ 'font-family': 'monospace', padding: '1rem' }}>
      <h1>uip</h1>
      <button onClick={() => setPaused(!paused())}>{paused() ? 'Resume' : 'Pause'}</button>
      <table>
        <thead>
          <tr><th>Zeit</th><th>Typ</th><th>Richtung</th><th>Aktion</th><th>Quelle</th><th>Ziel</th><th>Proto</th><th>Detail</th></tr>
        </thead>
        <tbody>
          <For each={rows()}>{(r) => (
            <tr>
              <td>{new Date(r.timestamp).toLocaleTimeString()}</td>
              <td>{r.log_type}</td>
              <td>{r.direction}</td>
              <td>{r.rule_action}</td>
              <td>{r.src_ip}{r.src_port != null ? `:${r.src_port}` : ''}</td>
              <td>{r.dst_ip}{r.dst_port != null ? `:${r.dst_port}` : ''}</td>
              <td>{r.protocol}</td>
              <td>{r.dns_query ?? r.dhcp_event ?? r.wifi_event ?? r.rule_name ?? r.raw_log}</td>
            </tr>
          )}</For>
        </tbody>
      </table>
    </main>
  );
}
