// Mounts each top-level view with fetch/EventSource stubbed out, first with
// an empty payload and then with one row of real data.
//
// The bug this file exists to catch: FlowView's sankey layout was computed
// eagerly (`createMemo`) the instant the view mounted — before the first
// `/api/flows/sankey` response arrived, when the node list is necessarily
// empty — and d3-sankey threw `RangeError: Invalid array length` on an empty
// graph. No existing test mounted a component, so nothing could have caught
// it. `computeLayout` now guards the empty case (see sankeyLayout.ts), but a
// pure-function test of that guard doesn't prove the *view* survives an
// empty first render — only actually mounting it does.
import { render, waitFor } from '@solidjs/testing-library';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Dashboard from './Dashboard';
import FlowView from './FlowView';
import LogsView from './LogsView';
import type { LogEntry } from './LogsView';
import ThreatMap from './ThreatMap';

type Routes = Record<string, unknown>;

/** Routes a stubbed `fetch` by URL pathname. An endpoint this map doesn't
 * know about throws instead of quietly answering `{}` — an unstubbed
 * endpoint is a test that proves less than it appears to. */
function stubFetch(routes: Routes): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input.toString();
      const path = new URL(url, 'http://localhost').pathname;
      if (!(path in routes)) {
        throw new Error(`views.smoke.test: no stubbed response for fetch("${url}")`);
      }
      const body = routes[path];
      return { ok: true, json: async () => body } as Response;
    }),
  );
}

/** Minimal `EventSource`: enough for LogsView to open and (in `onCleanup`)
 * close a live-stream connection without jsdom needing real networking. */
class FakeEventSource {
  url: string;
  constructor(url: string) {
    this.url = url;
  }
  addEventListener(_type: string, _listener: (event: unknown) => void): void {}
  removeEventListener(_type: string, _listener: (event: unknown) => void): void {}
  close(): void {}
}

function stubEventSource(): void {
  vi.stubGlobal('EventSource', FakeEventSource);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const noopFilter = (_patch: Record<string, string>): void => {};

const EMPTY_ROUTES: Routes = {
  '/api/logs': { rows: [], next_cursor: null },
  '/api/logs/count': { total: 0, exact: true },
  '/api/stats': { total: 0, allowed: 0, blocked: 0, by_type: {}, unique_sources: 0, threats: 0 },
  '/api/stats/series': { bucket: '15 minutes', points: [] },
  '/api/stats/top': { rows: [] },
  '/api/threats/points': { points: [], blocked_total: 0 },
  '/api/flows/sankey': { nodes: [], links: [] },
  '/api/flows/zones': { zones: [], cells: [] },
};

const SAMPLE_LOG: LogEntry = {
  id: 1,
  timestamp: '2026-09-13T12:00:00Z',
  log_type: 'firewall',
  direction: 'inbound',
  rule_action: 'block',
  rule_name: 'WAN_LOCAL',
  rule_desc: null,
  iface_in: 'eth0',
  iface_out: 'eth1',
  protocol: 'tcp',
  hostname: null,
      src_device: null,
      dst_device: null,
  src_ip: '203.0.113.5',
  dst_ip: '10.0.0.5',
  src_port: 51000,
  dst_port: 443,
  mac_address: null,
  dns_query: null,
  dns_type: null,
  dns_answer: null,
  dhcp_event: null,
  wifi_event: null,
  raw_log: 'raw log line',
  geo_country: 'US',
  geo_city: 'Ashburn',
  geo_lat: 39.0,
  geo_lon: -77.5,
  asn_number: 15169,
  asn_name: 'GOOGLE',
  rdns: null,
  threat_score: 80,
  threat_categories: ['malware'],
  abuse_is_tor: false,
};

const POPULATED_ROUTES: Routes = {
  '/api/logs': { rows: [SAMPLE_LOG], next_cursor: null },
  '/api/logs/count': { total: 1, exact: true },
  '/api/stats': { total: 10, allowed: 7, blocked: 3, by_type: { firewall: 10 }, unique_sources: 2, threats: 1 },
  '/api/stats/series': {
    bucket: '15 minutes',
    points: [{ t: '2026-09-13T12:00:00Z', allowed: 7, blocked: 3 }],
  },
  '/api/stats/top': { rows: [{ key: 'US', label: 'United States', count: 5, extra: { blocked: 2 } }] },
  '/api/threats/points': {
    points: [
      { lat: 39.0, lon: -77.5, country: 'US', city: 'Ashburn', count: 3, max_threat: 80, sample_ip: '203.0.113.5' },
    ],
    blocked_total: 3,
  },
  '/api/flows/sankey': {
    nodes: [
      { id: 'source:10.0.0.5', label: '10.0.0.5', kind: 'source' },
      { id: 'destination:1.2.3.4', label: '1.2.3.4', kind: 'destination' },
    ],
    links: [{ source: 0, target: 1, value: 10, blocked: 2 }],
  },
  '/api/flows/zones': {
    zones: ['LAN', 'WAN'],
    cells: [{ from: 'LAN', to: 'WAN', allowed: 8, blocked: 2 }],
  },
};

describe('LogsView', () => {
  it('renders the empty state without throwing', async () => {
    stubFetch(EMPTY_ROUTES);
    stubEventSource();
    const { container, findByText } = render(() => <LogsView query="" />);
    await findByText(/No logs match this filter/);
    expect(container).toHaveTextContent('No logs match this filter');
  });

  it('renders one row of real data', async () => {
    stubFetch(POPULATED_ROUTES);
    stubEventSource();
    const { findByText } = render(() => <LogsView query="" />);
    await findByText('203.0.113.5');
    await findByText('WAN_LOCAL');
  });
});

describe('LogsView — Ereigniszeilen', () => {
  /** Eine WLAN-Verbindung, wie das Gateway sie als CEF-Ereignis schickt. */
  const WIFI_EVENT: LogEntry = {
    ...SAMPLE_LOG,
    id: 2,
    log_type: 'wifi',
    rule_action: null,
    rule_name: null,
    direction: null,
    src_ip: '10.10.15.98',
    dst_ip: null,
    src_port: null,
    dst_port: null,
    protocol: null,
    wifi_event: 'connected',
    raw_log: null,
    geo_country: null,
    geo_city: null,
    geo_lat: null,
    geo_lon: null,
    asn_number: null,
    asn_name: null,
    threat_score: null,
    threat_categories: null,
    program: 'unifi',
    details: {
      event: 'WiFi Client Connected',
      msg: 'iPhone Air connected to #1 on U7 Pro. Connection Info: Ch. 37 (6 GHz, 160 MHz), -60 dBm.',
      wifiName: '#1',
      connectedToDeviceName: 'U7 Pro',
      wiFiRssi: '-60',
    },
  };

  it('zeigt den Satz des Ereignisses statt einer leeren Spalte', async () => {
    stubFetch({ ...POPULATED_ROUTES, '/api/logs': { rows: [WIFI_EVENT], next_cursor: null } });
    stubEventSource();
    const { findByText } = render(() => <LogsView query="" />);
    // Früher stand hier nichts als eine MAC-Adresse.
    await findByText(/iPhone Air connected to #1 on U7 Pro/);
  });

  it('zeigt den Schweregrad, wo eine System-Zeile keine Aktion hat', async () => {
    const system: LogEntry = {
      ...WIFI_EVENT,
      id: 3,
      log_type: 'system',
      wifi_event: null,
      severity: 4,
      program: 'mca-ctrl',
      details: null,
      raw_log: '<12>Sep 19 08:00:00 Express-7 Express-7 mca-ctrl[123]: etwas ging schief',
    };
    stubFetch({ ...POPULATED_ROUTES, '/api/logs': { rows: [system], next_cursor: null } });
    stubEventSource();
    const { findByText } = render(() => <LogsView query="" />);
    await findByText('WARN');
    // Und das Programm steht in der Spalte, die sonst den Dienst zeigt.
    await findByText('mca-ctrl');
  });
});

describe('Dashboard', () => {
  it('renders the empty state without throwing', async () => {
    stubFetch(EMPTY_ROUTES);
    const { container, findAllByText } = render(() => <Dashboard query="" onFilter={noopFilter} />);
    const noData = await findAllByText('No data');
    // Log Types card + 8 dimension cards + 2 charts.
    expect(noData.length).toBeGreaterThan(0);
    expect(container).toHaveTextContent('Traffic Overview');
  });

  it('renders one row of real data', async () => {
    stubFetch(POPULATED_ROUTES);
    const { container } = render(() => <Dashboard query="" onFilter={noopFilter} />);
    // "firewall" and its count render as sibling text nodes inside one pill
    // (`{type} {formatNumber(n)}`), so match on the container rather than a
    // single node's exact text.
    await waitFor(() => expect(container).toHaveTextContent('firewall'));
    await waitFor(() => expect(container).toHaveTextContent('United States'));
  });
});

describe('ThreatMap', () => {
  it('renders the empty state without throwing', async () => {
    stubFetch(EMPTY_ROUTES);
    const { findByText } = render(() => <ThreatMap query="" onFilter={noopFilter} />);
    await findByText(/No blocked traffic/);
  });

  it('renders one point of real data', async () => {
    stubFetch(POPULATED_ROUTES);
    const { container, findByText, getByText } = render(() => (
      <ThreatMap query="" onFilter={noopFilter} />
    ));
    // Der Zähler in der Kopfzeile sagt, dass der Punkt angekommen ist; im
    // Heatmap-Modus wird er als Dichtefläche gezeichnet, nicht als Kreis.
    await findByText(/1\s*locations/);
    // Im Cluster-Modus wird derselbe Punkt zum Kreis — das prüft beide Wege.
    getByText('Cluster').click();
    await waitFor(() => expect(container.querySelectorAll('circle').length).toBeGreaterThan(0));
  });
});

describe('FlowView', () => {
  it('renders the empty state without throwing', async () => {
    stubFetch(EMPTY_ROUTES);
    const { findByText } = render(() => <FlowView query="" onFilter={noopFilter} />);
    // This is the case that used to crash: computeLayout ran on an empty
    // graph the instant the component mounted, before this placeholder text
    // had any data-free path to fall back to.
    await findByText('No flow data for the current selection.');
    // Die Zonenmatrix liegt hinter einem eigenen Reiter und ist deshalb erst
    // nach dem Wechsel im DOM.
    (await findByText('Zone Matrix')).click();
    await findByText('No zone traffic for the current selection.');
  });

  it('renders a two-node sankey of real data', async () => {
    stubFetch(POPULATED_ROUTES);
    const { findByText, container } = render(() => <FlowView query="" onFilter={noopFilter} />);
    await findByText('10.0.0.5');
    await findByText('1.2.3.4');
    await waitFor(() => expect(container.querySelectorAll('.flow-link')).toHaveLength(1));
  });
});
