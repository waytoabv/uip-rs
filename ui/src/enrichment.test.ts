// @vitest-environment node
import { describe as suite, expect, it } from 'vitest';
import { applyEnrichment, type Enrichment } from './enrichment';
import type { LogEntry } from './LogsView';

function row(extra: Partial<LogEntry> = {}): LogEntry {
  return {
    id: 1,
    timestamp: '2026-09-17T10:30:46Z',
    log_type: 'firewall',
    direction: 'outbound',
    rule_action: 'allow',
    rule_name: null,
    rule_desc: null,
    iface_in: 'br10',
    iface_out: 'eth1',
    protocol: 'udp',
    hostname: null,
    src_device: null,
    dst_device: null,
    src_ip: '10.10.10.103',
    dst_ip: '204.74.105.1',
    src_port: 20194,
    dst_port: 53,
    mac_address: null,
    dns_query: null,
    dns_type: null,
    dns_answer: null,
    dhcp_event: null,
    wifi_event: null,
    raw_log: null,
    geo_country: null,
    geo_city: null,
    geo_lat: null,
    geo_lon: null,
    asn_number: null,
    asn_name: null,
    rdns: null,
    threat_score: null,
    threat_categories: null,
    abuse_is_tor: null,
    ...extra,
  };
}

const facts: Enrichment = {
  ip: '204.74.105.1',
  geo_country: 'US',
  geo_city: 'Sterling',
  geo_lat: 39.0,
  geo_lon: -77.4,
  asn_number: 394353,
  asn_name: 'Vercara, LLC',
  rdns: 'ns1.example.net.',
  threat_score: null,
  threat_categories: null,
  abuse_is_tor: null,
};

suite('applyEnrichment', () => {
  it('füllt die Zeile, die auf diese Adresse zeigt', () => {
    const out = applyEnrichment(row(), facts);
    expect(out.geo_country).toBe('US');
    expect(out.asn_name).toBe('Vercara, LLC');
    expect(out.rdns).toBe('ns1.example.net.');
  });

  it('trifft die Adresse auch als Quelle', () => {
    const inbound = row({ src_ip: '204.74.105.1', dst_ip: '10.10.10.103' });
    expect(applyEnrichment(inbound, facts).asn_name).toBe('Vercara, LLC');
  });

  it('lässt fremde Zeilen unverändert — dieselbe Zeile, kein neues Objekt', () => {
    const other = row({ dst_ip: '1.1.1.1' });
    // Identität, nicht nur Gleichheit: Solid zeichnet sonst jede Zeile neu.
    expect(applyEnrichment(other, facts)).toBe(other);
  });

  /// Eine über /api/logs geladene Zeile hat ihre Angaben aus der Datenbank.
  /// Die ist die verlässlichere Quelle und darf nicht überschrieben werden.
  it('überschreibt nichts, was schon dasteht', () => {
    const known = row({ geo_country: 'DE', asn_name: 'Schon bekannt' });
    const out = applyEnrichment(known, facts);
    expect(out.geo_country).toBe('DE');
    expect(out.asn_name).toBe('Schon bekannt');
    // Was fehlte, kommt trotzdem dazu.
    expect(out.rdns).toBe('ns1.example.net.');
  });

  it('trägt auch Nullwerte nicht als Wert ein', () => {
    const out = applyEnrichment(row(), facts);
    expect(out.threat_score).toBeNull();
    expect(out.abuse_is_tor).toBeNull();
  });
});
