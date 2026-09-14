export interface LogRow {
  id: number;
  timestamp: string;
  log_type: string | null;
  direction: string | null;
  rule_action: string | null;
  rule_name: string | null;
  iface_in: string | null;
  iface_out: string | null;
  protocol: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  dns_query: string | null;
  dhcp_event: string | null;
  wifi_event: string | null;
  raw_log: string | null;
  geo_country: string | null;
  geo_city: string | null;
  asn_name: string | null;
  rdns: string | null;
  threat_score: number | null;
}

export async function fetchLogs(query = ''): Promise<LogRow[]> {
  const res = await fetch(`/api/logs${query ? `?${query}` : ''}`);
  const body = await res.json();
  return body.rows as LogRow[];
}
