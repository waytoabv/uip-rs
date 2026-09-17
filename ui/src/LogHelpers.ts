/**
 * Reine Hilfsfunktionen für die Log-Tabelle: Farbwerte, Symbole und kleine
 * Ableitungen aus den Rohdaten einer Log-Zeile. Kein Solid-Import hier —
 * das hält die Datei mit `vitest --environment node` testbar, ohne DOM.
 */

// ── Typ- und Aktions-Pillen ────────────────────────────────────────────────

// Farbwerte für hellen Modus stammen aus der Vorlage
// (`ui/src/index.css`, `[data-theme="light"]`-Block, im Fork-Repo): der
// dunkle -400-Text ist auf weißem Grund zu blass, darum dort ein kräftigerer
// Ton (600–900). Hintergrund und Rahmen bleiben meist gleich — die
// Deckkraft der Vorlage weicht nur um wenige Prozentpunkte ab, was hier
// nicht extra nachgebildet wird.
const LOG_TYPE_PILL: Record<string, string> = {
  firewall: 'bg-blue-500/10 dark:bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30',
  dns: 'bg-violet-500/10 dark:bg-violet-500/15 text-violet-700 dark:text-violet-400 border-violet-500/30',
  dhcp: 'bg-cyan-500/10 dark:bg-cyan-500/15 text-cyan-700 dark:text-cyan-400 border-cyan-500/30',
  wifi: 'bg-amber-500/10 dark:bg-amber-500/15 text-amber-800 dark:text-amber-400 border-amber-500/30',
  system: 'bg-gray-500/15 text-gray-600 dark:text-gray-300 border-gray-500/30',
};

const DEFAULT_PILL = 'bg-gray-500/15 text-gray-400 border-gray-500/30';

/** Tailwind-Klassen für die TYPE-Pille; unbekannte Typen bekommen ein neutrales Grau. */
export function logTypePillClass(logType: string | null | undefined): string {
  if (!logType) return DEFAULT_PILL;
  return LOG_TYPE_PILL[logType] ?? DEFAULT_PILL;
}

const ACTION_PILL: Record<string, string> = {
  allow: 'bg-emerald-500/10 dark:bg-emerald-500/15 text-emerald-800 dark:text-emerald-400 border-emerald-500/30',
  block: 'bg-red-500/10 dark:bg-red-500/20 text-red-800 dark:text-red-400 border-red-500/40',
  redirect: 'bg-yellow-500/10 dark:bg-yellow-500/15 text-yellow-900 dark:text-yellow-400 border-yellow-500/30',
};

/** Tailwind-Klassen für die ACTION-Pille (auch für DHCP-/WLAN-Ereignisse als Ersatzwert). */
export function actionPillClass(action: string | null | undefined): string {
  if (!action) return DEFAULT_PILL;
  return ACTION_PILL[action] ?? DEFAULT_PILL;
}

// ── Richtung ────────────────────────────────────────────────────────────────

const DIRECTION_GLYPHS: Record<string, string> = {
  inbound: '↓',
  outbound: '↑',
  local: '⟳',
  nat: '↳',
  inter_vlan: '⇔',
  vpn: '⛨',
};

/** Das Pfeilzeichen für die schmale Richtungsspalte; unbekannt bleibt „—". */
export function directionGlyph(direction: string | null | undefined): string {
  if (!direction) return '—';
  return DIRECTION_GLYPHS[direction] ?? '—';
}

const DIRECTION_COLOR: Record<string, string> = {
  inbound: 'text-red-600 dark:text-red-400',
  outbound: 'text-blue-700 dark:text-blue-400',
  local: 'text-gray-400',
  nat: 'text-yellow-900 dark:text-yellow-400',
  inter_vlan: 'text-gray-600 dark:text-gray-300',
  vpn: 'text-teal-600 dark:text-teal-400',
};

/** Textfarbe für das Richtungszeichen. */
export function directionColorClass(direction: string | null | undefined): string {
  if (!direction) return 'text-gray-600';
  return DIRECTION_COLOR[direction] ?? 'text-gray-500';
}

// ── Dienst aus Port/Protokoll ────────────────────────────────────────────────

/**
 * Kleine, lokale Näherung an eine Dienst-Tabelle — nur noch die Rückfallebene
 * für Zeilen, die (noch) kein `service`-Feld vom Server tragen (etwa frisch
 * über den Live-Stream eingetroffene Zeilen; siehe `LiveRow` in `uip-core`).
 * `/api/logs` liefert `service` bereits fertig aufgelöst aus der gepflegten
 * IANA-Tabelle (`crates/uip-api/src/services.rs`) — das hat immer Vorrang.
 */
const WELL_KNOWN_PORTS: Record<number, string> = {
  20: 'FTP-DATA',
  21: 'FTP',
  22: 'SSH',
  23: 'TELNET',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  80: 'HTTP',
  110: 'POP3',
  119: 'NNTP',
  123: 'NTP',
  135: 'RPC',
  137: 'NETBIOS',
  138: 'NETBIOS',
  139: 'NETBIOS',
  143: 'IMAP',
  161: 'SNMP',
  162: 'SNMP-TRAP',
  179: 'BGP',
  194: 'IRC',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  500: 'IKE',
  514: 'SYSLOG',
  546: 'DHCPV6',
  547: 'DHCPV6',
  587: 'SMTP',
  631: 'IPP',
  636: 'LDAPS',
  853: 'DNS-TLS',
  873: 'RSYNC',
  993: 'IMAPS',
  995: 'POP3S',
  1080: 'SOCKS',
  1194: 'OPENVPN',
  1433: 'MSSQL',
  1521: 'ORACLE',
  1701: 'L2TP',
  1723: 'PPTP',
  1883: 'MQTT',
  2049: 'NFS',
  2222: 'SSH-ALT',
  3128: 'PROXY',
  3306: 'MYSQL',
  3389: 'RDP',
  3478: 'STUN',
  4500: 'IPSEC-NAT',
  5060: 'SIP',
  5061: 'SIPS',
  5222: 'XMPP',
  5353: 'MDNS',
  5432: 'POSTGRES',
  5900: 'VNC',
  6379: 'REDIS',
  8080: 'HTTP-ALT',
  8443: 'HTTPS-ALT',
  8883: 'SECURE-MQTT',
  9100: 'PRINTER',
  27017: 'MONGODB',
};

/** Näherungsweiser Dienstname aus dem Zielport. Kein Protokollabgleich — nur eine Tabelle. */
export function serviceName(port: number | null | undefined): string {
  if (port == null) return '—';
  return WELL_KNOWN_PORTS[port] ?? String(port);
}

// ── Bedrohung ─────────────────────────────────────────────────────────────

/** Ab welchem Score eine Zeile den roten Schimmer bekommt. */
export const HIGH_THREAT_THRESHOLD = 50;

/** Ob eine Zeile als „hohe Bedrohung" gilt (für den Zeilen-Farbton). */
export function isHighThreat(score: number | null | undefined, threshold = HIGH_THREAT_THRESHOLD): boolean {
  return score != null && score >= threshold;
}

/** Farbe des kleinen Punktes in der ABUSEIPDB-Spalte, gestaffelt nach Score. */
export function threatDotClass(score: number | null | undefined): string {
  if (score == null) return '';
  if (score === 0) return 'bg-emerald-400';
  if (score < 50) return 'bg-yellow-400';
  if (score < 90) return 'bg-orange-400';
  return 'bg-red-400';
}

const ABUSE_CATEGORIES: Record<number, string> = {
  1: 'DNS Compromise',
  2: 'DNS Poisoning',
  3: 'Fraud Orders',
  4: 'DDoS Attack',
  5: 'FTP Brute-Force',
  6: 'Ping of Death',
  7: 'Phishing',
  8: 'Fraud VoIP',
  9: 'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  12: 'Blog Spam',
  13: 'VPN IP',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  17: 'Spoofing',
  18: 'Brute-Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted',
};

/** AbuseIPDB-Kategoriecodes zu einer lesbaren, komma-getrennten Liste. */
export function decodeThreatCategories(cats: readonly string[] | null | undefined): string | null {
  if (!cats || cats.length === 0) return null;
  return cats
    .map((c) => {
      if (c === 'blacklist') return 'Blacklist';
      const n = Number.parseInt(c, 10);
      return ABUSE_CATEGORIES[n] ?? `Cat ${c}`;
    })
    .join(', ');
}

// ── Regelbeschreibung ────────────────────────────────────────────────────────

/** Original schreibt `[TAG]Text` ohne Leerzeichen — das hier trennt sie wieder. */
export function normalizeRuleDesc(desc: string | null | undefined): string | null {
  if (!desc) return null;
  return desc.replace(/\](?!\s)/g, '] ');
}

// ── Netzwerkpfad ─────────────────────────────────────────────────────────────

/** `iface_in → iface_out`, oder nur die eine bekannte Schnittstelle, oder „—". */
export function networkPath(ifaceIn: string | null | undefined, ifaceOut: string | null | undefined): string {
  if (ifaceIn && ifaceOut) return `${ifaceIn} → ${ifaceOut}`;
  return ifaceIn || ifaceOut || '—';
}

/**
 * Kürzt einen zu langen Namen auf Anfang und Herkunft: `a23…akamai.com.`
 *
 * Rückwärtsauflösungen von CDNs bestehen fast vollständig aus der kodierten
 * Adresse — `a23-61-199-130.deploy.static.akamaitechnologies.com.` sind
 * zweiundfünfzig Zeichen, von denen die ersten dreißig nichts sagen, was nicht
 * schon in der IP-Zeile darunter steht. Aussagekräftig sind der Anfang (er
 * unterscheidet zwei Nachbarn voneinander) und die letzten beiden Labels (sie
 * nennen, wem die Adresse gehört).
 *
 * Der Grenzwert liegt bei dreißig Zeichen: das ist das 90. Perzentil einer
 * Tagesmenge echter Auflösungen, neun von zehn Namen bleiben also unberührt.
 */
export function shortenHost(name: string | null | undefined, max = 30): string | null {
  if (!name) return null;
  if (name.length <= max) return name;

  const trailingDot = name.endsWith('.');
  const labels = (trailingDot ? name.slice(0, -1) : name).split('.');
  // Weniger als drei Labels heißt: es gibt nichts wegzulassen, ohne die
  // Herkunft zu zerstören. Dann bleibt das Kürzen dem Abschneiden überlassen.
  if (labels.length < 3) return name;

  const origin = labels.slice(-2).join('.') + (trailingDot ? '.' : '');
  return `${name.slice(0, 3)}…${origin}`;
}

// ── Lokale vs. entfernte Seite ───────────────────────────────────────────────

/** Privat/reserviert im Sinne der Anzeige — nicht sicherheitskritisch, nur für die Zuordnung von Gerätename/rDNS. */
export function isPrivateIp(ip: string | null | undefined): boolean {
  if (!ip) return true;
  if (ip.includes(':')) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    if (lower.startsWith('fe80')) return true;
    if (lower.startsWith('ff')) return true;
    return false;
  }
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.')) {
    return true;
  }
  const m = /^172\.(\d+)\./.exec(ip);
  if (m) {
    const second = Number.parseInt(m[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

/**
 * Welche Seite (Quelle oder Ziel) das eigene Gerät ist. Der Server liefert nur
 * ein einzelnes `hostname`- und ein einzelnes `rdns`-Feld statt getrennter
 * Felder je Seite, also wird hier genähert: bei bekannter Richtung entscheidet
 * sie (passend zur serverseitigen Anreicherungslogik in `uip-enrich`), sonst
 * gewinnt die private Adresse.
 */
export function localSide(
  direction: string | null | undefined,
  srcIp: string | null | undefined,
  dstIp: string | null | undefined,
): 'src' | 'dst' {
  if (direction === 'inbound') return 'dst';
  if (direction === 'outbound') return 'src';
  if (isPrivateIp(srcIp)) return 'src';
  if (isPrivateIp(dstIp)) return 'dst';
  return 'src';
}

/**
 * Die lesbare Nutzlast einer Rohzeile.
 *
 * System-Zeilen tragen ihre ganze Information im Rohtext — sie werden
 * absichtlich unzerlegt gespeichert, damit nichts verlorengeht. In der
 * Tabelle blieben sie dadurch komplett leer. Angezeigt wird der Teil hinter
 * dem RFC3164-Kopf: Priorität, Zeitstempel und Hostname stehen bereits in
 * eigenen Spalten oder wiederholen sich in jeder Zeile.
 */
export function rawMessage(raw: string | null | undefined): string | null {
  if (!raw) return null;
  // <45>Sep 14 22:17:06 host host prog[123]: text  →  prog[123]: text
  let rest = raw.replace(/^<\d+>/, '');
  const stamp = rest.match(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+/);
  if (!stamp) return raw.trim() || null;
  rest = rest.slice(stamp[0].length);

  const [host, ...tail] = rest.split(/\s+/);
  // Manche Absender wiederholen den Hostnamen ("Express-7 Express-7 …") —
  // nur dann fällt der zweite weg, sonst wäre schon der Programmname dran.
  if (tail[0] === host) tail.shift();
  return tail.join(' ').trim() || null;
}

/**
 * Protokollnummer zu Namen.
 *
 * Manche Firewall-Zeilen tragen im PROTO-Feld eine Zahl statt eines Namens
 * (`PROTO=2`). Die Vorlage zeigt sie unverändert an — „2" sagt aber niemandem
 * etwas, und die Zuordnung ist genormt. Unbekanntes bleibt unverändert
 * stehen, statt geraten zu werden.
 */
const PROTOCOL_NUMBERS: Record<string, string> = {
  '1': 'ICMP',
  '2': 'IGMP',
  '4': 'IPv4',
  '6': 'TCP',
  '17': 'UDP',
  '41': 'IPv6',
  '47': 'GRE',
  '50': 'ESP',
  '51': 'AH',
  '58': 'ICMPv6',
  '89': 'OSPF',
  '112': 'VRRP',
  '132': 'SCTP',
};

export function protocolName(proto: string | null | undefined): string | null {
  if (!proto) return null;
  const trimmed = proto.trim();
  if (!trimmed) return null;
  return PROTOCOL_NUMBERS[trimmed] ?? trimmed.toUpperCase();
}
