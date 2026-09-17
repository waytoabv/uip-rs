// @vitest-environment node
import { describe, expect, it } from 'vitest';
import {
  actionPillClass,
  decodeThreatCategories,
  directionColorClass,
  directionGlyph,
  isHighThreat,
  isPrivateIp,
  localSide,
  logTypePillClass,
  networkPath,
  shortenHost,
  normalizeRuleDesc,
  serviceName,
  threatDotClass,
  rawMessage,
  protocolName,
} from './LogHelpers';

describe('directionGlyph', () => {
  it('kennt alle Server-Richtungen', () => {
    expect(directionGlyph('inbound')).toBe('↓');
    expect(directionGlyph('outbound')).toBe('↑');
    expect(directionGlyph('local')).toBe('⟳');
    expect(directionGlyph('nat')).toBe('↳');
    expect(directionGlyph('inter_vlan')).toBe('⇔');
  });

  it('zeigt einen Strich für Unbekanntes oder Fehlendes', () => {
    expect(directionGlyph(null)).toBe('—');
    expect(directionGlyph(undefined)).toBe('—');
    expect(directionGlyph('sideways')).toBe('—');
  });
});

describe('directionColorClass', () => {
  it('gibt für jede Richtung eine Klasse zurück', () => {
    expect(directionColorClass('inbound')).toContain('red');
    expect(directionColorClass('outbound')).toContain('blue');
  });

  it('wirft nicht bei Unbekanntem', () => {
    expect(() => directionColorClass('bogus')).not.toThrow();
    expect(() => directionColorClass(null)).not.toThrow();
  });
});

describe('serviceName', () => {
  it('löst bekannte Ports auf', () => {
    expect(serviceName(443)).toBe('HTTPS');
    expect(serviceName(53)).toBe('DNS');
    expect(serviceName(123)).toBe('NTP');
  });

  it('fällt für unbekannte Ports auf die nackte Nummer zurück', () => {
    expect(serviceName(54321)).toBe('54321');
  });

  it('zeigt einen Strich ohne Port', () => {
    expect(serviceName(null)).toBe('—');
    expect(serviceName(undefined)).toBe('—');
  });
});

describe('isHighThreat', () => {
  it('greift ab der Schwelle (Standard 50)', () => {
    expect(isHighThreat(50)).toBe(true);
    expect(isHighThreat(49)).toBe(false);
    expect(isHighThreat(100)).toBe(true);
    expect(isHighThreat(0)).toBe(false);
  });

  it('ignoriert fehlende Scores', () => {
    expect(isHighThreat(null)).toBe(false);
    expect(isHighThreat(undefined)).toBe(false);
  });

  it('nimmt eine eigene Schwelle an', () => {
    expect(isHighThreat(80, 90)).toBe(false);
    expect(isHighThreat(90, 90)).toBe(true);
  });
});

describe('threatDotClass', () => {
  it('staffelt nach Score', () => {
    expect(threatDotClass(0)).toContain('emerald');
    expect(threatDotClass(10)).toContain('yellow');
    expect(threatDotClass(60)).toContain('orange');
    expect(threatDotClass(100)).toContain('red');
  });

  it('ist leer ohne Score', () => {
    expect(threatDotClass(null)).toBe('');
    expect(threatDotClass(undefined)).toBe('');
  });
});

describe('decodeThreatCategories', () => {
  it('übersetzt bekannte Codes', () => {
    expect(decodeThreatCategories(['14', '15'])).toBe('Port Scan, Hacking');
  });

  it('kennt das Sonderwort blacklist', () => {
    expect(decodeThreatCategories(['blacklist'])).toBe('Blacklist');
  });

  it('gibt null für leer oder fehlend', () => {
    expect(decodeThreatCategories(null)).toBeNull();
    expect(decodeThreatCategories(undefined)).toBeNull();
    expect(decodeThreatCategories([])).toBeNull();
  });
});

describe('normalizeRuleDesc', () => {
  it('trennt ]Text zu ] Text', () => {
    expect(normalizeRuleDesc('[WAN_IN-B-1-D]Block All Traffic')).toBe('[WAN_IN-B-1-D] Block All Traffic');
  });

  it('lässt bereits getrenntes in Ruhe', () => {
    expect(normalizeRuleDesc('[TAG] already spaced')).toBe('[TAG] already spaced');
  });

  it('gibt null ohne Text', () => {
    expect(normalizeRuleDesc(null)).toBeNull();
    expect(normalizeRuleDesc('')).toBeNull();
  });
});

describe('networkPath', () => {
  it('verbindet beide Schnittstellen', () => {
    expect(networkPath('ppp0', 'br20')).toBe('ppp0 → br20');
  });

  it('zeigt nur die eine bekannte Seite', () => {
    expect(networkPath('br20', null)).toBe('br20');
    expect(networkPath(null, 'br20')).toBe('br20');
  });

  it('zeigt einen Strich ohne beide', () => {
    expect(networkPath(null, null)).toBe('—');
    expect(networkPath(undefined, undefined)).toBe('—');
  });
});

describe('isPrivateIp', () => {
  it('erkennt RFC1918 und Loopback', () => {
    expect(isPrivateIp('10.10.30.5')).toBe(true);
    expect(isPrivateIp('192.168.2.8')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.32.0.1')).toBe(false);
  });

  it('erkennt öffentliche Adressen', () => {
    expect(isPrivateIp('2.125.160.216')).toBe(false);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
  });

  it('behandelt Fehlendes als privat, statt es als Ziel für Anreicherung zu behandeln', () => {
    expect(isPrivateIp(null)).toBe(true);
    expect(isPrivateIp(undefined)).toBe(true);
  });
});

describe('localSide', () => {
  it('folgt der Richtung, wenn bekannt', () => {
    expect(localSide('inbound', '2.125.160.216', '10.10.30.5')).toBe('dst');
    expect(localSide('outbound', '10.10.30.5', '2.125.160.216')).toBe('src');
  });

  it('greift auf die private Adresse zurück, wenn die Richtung nichts sagt', () => {
    expect(localSide('local', '10.10.10.1', '10.10.30.5')).toBe('src');
    expect(localSide(null, '2.125.160.216', '10.10.30.5')).toBe('dst');
  });
});

describe('logTypePillClass / actionPillClass', () => {
  it('kennt die Standardfarben', () => {
    expect(logTypePillClass('firewall')).toContain('blue');
    expect(logTypePillClass('dns')).toContain('violet');
    expect(actionPillClass('allow')).toContain('emerald');
    expect(actionPillClass('block')).toContain('red');
    expect(actionPillClass('redirect')).toContain('yellow');
  });

  it('wirft nicht bei Unbekanntem oder Fehlendem', () => {
    expect(() => logTypePillClass(null)).not.toThrow();
    expect(() => actionPillClass(undefined)).not.toThrow();
  });
});

describe('rawMessage', () => {
  it('schneidet den Syslog-Kopf ab, der in jeder Zeile gleich ist', () => {
    expect(
      rawMessage("<45>Sep 14 22:17:06 Express-7 Express-7 syslog-ng[2612919]: shutting down"),
    ).toBe('syslog-ng[2612919]: shutting down');
  });

  it('kommt auch ohne Prioritätspräfix und ohne zweiten Hostnamen zurecht', () => {
    expect(rawMessage('Feb  8 16:43:49 UDR kernel: something happened')).toBe(
      'kernel: something happened',
    );
  });

  it('lässt Unbekanntes stehen, statt es zu verschlucken', () => {
    expect(rawMessage('totaler muell ohne header')).toBe('totaler muell ohne header');
  });

  it('gibt für nichts auch nichts zurück', () => {
    expect(rawMessage(null)).toBeNull();
    expect(rawMessage('')).toBeNull();
    expect(rawMessage('   ')).toBeNull();
  });
});

describe('protocolName', () => {
  it('übersetzt die genormten Nummern', () => {
    expect(protocolName('2')).toBe('IGMP');
    expect(protocolName('6')).toBe('TCP');
    expect(protocolName('17')).toBe('UDP');
  });

  it('lässt Namen in Ruhe und schreibt sie groß', () => {
    expect(protocolName('tcp')).toBe('TCP');
    expect(protocolName('UDP')).toBe('UDP');
  });

  it('rät bei Unbekanntem nicht', () => {
    expect(protocolName('254')).toBe('254');
    expect(protocolName(null)).toBeNull();
    expect(protocolName('')).toBeNull();
    expect(protocolName('   ')).toBeNull();
  });
});

describe('shortenHost', () => {
  // Der Grenzwert ist das 90. Perzentil einer Tagesmenge echter Auflösungen:
  // neun von zehn Namen bleiben unberührt.
  it('lässt kurze Namen in Ruhe', () => {
    expect(shortenHost('dns.google.')).toBe('dns.google.');
    expect(shortenHost('ns1.example.com.')).toBe('ns1.example.com.');
  });

  it('behält Anfang und Herkunft, wirft die kodierte Mitte weg', () => {
    // Die ersten dreißig Zeichen wiederholen nur die Adresse, die eine Zeile
    // darunter ohnehin steht.
    expect(shortenHost('a23-61-199-130.deploy.static.akamaitechnologies.com.'))
      .toBe('a23…akamaitechnologies.com.');
  });

  it('behält den abschließenden Punkt nur, wenn er da war', () => {
    expect(shortenHost('a23-61-199-130.deploy.static.akamaitechnologies.com'))
      .toBe('a23…akamaitechnologies.com');
  });

  // Bei zwei Labels gäbe es nichts wegzulassen, ohne die Herkunft zu zerstören.
  it('rührt einen langen Namen ohne Unterdomäne nicht an', () => {
    const flat = 'averyveryverylongsingledomainname.example';
    expect(shortenHost(flat)).toBe(flat);
  });

  it('gibt für nichts nichts zurück', () => {
    expect(shortenHost(null)).toBeNull();
    expect(shortenHost('')).toBeNull();
  });
});
