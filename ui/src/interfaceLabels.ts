/**
 * Die Namen der Netze, wie sie im UniFi-Controller stehen.
 *
 * Im Log steht `br15`, im Controller heißt das Netz „IoT". Die Zuordnung holt
 * `/api/networks` einmal beim Start — sie gilt für alle Zeilen gleich und
 * ändert sich selten, also wäre sie an jeder einzelnen Zeile Verschwendung.
 *
 * Bewusst nicht in `LogHelpers.ts`: die Datei hält sich frei von Solid, damit
 * sie ohne DOM testbar bleibt. Hier braucht es ein Signal, denn die Tabelle
 * steht schon, wenn die Antwort eintrifft, und muss sich dann neu zeichnen.
 */
import { createSignal } from 'solid-js';

export interface NetworkInfo {
  /** Wie das Netz im Controller heißt — `null` bei allem, was er nicht kennt. */
  name: string | null;
  vlan: number | null;
  purpose: string | null;
  /** Der selbst vergebene Name aus den Einstellungen. Er schlägt den Controller. */
  custom?: string | null;
}

const [labels, setLabels] = createSignal<Record<string, NetworkInfo>>({});

/** Die ganze Tabelle — für den Einstellungsdialog, der auch die rohen Kennungen braucht. */
export function interfaceTable(): Record<string, NetworkInfo> {
  return labels();
}

/** Holt die Zuordnung. Scheitert sie, bleibt es bei den rohen Namen. */
export async function loadInterfaceLabels(): Promise<void> {
  try {
    const res = await fetch('/api/networks');
    if (!res.ok) return;
    const body = (await res.json()) as { interfaces?: Record<string, NetworkInfo> };
    setLabels(body.interfaces ?? {});
  } catch {
    // Ohne Controller oder ohne Netz: die rohen Namen sind immer noch richtig,
    // nur weniger schön.
  }
}

/**
 * Der Name der Schnittstelle — der aus dem Controller, sonst der rohe.
 *
 * Kein „unbekannt": `br15` ist eine wahre Aussage über die Zeile, nur eine
 * unfreundlichere. Sie zu verbergen, weil der Controller gerade nichts dazu
 * sagt, nähme die Information ganz weg.
 */
export function interfaceName(iface: string | null | undefined): string {
  if (!iface) return '—';
  const info = labels()[iface];
  // Der selbst vergebene Name zuerst: wer ihn eingetragen hat, hat den des
  // Controllers gesehen und sich dagegen entschieden.
  return info?.custom || info?.name || iface;
}

/** Ob für diese Schnittstelle ein Name vorliegt — eigener oder aus dem Controller. */
export function hasInterfaceName(iface: string | null | undefined): boolean {
  if (!iface) return false;
  const info = labels()[iface];
  return !!(info?.custom || info?.name);
}

/**
 * Der Weg durchs Netz, mit Namen statt Kennungen: „IoT → WAN".
 *
 * Gleiche Form wie `networkPath` in `LogHelpers`, nur beschriftet — die rohe
 * Fassung bleibt für den Tooltip, damit `br15` erreichbar bleibt, wenn man
 * genau das sucht.
 */
export function namedNetworkPath(
  ifaceIn: string | null | undefined,
  ifaceOut: string | null | undefined,
): string {
  if (ifaceIn && ifaceOut) return `${interfaceName(ifaceIn)} → ${interfaceName(ifaceOut)}`;
  return ifaceIn || ifaceOut ? interfaceName(ifaceIn || ifaceOut) : '—';
}
