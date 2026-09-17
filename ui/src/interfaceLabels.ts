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

interface NetworkInfo {
  name: string;
  vlan: number | null;
  purpose: string | null;
}

const [labels, setLabels] = createSignal<Record<string, NetworkInfo>>({});

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
  return labels()[iface]?.name ?? iface;
}

/** Ob für diese Schnittstelle ein Name aus dem Controller vorliegt. */
export function hasInterfaceName(iface: string | null | undefined): boolean {
  return !!iface && labels()[iface] != null;
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
