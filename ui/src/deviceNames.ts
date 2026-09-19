/**
 * Die Gerätenamen zu den Adressen im eigenen Netz.
 *
 * Die geladene Zeilenliste bringt sie schon mit — `/api/logs` löst sie beim
 * Lesen auf. Der Live-Strom kann das nicht: er reicht eine Zeile weiter, sobald
 * sie geschrieben ist, und ein Nachschlagen je Zeile im heißesten Pfad wäre ein
 * hoher Preis für einen Namen, der sich selten ändert. Ohne diese Tabelle zeigte
 * deshalb jede gerade eintreffende Zeile ihre nackte Adresse und bekam ihren
 * Namen erst beim Neuladen der Seite.
 *
 * Gleiche Bauweise wie `interfaceLabels.ts`: einmal geholt, gilt für alle
 * Zeilen. Nachgeladen wird in großem Abstand — der Abgleich mit dem Controller
 * läuft alle fünf Minuten, schneller ändert sich ohnehin nichts.
 */
import { createSignal } from 'solid-js';

const [devices, setDevices] = createSignal<Record<string, string>>({});

/** Wie oft nachgesehen wird, ob der Controller etwas Neues kennt. */
export const DEVICE_REFRESH_MS = 5 * 60 * 1000;

/** Holt die Zuordnung. Scheitert sie, bleibt es bei den Adressen. */
export async function loadDeviceNames(): Promise<void> {
  try {
    const res = await fetch('/api/devices');
    if (!res.ok) return;
    const body = (await res.json()) as { devices?: Record<string, string> };
    setDevices(body.devices ?? {});
  } catch {
    // Ohne Controller oder ohne Netz: die Adresse ist immer noch richtig,
    // nur unfreundlicher.
  }
}

/** Der Name des Geräts hinter dieser Adresse, falls einer bekannt ist. */
export function deviceName(ip: string | null | undefined): string | null {
  if (!ip) return null;
  return devices()[ip] ?? null;
}
