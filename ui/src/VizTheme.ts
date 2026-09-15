import { createSignal, onCleanup, onMount } from 'solid-js';

/** Liest das aktuell wirksame Farbschema — explizite Wahl (`data-theme` auf
 * `<html>`, gesetzt von App.tsx) geht vor, sonst entscheidet die
 * Systemeinstellung. Dieselbe Regel wie App.tsx' `effectiveTheme`, hier aber
 * synchron und ohne Solid-Kontext nutzbar. */
function readIsDark(): boolean {
  const explicit = document.documentElement.dataset.theme;
  if (explicit === 'light') return false;
  if (explicit === 'dark') return true;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

/**
 * Reaktiver Zugriff auf "ist gerade dunkel?" — für die Fälle, in denen eine
 * CSS-Variable nicht reicht, weil eine Farbskala oder eine feste Palette
 * (Sankey-Knotenfarben, Bedrohungsstufen-Punkte auf der Karte) je Theme einen
 * eigenen Satz braucht statt nur einen Wert.
 *
 * Reagiert ohne Neuladen auf zwei Auslöser: einen Klick auf den
 * Theme-Umschalter in der Kopfzeile (ändert `data-theme` per Attribut —
 * beobachtet über `MutationObserver`) und einen Wechsel der
 * Systemeinstellung, solange keine explizite Wahl getroffen wurde
 * (`matchMedia`-`change`-Event).
 */
export function useIsDark(): () => boolean {
  const [isDark, setIsDark] = createSignal(readIsDark());

  onMount(() => {
    const update = () => setIsDark(readIsDark());

    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    const media = window.matchMedia('(prefers-color-scheme: dark)');
    media.addEventListener('change', update);

    onCleanup(() => {
      observer.disconnect();
      media.removeEventListener('change', update);
    });
  });

  return isDark;
}
