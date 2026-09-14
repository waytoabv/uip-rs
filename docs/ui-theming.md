# Farben und Themes in der Oberfläche

## Die Regel

**Die helle Fassung ist die Grundlage, die dunkle die Variante.**

```
class="bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-200"
```

Grund: `tailwind.config.js` setzt

```js
darkMode: ['selector', ':root:not([data-theme="light"])']
```

`dark:` greift also immer — außer jemand hat ausdrücklich Hell gewählt. Wer
eine dunkle Farbe ohne Variante schreibt, bekommt sie in **beiden** Themes.
Genau so ist der helle Modus kaputtgegangen: die Seite blieb schwarz, und nur
die wenigen Stellen mit CSS-Variablen wurden hell — ein Flickenteppich, der
schlimmer aussah als gar kein heller Modus.

## Woran man den Fehler erkennt

Jede Farbklasse ohne `dark:`-Gegenstück ist verdächtig:

```
bg-gray-950  text-gray-300  border-gray-800   ← falsch, wirkt in beiden Themes
bg-white dark:bg-gray-950                     ← richtig
```

Ausnahme sind Farben, die in beiden Themes gleich bleiben sollen — die
Akzentfarben der Pillen etwa (`text-blue-400`), sofern sie auf hellem Grund
noch lesbar sind. Im Zweifel nachsehen, nicht raten: der Fork führt für jede
Pille einen eigenen Wert je Theme.

## Die CSS-Variablen

`--bg`, `--fg`, `--muted`, `--surface`, `--border`, `--accent`, `--danger-fg`
existieren weiterhin und kippen korrekt mit `[data-theme]`. Sie sind der
bequemere Weg für eigene Stile in `<style>`-Blöcken und für SVG-Füllungen,
wo Tailwind-Klassen nicht greifen. Beides ist erlaubt; gemischt innerhalb
einer Komponente sollte es nicht sein.

## Prüfen

Nicht nach Augenmaß im dunklen Modus allein. `ui/screenshot.mjs` nimmt eine
laufende Instanz auf; für beide Themes einmal mit
`localStorage['uip-theme'] = 'light'` bzw. `'dark'` vorbelegen und die Bilder
nebeneinanderlegen. Ein heller Modus, der nur „nicht abstürzt", ist nicht
geprüft.
