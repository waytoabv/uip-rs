# Design review: uip-rs

Reviewed against Apple's Human Interface Guidelines using the `apple-design`
skill. Measured on 2026-09-17 against the live instance at 10.10.10.107 through
the dev server's proxy, at 1600×900, in both appearances.

## Summary

**Good**, once the contrast is fixed. The thesis is clear and unusual for its
genre: a firewall log that reads like a table of facts rather than a dashboard
of gauges — dense, quiet, and honest about what it does not know. The single
thing it will be remembered by is that empty means empty: a value the system
has not looked up yet says so with a dash rather than a zero, and the live
stream suspends visibly rather than filtering on data it does not have.

Seven text-contrast failures spread across both appearances were Critical and
are fixed. The remaining findings are conventions and craft.

Scope: this is a web app on the desktop, so it is reviewed against the
foundations — accessibility, colour, typography, layout, writing — and the
`lists-and-tables` guidance, which applies directly. Apple's platform
conventions for menu bars, windows and sheets do not apply and are not scored.

## Critical — fixed

All ratios composited through the real background stack, not estimated.

| Element | Was | Needs | Now |
| --- | --- | --- | --- |
| Proto / Service / Rule (light) | 2.54:1 | 4.5:1 | 7.56:1 |
| Placeholder `—` (light) | 1.47:1 | 4.5:1 | 4.69:1 |
| Placeholder `—` (dark) | 2.04:1 | 4.5:1 | 8.27:1 |
| Column headings (light) | 4.39:1 | 4.5:1 | 6.87:1 |
| Action pill ALLOW (light) | 3.43:1 | 4.5:1 | 6.99:1 |
| "No filters" (dark) | 2.78:1 | 4.5:1 | 8.27:1 |
| "Updated hh:mm" (dark) | 4.34:1 | 4.5:1 | 8.27:1 |

> `accessibility.md › Vision`: "Text size up to 17 pts, all weights: minimum
> contrast ratio 4.5:1." And: "If your app supports Dark Mode, make sure to
> check the minimum contrast in both light and dark appearances."

The dark appearance was not exempt — three of the seven were only visible
there. Two of them came from a duplicated Tailwind class
(`dark:text-gray-400 dark:text-gray-600`), where the second silently won.

## Improvements

**Alternating row colours — High. Fixed.**

> `lists-and-tables.md › Desktop (macOS)`: "Consider using alternating row
> colours in a multicolumn table. Alternating colours can help people track row
> values across columns, especially in a wide table."

The table is 1839 px wide against a 1600 px window, so it scrolls sideways:
exactly the case Apple names. Implemented over the row index rather than
`nth-child`, because an expanded detail row sits between data rows and would
otherwise shift the stripe.

**A false empty state while loading — High. Fixed.**

`/api/stats` takes 20.2 s against the 8 million rows on the live instance. For
those twenty seconds every dashboard card read "No data" and the headline read
"0 total logs" — a statement about the network where only a statement about the
request was true. The cards now say "Loading…", and "Could not load" when every
request failed, keeping "No data" for the one case it describes.

> `loading.md` via the skill's interaction lens: something appears immediately
> while loading, and feedback lives in the interface.

The cause was `fetchJson` not checking `res.ok`: a failure threw inside
`json()`, the `then` never ran, and the card kept its initial value forever.

**Truncated values are unreachable — Medium. Partly fixed.**

> `lists-and-tables.md › Content`: "Consider ways to preserve readability of
> text that might otherwise get clipped or truncated… an ellipsis in the middle
> of text can make an item easier to distinguish because it preserves both the
> beginning and the end."

Every cell that can clip now carries the full value as a tooltip. True middle
truncation is the better answer for this data — two Fastly rows reading
`cdn-185-1…` are indistinguishable while `cdn-185…-153` would not be — but it
needs per-cell width measurement for 50 rows across 14 columns on every render.
Deferred deliberately, not overlooked.

**No column sorting — Medium. Not implemented.**

> `lists-and-tables.md › Desktop (macOS)`: "When it provides value, let people
> click a column heading to sort a table view based on that column."

The table is ordered by time and paged with a `(timestamp, id)` cursor. Sorting
by threat score or country would need the sort key in the cursor and an index
per sort column. Worth doing, too large to fold into a design pass.

**Type sizes below the platform minimum — Low, by choice.**

`accessibility.md › Vision` puts the macOS minimum at 10 pt and the default at
13 pt, which is 13 px and 17 px. The table runs 11–13 px, and the pills 10 px.
A log that shows fourteen columns of network facts is the case where density
earns its keep, and Apple's own Console and Activity Monitor sit in the same
range. Named as the trade-off it is rather than silently ignored.

**All-caps column headings — Low. Not changed.**

`lists-and-tables.md › Content` asks for "nouns or short noun phrases with
title-style capitalization". The headings are set in uppercase with letter
spacing. This is a deliberate visual choice, and changing it touches the look
rather than the usability, so it is left to its owner.

## Craft notes

**Point of view: yes, and it is restraint.** Three things carry it — the dash
that means "not looked up", the amber suspended banner when a filter asks about
data a fresh row cannot have, and a status bar that separates "off", "working"
and "something is wrong" instead of the usual green-or-red. The design's
opinion is that a monitoring tool should never bluff. That is rarer than it
should be.

**Not a template.** None of the three currently dominant generated looks are
present: no cream-and-serif, no near-black with one acid accent, no broadsheet
of hairlines. The palette is Tailwind's default ramp, which is a default — but
it is used semantically (one colour per log type, one per action, kept stable
across both appearances) rather than decoratively.

**Where the boldness is spent:** the coloured pills for type and action, and
nothing else. Everything around them is grey. That is the right single place
for a table that people scan.

**Remove one accessory:** the date under every timestamp. Fifty rows repeat
"17 Sept" fifty times. A day separator between date changes would say more and
repeat less — but the second line is what keeps every row the same height, and
that was a deliberate decision. Nothing else asked to go.

## What works

- **Empty is empty.** `—` for a value not yet looked up, never a zero.
- **Three-state status.** Off, working, and broken are distinguishable in the
  header and in Settings; a missing answer is not shown as a negative one.
- **Resizable columns**, which `lists-and-tables.md › Desktop (macOS)` asks for
  explicitly, with the dragged width persisted and outranking the measurement.
- **Uniform row height** with widths measured once per page, so the table does
  not move while it streams.
- **The theme toggle stays.** `dark-mode.md › Best practices` says "avoid
  offering an app-specific appearance setting", but the browser gives a page no
  way to follow a per-app system preference. The implementation already does
  the right thing: no stored choice means follow `prefers-color-scheme`, and
  the toggle only overrides. Keeping it.
