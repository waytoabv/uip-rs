import { createMemo, createSignal, For, Show, type Component, type JSX } from 'solid-js';
import { formatCompactNumber, formatNumber } from './DashFormat';
import { areaPath, niceAxis, tickIndices, xScale, yScale } from './DashChartMath';

export interface SeriesPoint {
  t: string;
  allowed: number;
  blocked: number;
}

// Gemeinsame Bühne für beide Flächendiagramme: eine Bibliothek für zwei
// handgezeichnete Pfade lohnt nicht (siehe Vorgabe), aber Achsen, Skalierung
// und Hover-Logik teilen sich beide Karten.
// Breite nah an der tatsächlichen Anzeigebreite: sonst skaliert das SVG
// hoch und zieht Höhe und Schriftgrößen mit.
const W = 1600;
const PAD_L = 44;
const PAD_R = 10;
const PAD_T = 12;
const PAD_B = 22;

/**
 * Achsenbeschriftung.
 *
 * Entscheidend ist die **Spanne der Daten**, nicht die Bucht-Breite: bei
 * 15-Minuten-Buckets über zwei Tage zeigte die Achse nur Uhrzeiten und las
 * sich dadurch wie eine Zeitreise — 16:15, 21:45, 22:00, 16:45, 17:00.
 */
function formatTick(iso: string, bucket: string, spansDays: boolean): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const day = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
  if (!bucket.includes('hour') && !bucket.includes('minute')) return day;
  const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  return spansDays ? `${day} ${time}` : time;
}

/** Ob die Reihe mehr als einen Kalendertag berührt. */
function spansMultipleDays(points: { t: string }[]): boolean {
  if (points.length < 2) return false;
  const first = new Date(points[0].t).toDateString();
  return points.some((p) => new Date(p.t).toDateString() !== first);
}

/** x-Position, Hover-Index und die paar Dinge, die beide Diagramme aus der
 * Mausbewegung brauchen — einmal gebaut statt in jeder Komponente neu. */
function useHover(count: () => number) {
  const [hoverIdx, setHoverIdx] = createSignal<number | null>(null);
  const innerW = W - PAD_L - PAD_R;
  const onMove = (e: MouseEvent) => {
    const svg = e.currentTarget as SVGSVGElement;
    const rect = svg.getBoundingClientRect();
    const n = count();
    if (n === 0) {
      setHoverIdx(null);
      return;
    }
    const x = ((e.clientX - rect.left) / rect.width) * W;
    const frac = n <= 1 ? 0 : (x - PAD_L) / innerW;
    setHoverIdx(Math.min(n - 1, Math.max(0, Math.round(frac * (n - 1)))));
  };
  return { hoverIdx, onMove, onLeave: () => setHoverIdx(null) };
}

interface AxisProps {
  height: number;
  maxValue: number;
  points: SeriesPoint[];
  bucket: string;
}

/** Grundgerüst, das beide Karten teilen: Basislinie, y-Beschriftung, x-
 * Beschriftung. Die Flächen selbst kommen von außen als Kinder. */
const ChartAxes: Component<
  AxisProps & { onMouseMove: (e: MouseEvent) => void; onMouseLeave: () => void; children: JSX.Element }
> = (props) => {
  const innerH = () => props.height - PAD_T - PAD_B;
  // Glatte Obergrenze statt des rohen Maximums: sonst stehen an der Achse
  // krumme Zahlen und die Fläche klebt am oberen Rand.
  const axis = createMemo(() => niceAxis(props.maxValue));
  const y = createMemo(() => yScale(axis().max, PAD_T, PAD_T + innerH()));
  const x = createMemo(() => xScale(props.points.length, PAD_L, W - PAD_R));
  const xTickIdx = createMemo(() => tickIndices(props.points.length, 5));

  return (
    <svg
      viewBox={`0 0 ${W} ${props.height}`}
      class="w-full h-auto block"
      onMouseMove={props.onMouseMove}
      onMouseLeave={props.onMouseLeave}
    >
      {/* y-Achse: vier stille Hilfslinien plus Beschriftung, keine Achse mit
          Strich — im Original trägt nur die Zahl links die Information. */}
      <For each={axis().ticks}>
        {(v) => {
          const yy = y()(v);
          return (
            <>
              <line x1={PAD_L} y1={yy} x2={W - PAD_R} y2={yy} stroke="var(--border)" stroke-width="0.5" opacity="0.5" />
              <text x={PAD_L - 6} y={yy} dy="0.32em" text-anchor="end" font-size="9" fill="var(--muted)">
                {formatCompactNumber(v)}
              </text>
            </>
          );
        }}
      </For>

      {props.children}

      {/* x-Achse: Datum unter ein paar gleichmäßig verteilten Punkten. */}
      <For each={xTickIdx()}>
        {(i) => (
          <text
            x={x()(i)}
            y={props.height - 4}
            font-size="9"
            fill="var(--muted)"
            text-anchor={i === 0 ? 'start' : i === props.points.length - 1 ? 'end' : 'middle'}
          >
            {formatTick(props.points[i].t, props.bucket, spansMultipleDays(props.points))}
          </text>
        )}
      </For>
    </svg>
  );
};

/** "Traffic over Time": eine Fläche, blauer Verlauf, wie im Original. */
export const TrafficOverTimeChart: Component<{ points: SeriesPoint[]; bucket: string; empty?: string }> = (props) => {
  const H = 170;
  const innerH = H - PAD_T - PAD_B;
  const totals = createMemo(() => props.points.map((p) => p.allowed + p.blocked));
  const maxValue = createMemo(() => Math.max(1, ...totals(), 0));
  const { hoverIdx, onMove, onLeave } = useHover(() => props.points.length);

  const path = createMemo(() => {
    const y = yScale(niceAxis(maxValue()).max, PAD_T, PAD_T + innerH);
    const x = xScale(props.points.length, PAD_L, W - PAD_R);
    const xs = props.points.map((_, i) => x(i));
    const tops = totals().map((v) => y(v));
    const bottoms = props.points.map(() => PAD_T + innerH);
    return areaPath(xs, tops, bottoms);
  });

  const hovered = createMemo(() => {
    const i = hoverIdx();
    return i == null ? null : (props.points[i] ?? null);
  });
  const hoverX = createMemo(() => {
    const i = hoverIdx();
    return i == null ? 0 : xScale(props.points.length, PAD_L, W - PAD_R)(i);
  });

  return (
    <div class="relative">
      <Show when={props.points.length === 0}>
        <div class="absolute inset-0 flex items-center justify-center text-xs text-[var(--muted)]">{props.empty ?? 'No data'}</div>
      </Show>
      <ChartAxes height={H} maxValue={maxValue()} points={props.points} bucket={props.bucket} onMouseMove={onMove} onMouseLeave={onLeave}>
        <defs>
          <linearGradient id="dash-total-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.45" />
            <stop offset="100%" stop-color="#3b82f6" stop-opacity="0.03" />
          </linearGradient>
        </defs>
        <path d={path()} fill="url(#dash-total-grad)" stroke="#3b82f6" stroke-width="1.5" />
        <Show when={hovered()}>
          <line x1={hoverX()} y1={PAD_T} x2={hoverX()} y2={PAD_T + innerH} stroke="var(--muted)" stroke-dasharray="3,3" />
        </Show>
      </ChartAxes>
      <Show when={hovered()}>
        <div
          class="absolute -translate-x-1/2 -translate-y-full pointer-events-none rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-xs whitespace-nowrap"
          style={{ left: `${(hoverX() / W) * 100}%`, top: '0.5rem' }}
        >
          {formatTick(hovered()!.t, props.bucket, spansMultipleDays(props.points))} — {formatNumber(hovered()!.allowed + hovered()!.blocked)}
        </div>
      </Show>
    </div>
  );
};

/** "Traffic by Action": zwei übereinandergelegte Flächen, grün/rot. Die
 * Quelle liefert nur `allowed`/`blocked` — ein dritter ("redirect") Verlauf
 * käme aus keiner echten Zahl, deshalb bleibt er weg statt ihn zu erfinden. */
export const TrafficByActionChart: Component<{ points: SeriesPoint[]; bucket: string; empty?: string }> = (props) => {
  const H = 200;
  const innerH = H - PAD_T - PAD_B;
  const totals = createMemo(() => props.points.map((p) => p.allowed + p.blocked));
  const maxValue = createMemo(() => Math.max(1, ...totals(), 0));
  const { hoverIdx, onMove, onLeave } = useHover(() => props.points.length);

  const scales = createMemo(() => ({
    y: yScale(niceAxis(maxValue()).max, PAD_T, PAD_T + innerH),
    x: xScale(props.points.length, PAD_L, W - PAD_R),
  }));

  const allowedPath = createMemo(() => {
    const { x, y } = scales();
    const xs = props.points.map((_, i) => x(i));
    const tops = props.points.map((p) => y(p.allowed));
    const bottoms = props.points.map(() => PAD_T + innerH);
    return areaPath(xs, tops, bottoms);
  });
  const blockedPath = createMemo(() => {
    const { x, y } = scales();
    const xs = props.points.map((_, i) => x(i));
    const tops = props.points.map((p) => y(p.allowed + p.blocked));
    const bottoms = props.points.map((p) => y(p.allowed));
    return areaPath(xs, tops, bottoms);
  });

  const hovered = createMemo(() => {
    const i = hoverIdx();
    return i == null ? null : (props.points[i] ?? null);
  });
  const hoverX = createMemo(() => {
    const i = hoverIdx();
    return i == null ? 0 : scales().x(i);
  });

  return (
    <div class="relative">
      <Show when={props.points.length === 0}>
        <div class="absolute inset-0 flex items-center justify-center text-xs text-[var(--muted)]">{props.empty ?? 'No data'}</div>
      </Show>
      <ChartAxes height={H} maxValue={maxValue()} points={props.points} bucket={props.bucket} onMouseMove={onMove} onMouseLeave={onLeave}>
        <defs>
          <linearGradient id="dash-allowed-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#22c55e" stop-opacity="0.5" />
            <stop offset="100%" stop-color="#22c55e" stop-opacity="0.08" />
          </linearGradient>
          <linearGradient id="dash-blocked-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#ef4444" stop-opacity="0.5" />
            <stop offset="100%" stop-color="#ef4444" stop-opacity="0.08" />
          </linearGradient>
        </defs>
        <path d={allowedPath()} fill="url(#dash-allowed-grad)" stroke="#22c55e" stroke-width="1.5" />
        <path d={blockedPath()} fill="url(#dash-blocked-grad)" stroke="#ef4444" stroke-width="1.5" />
        <Show when={hovered()}>
          <line x1={hoverX()} y1={PAD_T} x2={hoverX()} y2={PAD_T + innerH} stroke="var(--muted)" stroke-dasharray="3,3" />
        </Show>
      </ChartAxes>
      <Show when={hovered()}>
        <div
          class="absolute -translate-x-1/2 -translate-y-full pointer-events-none rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-xs whitespace-nowrap"
          style={{ left: `${(hoverX() / W) * 100}%`, top: '0.5rem' }}
        >
          {formatTick(hovered()!.t, props.bucket, spansMultipleDays(props.points))} — allowed {formatNumber(hovered()!.allowed)}, blocked{' '}
          {formatNumber(hovered()!.blocked)}
        </div>
      </Show>
    </div>
  );
};
