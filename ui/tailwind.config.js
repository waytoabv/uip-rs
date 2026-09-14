/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['selector', ':root:not([data-theme="light"])'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        // 'UI Sans' ist die Hausschrift des Originals und wird hier nicht
        // mitgeliefert — wer sie rechtmäßig hat, legt sie unter public/fonts/
        // ab, alle anderen bekommen Inter, das sehr nah dran ist.
        sans: ['UI Sans', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['Fira Code', 'SF Mono', 'Cascadia Code', 'monospace'],
      },
      colors: {
        gray: { 950: '#000000' },
      },
    },
  },
  plugins: [],
};
