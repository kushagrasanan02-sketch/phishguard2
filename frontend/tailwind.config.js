/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0b0f19",
          card: "#111827",
          panel: "#1e293b",
          border: "#1f293d",
          accent: "#06b6d4",
          "accent-hover": "#0891b2",
          safe: "#10b981",
          guarded: "#3b82f6",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#ef4444"
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}
