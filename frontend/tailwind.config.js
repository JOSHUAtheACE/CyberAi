/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#05080F",
          900: "#070B14",
          850: "#0A101B",
          800: "#0B1220",
          750: "#0D1524",
          700: "#111C2D",
          600: "#162237",
          500: "#1D2B44",
        },
        accent: {
          DEFAULT: "#36D9D0",
          soft: "#7FF0EA",
          dim: "#1B8F8A",
        },
        signal: {
          blue: "#4BA3FF",
          violet: "#8B7CF6",
          amber: "#F5B84B",
          rose: "#FF5C7A",
          mint: "#3DDC97",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        panel: "0 24px 80px -32px rgba(0, 0, 0, 0.75)",
        glow: "0 0 0 1px rgba(54, 217, 208, 0.18), 0 24px 60px -24px rgba(54, 217, 208, 0.28)",
      },
      backgroundImage: {
        "grid-faint":
          "linear-gradient(to right, rgba(148,163,184,0.055) 1px, transparent 1px), linear-gradient(to bottom, rgba(148,163,184,0.055) 1px, transparent 1px)",
        "radial-fade":
          "radial-gradient(ellipse at top, rgba(54,217,208,0.10), transparent 55%)",
      },
      keyframes: {
        pulseSoft: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.35" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-8px)" },
        },
      },
      animation: {
        "pulse-soft": "pulseSoft 2.4s ease-in-out infinite",
        scan: "scan 6s linear infinite",
        float: "float 7s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
