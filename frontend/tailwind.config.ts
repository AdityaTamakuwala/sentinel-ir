import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "var(--soc-bg)",
          surface: "var(--soc-surface)",
          elevated: "var(--soc-elevated)",
          border: "var(--soc-border)",
          text: "var(--soc-text)",
          muted: "var(--soc-muted)",
          accent: "var(--soc-accent)",
          "accent-muted": "var(--soc-accent-muted)",
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#38bdf8",
          resolved: "#22c55e",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;

