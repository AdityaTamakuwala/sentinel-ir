import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    environment: "./vitest-env-jsdom.ts",
    include: ["src/__tests__/**/*.test.{ts,tsx}"],
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
