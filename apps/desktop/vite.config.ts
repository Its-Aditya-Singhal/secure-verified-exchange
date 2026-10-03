import { defineConfig } from "vite";

// Tauri expects a fixed port in dev and a relative build in dist/.
export default defineConfig({
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: "localhost" },
  build: { target: "es2022", outDir: "dist", emptyOutDir: true, sourcemap: false },
});
