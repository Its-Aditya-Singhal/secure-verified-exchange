// Builds the real desktop UI (apps/desktop) with Tauri replaced by
// mock-tauri.ts, for use inside the tutorial video:
//   (cd apps/desktop && npx vite build --config ../../brand/tutorial/app/vite.config.ts)
import { fileURLToPath } from "node:url";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const mock = here("./mock-tauri.ts");

export default {
  root: here("../../../apps/desktop"),
  base: "./",
  resolve: {
    alias: {
      "@tauri-apps/api/core": mock,
      "@tauri-apps/api/event": mock,
      "@tauri-apps/api/webview": mock,
      "@tauri-apps/api/app": mock,
    },
  },
  build: {
    target: "es2022",
    outDir: here("../out/app"),
    emptyOutDir: true,
    rollupOptions: { input: { main: here("../../../apps/desktop/index.html") } },
  },
};
