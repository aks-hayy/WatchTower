import tailwindcss from "@tailwindcss/vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";
import { nitro } from "nitro/vite";
import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";

const apiOrigin = process.env.WATCHTOWER_API_ORIGIN || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [
    tsconfigPaths(),
    tailwindcss(),
    tanstackStart(),
    nitro({
      serverDir: "./server",
      devProxy: { "/api": { target: apiOrigin } },
    }),
    viteReact(),
  ],
  server: {
    host: "127.0.0.1",
    proxy: { "/api": { target: apiOrigin, changeOrigin: false } },
  },
});
