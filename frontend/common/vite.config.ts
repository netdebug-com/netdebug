// https://earthly.dev/blog/npm-workspaces-monorepo/
import { resolve } from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import dts from "vite-plugin-dts";
import tsConfigPaths from "vite-tsconfig-paths";
import * as packageJson from "./package.json";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export default defineConfig((_configEnv) => ({
  plugins: [react(), tsConfigPaths(), dts()],
  build: {
    lib: {
      entry: [resolve("src", "index.ts")],
      name: "common",
      fileName: "index",
    },
    rollupOptions: {
      external: [...Object.keys(packageJson.peerDependencies)],
    },
  },
}));
