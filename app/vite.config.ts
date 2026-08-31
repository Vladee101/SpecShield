import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the frontend from a fixed port in dev and from bundled assets in
// release. `clearScreen: false` keeps Rust compiler output visible.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2022", sourcemap: false },
});
