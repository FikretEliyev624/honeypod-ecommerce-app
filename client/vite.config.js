import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Read the API port from the project-root .env (client → ../.env)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const API_PORT = Number(process.env.API_PORT) || 3000;

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      // The dashboard only talks to the INTERNAL API, never to the honeypot.
      '/api': {
        target: `http://localhost:${API_PORT}`,
        changeOrigin: true,
      },
    },
  },
});
