import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// API portunu layihə kökündəki .env-dən oxuyuruq (client → ../.env)
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const API_PORT = Number(process.env.API_PORT) || 3000;

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      // Dashboard yalnız DAXİLİ API-yə müraciət edir, honeypot-a yox.
      '/api': {
        target: `http://localhost:${API_PORT}`,
        changeOrigin: true,
      },
    },
  },
});
