import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In production the static build talks to the API at the same-origin "/api"
// path, which nginx proxies to the backend. For local development (`npm run
// dev`) there is no nginx, so proxy "/api" to the backend dev server here.
// Override the target with VITE_DEV_API_TARGET if your backend runs elsewhere.
const API_TARGET = process.env.VITE_DEV_API_TARGET || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
