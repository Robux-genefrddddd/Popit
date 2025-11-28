import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import fs from "fs";
import { createServer } from "./server";

// Plugin pour écrire le fichier _redirects dans dist/spa après build
function netlifyRedirectsPlugin(): Plugin {
  return {
    name: "netlify-redirects",
    closeBundle() {
      const redirectsPath = path.join(process.cwd(), "dist/spa/_redirects");
      fs.mkdirSync(path.dirname(redirectsPath), { recursive: true });
      fs.writeFileSync(redirectsPath, "/* /index.html 200\n");
      console.log("✨ Netlify _redirects -> OK");
    },
  };
}

// Plugin Express en dev uniquement
function expressPlugin(): Plugin {
  return {
    name: "express-plugin",
    apply: "serve",
    configureServer(server) {
      const app = createServer();
      server.middlewares.use(app);
    },
  };
}

// Config Vite principale
export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
    fs: {
      allow: [".", "./client", "./shared"],
      deny: [".env", ".env.*", "*.{crt,pem}", "**/.git/**", "server/**"],
    },
  },
  build: {
    outDir: "dist/spa",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks: {
          firebase: ["firebase/app", "firebase/auth", "firebase/firestore"],
          react: ["react", "react-dom"],
        },
      },
    },
    chunkSizeWarningLimit: 1000,
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./client"),
      "@shared": path.resolve(__dirname, "./shared"),
    },
  },
  plugins: [
    react(),
    expressPlugin(), // Express en dev
    netlifyRedirectsPlugin(), // Ajout automatique du fichier _redirects
  ],
}));
