import { fileURLToPath } from "node:url";

// Static export: `NEXT_EXPORT=1 next build` writes a purely static directory to web/out, which can be dropped
// into an nginx web root as-is. Development (next dev) leaves the variable unset, keeping the /api proxy and hot reload.
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo: the whole site runs on mocks with no backend, so no /api proxy is needed.
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Keep a lockfile in a parent directory from affecting root inference and asset path generation.
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
  reactCompiler: true,
  // Allow dev resources (HMR) to be accessed from LAN IPs; add or remove entries as needed.
  // During dev, any IPv4 origin may access /_next/* and HMR (unaffected by changing LAN IPs).
  // Note: Next forbids a bare "*" for security, so segment wildcards are used; "*.*.*.*" matches any IPv4.
  allowedDevOrigins: ["*.*.*.*"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // Pure static export: no Node runtime; images are not optimized; every route produces <route>/index.html.
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : isMock
      ? {
          // Vercel mock demo: no backend, so no /api proxy is needed.
          images: { unoptimized: true },
        }
      : {
          // Development: proxy /api/* to the Go backend (default :8797, override with AUTOPENTEST_API).
          async rewrites() {
            const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8797";
            return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
          },
        }),
};

export default nextConfig;
