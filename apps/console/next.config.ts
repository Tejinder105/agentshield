import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The console is a thin client over `agentshield-console-api`; every
  // page here is a client component that talks to that API directly over
  // `fetch`/`EventSource`, so this app itself holds no server-side
  // secrets or database access of its own.
  reactStrictMode: true,
};

export default nextConfig;
