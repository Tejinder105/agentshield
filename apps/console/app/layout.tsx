import type { Metadata } from "next";

import { Nav } from "@/components/Nav";
import { Providers } from "@/components/Providers";

import "./globals.css";

export const metadata: Metadata = {
  title: "Agent Shield Console",
  description:
    "The Agent Shield control plane: policy editor, live approval queue, audit explorer, and the emergency kill switch.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <Nav />
          <main className="mx-auto max-w-5xl px-4 py-8">{children}</main>
        </Providers>
      </body>
    </html>
  );
}
