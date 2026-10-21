"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/", label: "Dashboard" },
  { href: "/approvals", label: "Approvals" },
  { href: "/kill-switch", label: "Kill switch" },
];

export function Nav() {
  const pathname = usePathname();
  return (
    <nav className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-5xl items-center gap-6 px-4 py-3">
        <span className="text-sm font-semibold tracking-tight text-slate-900">
          Agent Shield Console
        </span>
        <div className="flex gap-4">
          {LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={
                "text-sm font-medium " +
                (pathname === link.href
                  ? "text-slate-900"
                  : "text-slate-500 hover:text-slate-700")
              }
            >
              {link.label}
            </Link>
          ))}
        </div>
      </div>
    </nav>
  );
}
