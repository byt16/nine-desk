import type { ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Radar" },
  { to: "/cves", label: "CVEs" },
  { to: "/misconfigs", label: "Misconfigs" },
  { to: "/headers", label: "Headers" },
  { to: "/watch", label: "Watch" },
] as const;

function pathActive(pathname: string, to: string) {
  if (to === "/") return pathname === "/";
  return pathname === to || pathname.startsWith(`${to}/`);
}

export function Shell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <header className="sticky top-0 z-30 border-b border-border bg-bg/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-6xl flex-nowrap items-center gap-4 px-4 py-3 sm:px-6">
          <Link
            to="/"
            className="shrink-0 font-display text-xl italic leading-none tracking-tight text-fg"
          >
            NINE
          </Link>
          <p className="hidden font-mono text-xs uppercase tracking-[0.18em] text-muted sm:block">
            Floor 9.0
          </p>
          <nav
            aria-label="Primary"
            className="-mx-1 flex min-w-0 flex-1 flex-nowrap items-center gap-0.5 overflow-x-auto [scrollbar-width:none] sm:justify-end"
          >
            {NAV.map((item) => {
              const active = pathActive(pathname, item.to);
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={cn(
                    "inline-flex h-11 shrink-0 items-center rounded-md px-3 font-sans text-sm transition-colors duration-[var(--motion-quick)]",
                    active ? "text-fg" : "text-muted hover:text-fg",
                  )}
                  aria-current={active ? "page" : undefined}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>
      </header>
      <div className="mx-auto w-full max-w-6xl px-4 py-8 sm:px-6 sm:py-10">
        {children}
      </div>
      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-6 font-mono text-xs text-subtle sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <p>NINE — defensive intelligence. No scanners. No payloads.</p>
          <p>CVSS 9.0 and above. Server misconfiguration mapped to equivalent severity.</p>
        </div>
      </footer>
    </div>
  );
}
