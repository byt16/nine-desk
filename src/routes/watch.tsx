import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { CveRow, MisconfigRow } from "@/components/cve-row";
import { getCve, getMisconfig } from "@/lib/data";
import { useWatchlist } from "@/lib/watchlist";

export const Route = createFileRoute("/watch")({ component: WatchPage });

function WatchPage() {
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);
  const cveIds = useWatchlist((s) => s.cves);
  const slugs = useWatchlist((s) => s.misconfigs);

  const cves = ready
    ? cveIds.map(getCve).filter((c): c is NonNullable<typeof c> => Boolean(c))
    : [];
  const mis = ready
    ? slugs
        .map(getMisconfig)
        .filter((m): m is NonNullable<typeof m> => Boolean(m))
    : [];

  return (
    <main>
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-muted">
        This browser
      </p>
      <h1 className="mt-3 font-display text-4xl italic tracking-tight sm:text-5xl">
        Watch
      </h1>
      <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted">
        Bookmarks stay on this device. Nothing is uploaded.
      </p>

      {!ready ? (
        <p className="mt-10 text-sm text-muted">Loading watchlist.</p>
      ) : (
        <div className="mt-10 grid gap-12 lg:grid-cols-2">
          <section>
            <h2 className="font-display text-2xl italic tracking-tight">CVEs</h2>
            <div className="mt-4 flex flex-col gap-2">
              {cves.map((cve) => (
                <CveRow key={cve.id} cve={cve} />
              ))}
              {cves.length === 0 ? (
                <Empty to="/cves" label="Open the CVE catalog" />
              ) : null}
            </div>
          </section>
          <section>
            <h2 className="font-display text-2xl italic tracking-tight">
              Misconfigs
            </h2>
            <div className="mt-4 flex flex-col gap-2">
              {mis.map((m) => (
                <MisconfigRow
                  key={m.slug}
                  slug={m.slug}
                  title={m.title}
                  equivalent={m.equivalent}
                  owasp={m.owasp}
                />
              ))}
              {mis.length === 0 ? (
                <Empty to="/misconfigs" label="Open misconfigs" />
              ) : null}
            </div>
          </section>
        </div>
      )}
    </main>
  );
}

function Empty({ to, label }: { to: "/cves" | "/misconfigs"; label: string }) {
  return (
    <p className="rounded-xl px-4 py-8 text-sm text-muted shadow-[var(--shadow-border)]">
      Nothing watched.{" "}
      <Link to={to} className="text-fg underline-offset-4 hover:underline">
        {label}
      </Link>
    </p>
  );
}
